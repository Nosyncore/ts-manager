"""Operações de provisionamento no domínio: conclusão, nova tentativa, abandono e expurgo."""

from __future__ import annotations

import pytest

from tests.unit.identity_fakes import audit_events, seed_user
from tsm_common import protocol as P
from tsm_manager.identity import accounts
from tsm_manager.identity.base import Actor, IdentityError

OPERATOR = Actor.operator()
ADMIN = Actor("adm", "dev-adm")


def op(ctx, op_id):
    with ctx.repo.read() as tx:
        return tx.get_op(op_id)


def revoked(ctx, uid="dev1") -> tuple[str, int]:
    """Dispositivo revogado pelo operador, com a operação ``disable`` pendente."""
    _, did = seed_user(ctx, uid, key=70)
    return did, accounts.revoke(ctx, OPERATOR, did)


def test_finish_operation_marks_done_and_audits(ctx, database):
    did, op_id = revoked(ctx)
    accounts.finish_operation(ctx, op_id)
    done = op(ctx, op_id)
    assert (done.status, done.error, done.finished_at is not None) == ("done", None, True)
    assert audit_events(database)[-1] | {} == {
        "event": "provisioning_done", "project": None, "user": None, "device": did,
        "op": op_id, "action": "disable"}


def test_failed_attempt_keeps_the_operation_pending(ctx, database):
    _did, op_id = revoked(ctx)
    accounts.finish_operation(ctx, op_id, error="pkill: processos restantes")
    pending = op(ctx, op_id)
    assert (pending.status, pending.error) == ("pending", "pkill: processos restantes")
    assert audit_events(database)[-1]["event"] == "provisioning_retry"
    accounts.finish_operation(ctx, op_id)
    assert (op(ctx, op_id).status, op(ctx, op_id).error) == ("done", None)


def test_abandoned_operation_is_failed(ctx, database):
    _, op_id = revoked(ctx)
    accounts.finish_operation(ctx, op_id, error="estado mudou", abandon=True)
    assert (op(ctx, op_id).status, op(ctx, op_id).error) == ("failed", "estado mudou")
    assert audit_events(database)[-1]["event"] == "provisioning_abandoned"


def test_long_errors_are_truncated(ctx):
    _, op_id = revoked(ctx)
    accounts.finish_operation(ctx, op_id, error="x" * 5000)
    assert len(op(ctx, op_id).error) == 1000


def test_finished_operation_cannot_be_finished_again(ctx):
    _, op_id = revoked(ctx)
    accounts.finish_operation(ctx, op_id)
    for kw in ({}, {"error": "e"}, {"error": "e", "abandon": True}):
        with pytest.raises(IdentityError) as info:
            accounts.finish_operation(ctx, op_id, **kw)
        assert info.value.code == P.INVALID_STATE


def test_unknown_operation(ctx):
    with pytest.raises(IdentityError) as info:
        accounts.finish_operation(ctx, 999)
    assert info.value.code == P.NOT_FOUND


def test_create_is_concluded_only_by_the_approval(ctx):
    seed_user(ctx, "adm", role="admin", key=1000)
    _, did = seed_user(ctx, "dev1", key=71, device_status="pending")
    fp = accounts.list_requests(ctx, ADMIN)[0].device.fingerprint
    ticket = accounts.begin_approval(ctx, ADMIN, did, fingerprint=fp)
    with pytest.raises(IdentityError) as info:
        accounts.finish_operation(ctx, ticket.op_id)
    assert info.value.code == P.INVALID_STATE
    accounts.finish_operation(ctx, ticket.op_id, error="estado mudou", abandon=True)
    assert op(ctx, ticket.op_id).status == "failed"


def test_abandon_requires_an_error(ctx):
    _, op_id = revoked(ctx)
    with pytest.raises(ValueError):
        accounts.finish_operation(ctx, op_id, abandon=True)


# ------------------------------------------------------------------ expurgo


def test_purge_registers_delete_for_revoked_device(ctx, database):
    did, disable = revoked(ctx)
    accounts.finish_operation(ctx, disable)
    op_id = accounts.purge(ctx, OPERATOR, did)
    assert (op(ctx, op_id).action, op(ctx, op_id).status) == ("delete", "pending")
    event = audit_events(database)[-1]
    assert (event["event"], event["device"], event["op"], event["operator"]) == (
        "device_purge_requested", did, op_id, True)


def test_purge_only_by_the_operator(ctx, database):
    seed_user(ctx, "adm", role="admin", key=1000)
    did, disable = revoked(ctx)
    accounts.finish_operation(ctx, disable)
    with pytest.raises(IdentityError) as info:
        accounts.purge(ctx, ADMIN, did)
    assert info.value.code == P.FORBIDDEN
    assert audit_events(database)[-1]["event"] == "purge_refused"


def test_purge_requires_a_revoked_device_without_pending_operations(ctx):
    _, active = seed_user(ctx, "dev2", key=72)
    with pytest.raises(IdentityError) as info:
        accounts.purge(ctx, OPERATOR, active)
    assert info.value.code == P.INVALID_STATE
    did, disable = revoked(ctx)
    with pytest.raises(IdentityError) as info:
        accounts.purge(ctx, OPERATOR, did)
    assert (info.value.code, info.value.message) == (P.INVALID_STATE,
                                                     "revogação SSH pendente")
    accounts.finish_operation(ctx, disable)
    accounts.purge(ctx, OPERATOR, did)
    with pytest.raises(IdentityError) as info:
        accounts.purge(ctx, OPERATOR, did)
    assert info.value.message == "expurgo já pendente"
    with pytest.raises(IdentityError) as info:
        accounts.purge(ctx, OPERATOR, "nao-existe")
    assert info.value.code == P.NOT_FOUND


def test_note_op_error_only_touches_pending_operations(ctx):
    _, op_id = revoked(ctx)
    with ctx.repo.write() as tx:
        assert tx.note_op_error(op_id, "primeira") is True
    accounts.finish_operation(ctx, op_id)
    with ctx.repo.write() as tx:
        assert tx.note_op_error(op_id, "depois") is False
    assert op(ctx, op_id).error is None


# ------------------------------------------------------------------ desativação agendada


def pending_request(ctx, uid="dev3", key=73) -> tuple[str, str]:
    seed_user(ctx, "adm", role="admin", key=1000)
    _, did = seed_user(ctx, uid, key=key, device_status="pending")
    fp = next(r.device.fingerprint for r in accounts.list_requests(ctx, ADMIN)
              if r.device.id == did)
    return did, fp


def test_schedule_disable_registers_one_pending_disable(ctx, database):
    did, _ = pending_request(ctx)
    op_id = accounts.schedule_disable(ctx, did, "conferência falhou")
    assert (op(ctx, op_id).action, op(ctx, op_id).status) == ("disable", "pending")
    assert accounts.schedule_disable(ctx, did, "de novo") == op_id
    event = audit_events(database)[-1]
    assert (event["event"], event["device"], event["reason"]) == (
        "provisioning_disable_scheduled", did, "conferência falhou")


def test_approval_waits_for_pending_operations(ctx, database):
    did, fp = pending_request(ctx)
    op_id = accounts.schedule_disable(ctx, did, "conferência falhou")
    with pytest.raises(IdentityError) as info:
        accounts.begin_approval(ctx, ADMIN, did, fingerprint=fp)
    assert (info.value.code, info.value.message) == (
        P.INVALID_STATE, "operação de provisionamento pendente; rode o recover")
    accounts.finish_operation(ctx, op_id)
    assert accounts.begin_approval(ctx, ADMIN, did, fingerprint=fp).device_id == did


def test_schedule_disable_of_unknown_device(ctx):
    with pytest.raises(IdentityError) as info:
        accounts.schedule_disable(ctx, "nao-existe", "x")
    assert info.value.code == P.NOT_FOUND
