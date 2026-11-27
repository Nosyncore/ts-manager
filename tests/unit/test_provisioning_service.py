"""Serviço de provisionamento: ordem, conferência, falhas, ``recover`` e segurança do estado.

O provisionador é o ``LocalProvisioner`` real (estado em ``tmp_path``) atrás de um wrapper
que injeta falhas, adultera inspeções e registra o estado do dispositivo no banco no
momento de cada chamada; o repositório é o real, sobre SQLite.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest

from tests.unit.identity_fakes import audit_events, fake_key, seed_user
from tsm_common import protocol as P
from tsm_common.sshkeys import parse_public_key
from tsm_manager.identity import accounts
from tsm_manager.identity.base import Actor, IdentityError
from tsm_manager.layout import ProjectLayout
from tsm_manager.provisioning.provisioner import LocalProvisioner, ProvisionError
from tsm_manager.provisioning.service import OpResult, ProvisioningService

OPERATOR = Actor.operator()
ADMIN = Actor("adm", "dev-adm")


class Flaky:
    """``LocalProvisioner`` com falhas injetadas e registro de (verbo, conta, estado)."""

    def __init__(self, inner: LocalProvisioner, ctx) -> None:
        self.inner = inner
        self.ctx = ctx
        self.calls: list[tuple[str, str, str | None]] = []
        self.fail: dict[str, list[ProvisionError]] = {}
        self.tamper = None

    def _status(self, account: str) -> str | None:
        with self.ctx.repo.read() as tx:
            device = next((d for d in tx.list_devices() if d.ssh_account == account), None)
        return device.status if device else None

    def _do(self, verb: str, account: str, *args):
        self.calls.append((verb, account, self._status(account)))
        queue = self.fail.get(verb)
        if queue:
            raise queue.pop(0)
        return getattr(self.inner, verb)(account, *args)

    def failing(self, verb: str, times: int = 1, kind: str = "system") -> Flaky:
        self.fail[verb] = [ProvisionError(kind, f"{verb} quebrou") for _ in range(times)]
        return self

    def create_device(self, account, project, key):
        return self._do("create_device", account, project, key)

    def disable_device(self, account):
        return self._do("disable_device", account)

    def enable_device(self, account, key):
        return self._do("enable_device", account, key)

    def delete_device(self, account, project):
        return self._do("delete_device", account, project)

    def inspect_device(self, account, project):
        result = self._do("inspect_device", account, project)
        return self.tamper(result) if self.tamper else result

    def verbs(self) -> list[str]:
        return [c[0] for c in self.calls]


@pytest.fixture
def prov(ctx, tmp_path) -> Flaky:
    ProjectLayout(tmp_path, "demo").workspaces.mkdir(parents=True)
    return Flaky(LocalProvisioner(tmp_path), ctx)


@pytest.fixture
def svc(ctx, prov) -> ProvisioningService:
    return ProvisioningService(ctx, prov)


def device(ctx, did):
    with ctx.repo.read() as tx:
        return tx.get_device(did)


def ops(ctx, did):
    with ctx.repo.read() as tx:
        return [(o.action, o.status) for o in tx.ops_for_device(did)]


def pending(ctx, uid="dev1", key=80) -> tuple[str, str]:
    """Solicitação ``pending`` de ``uid`` (admin semeado); devolve (device_id, fingerprint)."""
    if not _has_user(ctx, "adm"):
        seed_user(ctx, "adm", role="admin", key=1000)
    did = str(uuid.UUID(int=key << 96))
    seed_user(ctx, uid, did=did, key=key, device_status="pending")
    return did, parse_public_key(fake_key(key)).fingerprint


def _has_user(ctx, uid) -> bool:
    with ctx.repo.read() as tx:
        return tx.get_user(uid) is not None


def approved(svc, ctx, uid="dev1", key=80) -> tuple[str, str]:
    did, fp = pending(ctx, uid, key)
    svc.approve(ADMIN, did, fp)
    svc.provisioner.calls.clear()
    return did, device(ctx, did).ssh_account


def state(prov: Flaky, account: str):
    return prov.inner.inspect_device(account, "demo")


# ------------------------------------------------------------------ aprovação


def test_approve_provisions_then_checks_then_activates(svc, ctx, prov, database):
    did, fp = pending(ctx)
    binding = svc.approve(ADMIN, did, fp)
    account = device(ctx, did).ssh_account
    assert prov.calls == [("create_device", account, "provisioning"),
                          ("inspect_device", account, "provisioning")]
    assert device(ctx, did).status == "active"
    assert (binding.project_id, binding.workspace) == ("demo", account)
    assert ops(ctx, did) == [("create", "done")]
    assert state(prov, account).key_fingerprint == fp
    assert [e["event"] for e in audit_events(database)][-2:] == ["approval_started",
                                                                  "device_approved"]


def test_create_failure_returns_to_pending_and_disables(svc, ctx, prov):
    did, fp = pending(ctx)
    prov.failing("create_device")
    with pytest.raises(IdentityError) as info:
        svc.approve(ADMIN, did, fp)
    assert info.value.code == P.PROVISIONING_FAILED
    assert "create_device quebrou" in info.value.message
    current = device(ctx, did)
    assert (current.status, "create_device quebrou" in current.last_error) == ("pending", True)
    assert ops(ctx, did) == [("create", "failed")]
    assert prov.verbs() == ["create_device", "disable_device"]


@pytest.mark.parametrize(("tamper", "problem"), [
    (lambda i: dataclasses.replace(i, exists=False), "conta não existe"),
    (lambda i: dataclasses.replace(i, expired=True), "conta expirada"),
    (lambda i: dataclasses.replace(i, groups=i.groups - {"tsm-ws"}), "grupos ausentes: tsm-ws"),
    (lambda i: dataclasses.replace(i, key_fingerprint="SHA256:" + "A" * 43),
     "chave instalada difere"),
    (lambda i: dataclasses.replace(i, home=dataclasses.replace(i.home, mode=0o755)),
     "home fora do esperado"),
    (lambda i: dataclasses.replace(i, home=None), "home fora do esperado"),
    (lambda i: dataclasses.replace(i, gate=dataclasses.replace(i.gate, group="tsm-ws")),
     "portão do workspace fora do esperado"),
    (lambda i: dataclasses.replace(i, tree=None), "tree do workspace fora do esperado"),
])
def test_failed_check_returns_to_pending_and_disables(svc, ctx, prov, tamper, problem):
    did, fp = pending(ctx)
    prov.tamper = tamper
    with pytest.raises(IdentityError) as info:
        svc.approve(ADMIN, did, fp)
    assert problem in info.value.message
    assert device(ctx, did).status == "pending"
    account = device(ctx, did).ssh_account
    prov.tamper = None
    assert (state(prov, account).key_fingerprint, state(prov, account).expired) == (None, True)


def test_failed_disable_after_failed_approval_is_scheduled(svc, ctx, prov):
    did, fp = pending(ctx)
    prov.failing("create_device").failing("disable_device")
    with pytest.raises(IdentityError):
        svc.approve(ADMIN, did, fp)
    assert ops(ctx, did) == [("create", "failed"), ("disable", "pending")]
    with pytest.raises(IdentityError) as info:
        svc.approve(ADMIN, did, fp)
    assert info.value.code == P.INVALID_STATE
    assert [r.status for r in svc.recover()] == ["done"]
    svc.approve(ADMIN, did, fp)
    assert device(ctx, did).status == "active"
    account = device(ctx, did).ssh_account
    assert (state(prov, account).expired, state(prov, account).key_fingerprint) == (False, fp)


def test_wrong_fingerprint_never_calls_the_helper(svc, ctx, prov):
    did, _ = pending(ctx)
    with pytest.raises(IdentityError) as info:
        svc.approve(ADMIN, did, "SHA256:" + "B" * 43)
    assert info.value.code == P.FINGERPRINT_MISMATCH
    assert prov.calls == []


def test_user_blocked_during_provisioning_is_not_activated(svc, ctx, prov):
    did, fp = pending(ctx)
    ticket = accounts.begin_approval(ctx, ADMIN, did, fingerprint=fp)
    accounts.block_user(ctx, ADMIN, "dev1")
    result = svc.run_op(ticket.op_id)
    assert (result.status, result.error) == ("failed", "usuário bloqueado")
    assert device(ctx, did).status == "pending"
    assert state(prov, ticket.ssh_account).key_fingerprint is None


# ------------------------------------------------------------------ recover


def test_recover_after_crash_before_the_helper(svc, ctx, prov):
    did, fp = pending(ctx)
    accounts.begin_approval(ctx, ADMIN, did, fingerprint=fp)
    [result] = svc.recover()
    assert (result.action, result.status, result.device_id) == ("create", "done", did)
    assert device(ctx, did).status == "active"
    assert svc.recover() == []


def test_recover_after_crash_between_helper_and_final_transaction(svc, ctx, prov):
    did, fp = pending(ctx)
    ticket = accounts.begin_approval(ctx, ADMIN, did, fingerprint=fp)
    prov.inner.create_device(ticket.ssh_account, "demo", ticket.public_key)
    [result] = svc.recover()
    assert result.status == "done"
    assert device(ctx, did).status == "active"
    assert ops(ctx, did) == [("create", "done")]


def test_create_abandoned_when_device_left_provisioning(svc, ctx, database):
    did, fp = pending(ctx)
    ticket = accounts.begin_approval(ctx, ADMIN, did, fingerprint=fp)
    with ctx.repo.write() as tx:
        tx.update_device(did, status="pending")
    result = svc.run_op(ticket.op_id)
    assert (result.status, result.error) == ("failed", "estado mudou")
    assert audit_events(database)[-1]["event"] == "provisioning_abandoned"


def test_run_op_on_finished_or_unknown_operation(svc, ctx, prov):
    did, _account = approved(svc, ctx)
    [op_id] = [o.id for o in _ops(ctx, did)]
    assert svc.run_op(op_id) == OpResult(op_id, "create", did, "done", None)
    assert prov.calls == []
    with pytest.raises(IdentityError) as info:
        svc.run_op(999)
    assert info.value.code == P.NOT_FOUND


def _ops(ctx, did):
    with ctx.repo.read() as tx:
        return tx.ops_for_device(did)


# ------------------------------------------------------------------ revogação, bloqueio


def test_revoke_changes_the_database_before_the_helper(svc, ctx, prov):
    did, account = approved(svc, ctx)
    result = svc.revoke(ADMIN, did)
    assert (result.action, result.status) == ("disable", "done")
    assert prov.calls == [("disable_device", account, "revoked"),
                          ("inspect_device", account, "revoked")]
    got = state(prov, account)
    assert (got.key_fingerprint, got.expired) == (None, True)


def test_failed_revocation_stays_pending_until_recover(svc, ctx, prov, database):
    did, _account = approved(svc, ctx)
    prov.failing("disable_device", times=2)
    result = svc.revoke(ADMIN, did)
    assert (result.status, result.error) == ("pending", "system: disable_device quebrou")
    assert device(ctx, did).status == "revoked"
    assert svc.recover()[0].status == "pending"
    assert [r.status for r in svc.recover()] == ["done"]
    assert ops(ctx, did) == [("create", "done"), ("disable", "done")]
    events = [e["event"] for e in audit_events(database)]
    assert events.count("provisioning_retry") == 2


def test_revocation_with_surviving_processes_is_retried(svc, ctx, prov):
    did, _account = approved(svc, ctx)
    prov.tamper = lambda i: dataclasses.replace(i, processes=2)
    result = svc.revoke(ADMIN, did)
    assert (result.status, result.error) == ("pending", "processos ativos: 2")
    prov.tamper = lambda i: dataclasses.replace(i, expired=False)
    assert svc.recover()[0].error == "conta não expirada"
    prov.tamper = lambda i: dataclasses.replace(i, key_fingerprint="SHA256:x")
    assert svc.recover()[0].error == "chave ainda instalada"
    prov.tamper = None
    assert svc.recover()[0].status == "done"


def test_block_and_unblock(svc, ctx, prov):
    did, account = approved(svc, ctx)
    [blocked] = svc.block(ADMIN, "dev1")
    assert (blocked.action, blocked.status) == ("disable", "done")
    assert state(prov, account).expired is True
    [unblocked] = svc.unblock(ADMIN, "dev1")
    assert (unblocked.action, unblocked.status) == ("enable", "done")
    got = state(prov, account)
    assert (got.expired, got.key_fingerprint) == (False, device(ctx, did).fingerprint)


def test_enable_failure_and_check_are_retried(svc, ctx, prov):
    _did, _account = approved(svc, ctx)
    svc.block(ADMIN, "dev1")
    prov.failing("enable_device")
    [result] = svc.unblock(ADMIN, "dev1")
    assert result.status == "pending"
    prov.tamper = lambda i: dataclasses.replace(i, expired=True)
    assert svc.recover()[0].error == "conta expirada"
    prov.tamper = None
    assert svc.recover()[0].status == "done"


def test_late_enable_never_reopens_a_revoked_device(svc, ctx, prov):
    did, account = approved(svc, ctx)
    svc.block(ADMIN, "dev1")
    prov.failing("enable_device")
    svc.unblock(ADMIN, "dev1")
    svc.revoke(ADMIN, did)
    results = svc.recover()
    assert [(r.action, r.status, r.error) for r in results] == [
        ("enable", "failed", "estado mudou")]
    got = state(prov, account)
    assert (got.expired, got.key_fingerprint) == (True, None)
    assert prov.verbs().count("enable_device") == 1


def test_late_enable_never_reopens_a_user_blocked_again(svc, ctx, prov):
    _did, account = approved(svc, ctx)
    svc.block(ADMIN, "dev1")
    prov.failing("enable_device")
    svc.unblock(ADMIN, "dev1")
    prov.failing("disable_device")
    svc.block(ADMIN, "dev1")
    results = svc.recover()
    assert [(r.action, r.status) for r in results] == [("enable", "failed"),
                                                       ("disable", "done")]
    assert state(prov, account).expired is True


# ------------------------------------------------------------------ expurgo


def test_purge_removes_account_and_workspace(svc, ctx, prov, tmp_path):
    did, account = approved(svc, ctx)
    svc.revoke(ADMIN, did)
    (ProjectLayout(tmp_path, "demo").sync_root(account) / "a.txt").write_text("x")
    result = svc.purge(OPERATOR, did)
    assert (result.action, result.status) == ("delete", "done")
    got = state(prov, account)
    assert (got.exists, got.gate) == (False, None)
    assert not ProjectLayout(tmp_path, "demo").account_gate(account).exists()


def test_purge_check_failure_is_retried(svc, ctx, prov):
    did, _account = approved(svc, ctx)
    svc.revoke(ADMIN, did)
    prov.tamper = lambda i: dataclasses.replace(i, exists=True)
    assert svc.purge(OPERATOR, did).error == "conta ainda existe"
    prov.tamper = lambda i: dataclasses.replace(i, gate=_gate())
    assert svc.recover()[0].error == "workspace ainda existe"
    prov.tamper = None
    assert svc.recover()[0].status == "done"


def _gate():
    from tsm_manager.provisioning.provisioner import DirInfo
    return DirInfo("x", "tsm-manager", 0o750)


def test_purge_only_by_the_operator(svc, ctx, prov):
    did, _ = approved(svc, ctx)
    svc.revoke(ADMIN, did)
    with pytest.raises(IdentityError) as info:
        svc.purge(ADMIN, did)
    assert info.value.code == P.FORBIDDEN
    assert prov.verbs() == ["disable_device", "inspect_device"]


def test_operation_of_a_device_without_account_is_abandoned(svc, ctx):
    _, did = seed_user(ctx, "dev9", key=99)
    with ctx.repo.write() as tx:
        tx.update_device(did, ssh_account=None)
    op_id = accounts.revoke(ctx, OPERATOR, did)
    result = svc.run_op(op_id)
    assert (result.status, result.error) == ("failed", "dispositivo sem conta")
