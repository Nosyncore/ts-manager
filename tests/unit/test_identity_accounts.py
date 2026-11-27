"""Contas: cadastro com convite, máquina de estados de dispositivos e usuários, último admin."""

from __future__ import annotations

import re

import pytest

from tests.unit.identity_fakes import (
    FakeVerifier,
    audit_events,
    fake_key,
    seed_user,
)
from tsm_common import protocol as P
from tsm_common.sshkeys import parse_public_key
from tsm_manager.identity import accounts, challenges, invites, sessions
from tsm_manager.identity.base import Actor, IdentityError

OPERATOR = Actor.operator()
ADMIN = Actor("adm", "dev-adm")


def with_admin(ctx) -> Actor:
    seed_user(ctx, "adm", role="admin", key=1000)
    return ADMIN


def enroll(ctx, code: str, key: int, *, name: str | None = "Fulano", device: str = "pc",
           signer: int | None = None):
    issued = challenges.issue_register(ctx, fake_key(key))
    signature = FakeVerifier.sign(parse_public_key(fake_key(signer or key)).openssh,
                                  issued.message())
    return accounts.register(ctx, invite_code=code, display_name=name, device_name=device,
                             challenge_id=issued.challenge_id, signature=signature)


def code_for(ctx, actor=ADMIN, **kw) -> str:
    return invites.create(ctx, actor, project_id=kw.pop("project_id", "demo"), **kw).code


def refused(fn, *args, **kw) -> str:
    with pytest.raises(IdentityError) as err:
        fn(*args, **kw)
    return err.value.code


def device(ctx, did):
    with ctx.repo.read() as tx:
        return tx.get_device(did)


def user(ctx, uid):
    with ctx.repo.read() as tx:
        return tx.get_user(uid)


def approve(ctx, actor, did):
    ticket = accounts.begin_approval(ctx, actor, did, fingerprint=device(ctx, did).fingerprint)
    return accounts.complete_approval(ctx, did, ticket.op_id)


def login_token(ctx, key: int) -> str:
    issued = challenges.issue_login(ctx, parse_public_key(fake_key(key)).fingerprint)
    signature = FakeVerifier.sign(parse_public_key(fake_key(key)).openssh, issued.message())
    return sessions.login(ctx, issued.challenge_id, signature).token


# ---------------------------------------------------------------- nomes


def test_names_normalized_and_validated():
    assert accounts.validate_name("  José ") == "José"
    assert accounts.validate_name("x" * 64) == "x" * 64
    for bad in ["", "   ", "x" * 65, "a\nb", "a\x00b", "a​b", None, 3]:
        with pytest.raises(IdentityError) as err:
            accounts.validate_name(bad)
        assert err.value.code == P.INVALID_REQUEST


def test_ssh_account_from_device_id():
    assert accounts.ssh_account_for("0123abcd-ef01-4abc-8def-0123456789ab") == \
        "tsm-d-0123abcdef01"


# ---------------------------------------------------------------- cadastro


def test_register_new_user(ctx, database):
    with_admin(ctx)
    created = invites.create(ctx, ADMIN, project_id="demo")
    reg = enroll(ctx, created.code, 1, name="José", device="notebook")
    d, u = device(ctx, reg.device_id), user(ctx, reg.user_id)
    assert (reg.status, reg.project_id, reg.fingerprint) == (
        "pending", "demo", parse_public_key(fake_key(1)).fingerprint)
    assert (u.display_name, u.role, u.status) == ("José", "developer", "active")
    assert (d.name, d.status, d.ssh_account, d.invite_id, d.public_key) == (
        "notebook", "pending", None, created.invite.id, parse_public_key(fake_key(1)).openssh)
    event = audit_events(database)[-1]
    assert (event["event"], event["project"], event["user"], event["device"]) == (
        "device_registered", "demo", reg.user_id, reg.device_id)
    with ctx.repo.read() as tx:
        assert tx.get_invite(created.invite.id).used_at is not None


def test_register_with_admin_invite_creates_admin_user(ctx):
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx, role="admin"), 1)
    assert user(ctx, reg.user_id).role == "admin"


def test_register_new_device_for_existing_user(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    reg = enroll(ctx, code_for(ctx, kind="new_device", for_user="dev1"), 2, name=None,
                 device="desktop")
    assert reg.user_id == "dev1" and device(ctx, reg.device_id).status == "pending"
    assert device(ctx, "dev-dev1").status == "active"  # o primeiro continua ativo
    assert user(ctx, "dev1").display_name == "Nome dev1"


def test_new_device_invite_of_user_blocked_later_is_invalid(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    code = code_for(ctx, kind="new_device", for_user="dev1")
    accounts.block_user(ctx, ADMIN, "dev1")
    assert refused(enroll, ctx, code, 2) == P.INVALID_INVITE


def test_new_user_needs_a_display_name(ctx):
    with_admin(ctx)
    code = code_for(ctx)
    assert refused(enroll, ctx, code, 1, name=None) == P.INVALID_REQUEST
    assert enroll(ctx, code, 1).status == "pending"  # convite não foi consumido


def test_bootstrap_registration(ctx):
    code = invites.create_bootstrap(ctx, OPERATOR, project_id="demo").code
    reg = enroll(ctx, code, 1)
    assert user(ctx, reg.user_id).role == "admin"


def test_bootstrap_invite_useless_once_an_admin_is_active(ctx):
    code = invites.create_bootstrap(ctx, OPERATOR, project_id="demo").code
    seed_user(ctx, "adm", role="admin", key=1000)
    assert refused(enroll, ctx, code, 1) == P.INVALID_INVITE


def test_key_already_registered_in_any_state(ctx, database):
    with_admin(ctx)
    for status, key in [("active", 60), ("revoked", 61), ("rejected", 62), ("pending", 63)]:
        seed_user(ctx, f"u{key}", key=key, device_status=status)
        code = code_for(ctx)
        assert refused(enroll, ctx, code, key) == P.KEY_IN_USE
        assert enroll(ctx, code, key + 100).status == "pending"  # convite intacto
    assert any(e["event"] == "register_refused" and e["reason"] == P.KEY_IN_USE
               for e in audit_events(database))


def test_bad_signature_keeps_the_invite(ctx):
    with_admin(ctx)
    code = code_for(ctx)
    assert refused(enroll, ctx, code, 1, signer=2) == P.UNAUTHORIZED
    assert enroll(ctx, code, 1).status == "pending"


def test_login_challenge_cannot_register(ctx):
    with_admin(ctx)
    issued = challenges.issue_login(ctx, parse_public_key(fake_key(1)).fingerprint)
    signature = FakeVerifier.sign(parse_public_key(fake_key(1)).openssh, issued.message())
    assert refused(accounts.register, ctx, invite_code=code_for(ctx), display_name="A",
                   device_name="pc", challenge_id=issued.challenge_id,
                   signature=signature) == P.UNAUTHORIZED


def test_invalid_invite_is_audited(ctx, database):
    with_admin(ctx)
    assert refused(enroll, ctx, "tsm-inv-" + "a" * 26, 1) == P.INVALID_INVITE
    event = audit_events(database)[-1]
    assert (event["event"], event["reason"]) == ("register_refused", P.INVALID_INVITE)


def test_invalid_device_name_refused_before_spending_anything(ctx):
    with_admin(ctx)
    code = code_for(ctx)
    assert refused(enroll, ctx, code, 1, device="") == P.INVALID_REQUEST
    assert enroll(ctx, code, 1).status == "pending"


# ---------------------------------------------------------------- aprovação


def test_approval_provisions_then_activates(ctx, database, rng):
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx), 1)
    ticket = accounts.begin_approval(ctx, ADMIN, reg.device_id, fingerprint=reg.fingerprint)
    d = device(ctx, reg.device_id)
    assert d.status == "provisioning"
    assert ticket.ssh_account == d.ssh_account == accounts.ssh_account_for(reg.device_id)
    assert re.fullmatch(r"tsm-d-[0-9a-f]{12}", ticket.ssh_account)
    assert (ticket.project_id, ticket.public_key) == ("demo", d.public_key)
    with ctx.repo.read() as tx:
        assert [(o.action, o.status) for o in tx.ops_for_device(reg.device_id)] == [
            ("create", "pending")]
    binding = accounts.complete_approval(ctx, reg.device_id, ticket.op_id)
    d = device(ctx, reg.device_id)
    assert (d.status, d.decided_by) == ("active", "adm") and d.decided_at is not None
    assert re.fullmatch(r"b-[0-9a-f]{20}", binding.id)
    assert (binding.project_id, binding.device_id, binding.workspace) == (
        "demo", reg.device_id, ticket.ssh_account)
    with ctx.repo.read() as tx:
        assert tx.get_op(ticket.op_id).status == "done"
    assert [e["event"] for e in audit_events(database)][-2:] == [
        "approval_started", "device_approved"]


def test_approval_requires_the_matching_fingerprint(ctx, database):
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx), 1)
    other = parse_public_key(fake_key(2)).fingerprint
    assert refused(accounts.begin_approval, ctx, ADMIN, reg.device_id,
                   fingerprint=other) == P.FINGERPRINT_MISMATCH
    assert device(ctx, reg.device_id).status == "pending"
    event = audit_events(database)[-1]
    assert (event["event"], event["reason"]) == ("approval_refused", P.FINGERPRINT_MISMATCH)


def test_approval_requires_admin(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    reg = enroll(ctx, code_for(ctx), 1)
    assert refused(accounts.begin_approval, ctx, Actor("dev1", "dev-dev1"), reg.device_id,
                   fingerprint=reg.fingerprint) == P.FORBIDDEN
    assert refused(accounts.begin_approval, ctx, Actor("dev1", "dev-dev1"), "nada",
                   fingerprint=reg.fingerprint) == P.FORBIDDEN  # não revela existência
    assert refused(accounts.begin_approval, ctx, ADMIN, "nada",
                   fingerprint=reg.fingerprint) == P.NOT_FOUND


def test_only_pending_devices_are_approved(ctx):
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx), 1)
    approve(ctx, ADMIN, reg.device_id)
    assert refused(accounts.begin_approval, ctx, ADMIN, reg.device_id,
                   fingerprint=reg.fingerprint) == P.INVALID_STATE


def test_approval_of_blocked_user_refused(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    reg = enroll(ctx, code_for(ctx, kind="new_device", for_user="dev1"), 2, name=None)
    accounts.block_user(ctx, ADMIN, "dev1")
    assert refused(accounts.begin_approval, ctx, ADMIN, reg.device_id,
                   fingerprint=reg.fingerprint) == P.INVALID_STATE


def test_bootstrap_request_approved_only_by_operator(ctx):
    reg = enroll(ctx, invites.create_bootstrap(ctx, OPERATOR, project_id="demo").code, 1)
    other_admin = with_admin(ctx)
    assert refused(accounts.begin_approval, ctx, other_admin, reg.device_id,
                   fingerprint=reg.fingerprint) == P.FORBIDDEN
    # com admin ativo, nem o operador aprova o bootstrap
    assert refused(accounts.begin_approval, ctx, OPERATOR, reg.device_id,
                   fingerprint=reg.fingerprint) == P.INVALID_STATE


def test_bootstrap_flow_by_operator(ctx):
    reg = enroll(ctx, invites.create_bootstrap(ctx, OPERATOR, project_id="demo").code, 1)
    approve(ctx, OPERATOR, reg.device_id)
    assert device(ctx, reg.device_id).decided_by is None
    assert user(ctx, reg.user_id).role == "admin"
    assert refused(invites.create_bootstrap, ctx, OPERATOR,
                   project_id="demo") == P.INVALID_STATE


def test_failed_provisioning_returns_to_pending_and_can_be_retried(ctx):
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx), 1)
    ticket = accounts.begin_approval(ctx, ADMIN, reg.device_id, fingerprint=reg.fingerprint)
    accounts.fail_approval(ctx, reg.device_id, ticket.op_id, "useradd falhou")
    d = device(ctx, reg.device_id)
    assert (d.status, d.last_error, d.decided_by) == ("pending", "useradd falhou", None)
    with ctx.repo.read() as tx:
        assert (tx.get_op(ticket.op_id).status, tx.get_op(ticket.op_id).error) == (
            "failed", "useradd falhou")
    binding = approve(ctx, ADMIN, reg.device_id)
    assert device(ctx, reg.device_id).last_error is None
    assert binding.workspace == ticket.ssh_account


def test_completion_reuses_an_existing_binding(ctx):
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx), 1)
    ticket = accounts.begin_approval(ctx, ADMIN, reg.device_id, fingerprint=reg.fingerprint)
    first = accounts.complete_approval(ctx, reg.device_id, ticket.op_id)
    with ctx.repo.write() as tx:  # simula repetição após queda: volta a provisioning
        tx.update_device(reg.device_id, status="provisioning")
        op = tx.insert_op(reg.device_id, "create", now=ctx.now_ts())
    assert accounts.complete_approval(ctx, reg.device_id, op).id == first.id


def test_completion_and_failure_need_the_right_operation(ctx):
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx), 1)
    assert refused(accounts.complete_approval, ctx, reg.device_id, 1) == P.INVALID_STATE
    ticket = accounts.begin_approval(ctx, ADMIN, reg.device_id, fingerprint=reg.fingerprint)
    for op_id in (ticket.op_id + 100, None):
        assert refused(accounts.complete_approval, ctx, reg.device_id, op_id) == \
            P.INVALID_STATE
        assert refused(accounts.fail_approval, ctx, reg.device_id, op_id, "x") == \
            P.INVALID_STATE
    with ctx.repo.write() as tx:
        disable = tx.insert_op(reg.device_id, "disable", now=ctx.now_ts())
    assert refused(accounts.complete_approval, ctx, reg.device_id, disable) == \
        P.INVALID_STATE
    assert refused(accounts.complete_approval, ctx, "nada", ticket.op_id) == P.INVALID_STATE


# ---------------------------------------------------------------- rejeição e expiração


def test_reject_pending_request(ctx):
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx), 1)
    token = login_token(ctx, 1)
    rejected = accounts.reject(ctx, ADMIN, reg.device_id)
    assert (rejected.status, rejected.decided_by) == ("rejected", "adm")
    assert refused(sessions.authenticate, ctx, token) == P.UNAUTHORIZED
    assert refused(accounts.reject, ctx, ADMIN, reg.device_id) == P.INVALID_STATE
    # chave recusada para sempre; o dispositivo nunca volta
    assert refused(enroll, ctx, code_for(ctx), 1) == P.KEY_IN_USE
    assert refused(accounts.begin_approval, ctx, ADMIN, reg.device_id,
                   fingerprint=reg.fingerprint) == P.INVALID_STATE


def test_reject_requires_admin_and_operator_for_bootstrap(ctx):
    boot = enroll(ctx, invites.create_bootstrap(ctx, OPERATOR, project_id="demo").code, 1)
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    assert refused(accounts.reject, ctx, ADMIN, boot.device_id) == P.FORBIDDEN
    assert refused(accounts.reject, ctx, ADMIN, "nada") == P.NOT_FOUND
    reg = enroll(ctx, code_for(ctx), 2)
    assert refused(accounts.reject, ctx, Actor("dev1", "dev-dev1"), reg.device_id) == \
        P.FORBIDDEN
    assert accounts.reject(ctx, OPERATOR, boot.device_id).status == "rejected"


def test_pending_requests_expire(ctx, clock):
    with_admin(ctx)
    old = enroll(ctx, code_for(ctx), 1)
    clock.advance(604_800 - 1)
    young = enroll(ctx, code_for(ctx), 2)
    clock.advance(1)
    assert accounts.expire_pending(ctx) == [old.device_id]
    assert device(ctx, old.device_id).status == "expired"
    assert device(ctx, young.device_id).status == "pending"
    assert accounts.expire_pending(ctx) == []


# ---------------------------------------------------------------- revogação


def test_revoke_active_device(ctx, database):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    token = login_token(ctx, 50)
    op = accounts.revoke(ctx, ADMIN, "dev-dev1")
    assert device(ctx, "dev-dev1").status == "revoked"
    assert refused(sessions.authenticate, ctx, token) == P.UNAUTHORIZED
    with ctx.repo.read() as tx:
        assert (tx.get_op(op).action, tx.get_op(op).status) == ("disable", "pending")
        assert tx.session_by_token_hash(sessions.token_hash(token)).revoked_at is not None
    assert audit_events(database)[-1]["event"] == "device_revoked"
    assert refused(accounts.revoke, ctx, ADMIN, "dev-dev1") == P.INVALID_STATE
    assert refused(accounts.revoke, ctx, ADMIN, "nada") == P.NOT_FOUND


def test_revoke_requires_admin(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    seed_user(ctx, "dev2", key=51)
    assert refused(accounts.revoke, ctx, Actor("dev1", "dev-dev1"), "dev-dev2") == P.FORBIDDEN


def test_last_admin_device_cannot_be_revoked(ctx, database):
    with_admin(ctx)
    assert refused(accounts.revoke, ctx, ADMIN, "dev-adm") == P.LAST_ADMIN
    assert refused(accounts.revoke, ctx, OPERATOR, "dev-adm") == P.LAST_ADMIN
    assert device(ctx, "dev-adm").status == "active"
    seed_user(ctx, "adm", did="dev-adm-2", key=1001)  # segundo dispositivo do mesmo admin
    accounts.revoke(ctx, ADMIN, "dev-adm")
    assert refused(accounts.revoke, ctx, OPERATOR, "dev-adm-2") == P.LAST_ADMIN


def test_lost_last_admin_device_recovered_by_operator(ctx, database):
    with_admin(ctx)
    assert refused(accounts.revoke, ctx, ADMIN, "dev-adm",
                   allow_last_admin=True) == P.FORBIDDEN  # nunca pela API
    accounts.revoke(ctx, OPERATOR, "dev-adm", allow_last_admin=True)
    assert device(ctx, "dev-adm").status == "revoked"
    event = audit_events(database)[-1]
    assert (event["event"], event["allow_last_admin"], event["operator"]) == (
        "device_revoked", True, True)
    reg = enroll(ctx, invites.create_bootstrap(ctx, OPERATOR, project_id="demo").code, 5)
    approve(ctx, OPERATOR, reg.device_id)
    assert device(ctx, reg.device_id).status == "active"


def test_revoked_device_never_returns(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    accounts.revoke(ctx, ADMIN, "dev-dev1")
    accounts.block_user(ctx, ADMIN, "dev1")
    accounts.unblock_user(ctx, ADMIN, "dev1")
    assert device(ctx, "dev-dev1").status == "revoked"
    assert refused(accounts.begin_approval, ctx, ADMIN, "dev-dev1",
                   fingerprint=device(ctx, "dev-dev1").fingerprint) == P.INVALID_STATE


# ---------------------------------------------------------------- bloqueio


def test_block_and_unblock_user(ctx, database):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    seed_user(ctx, "dev1", did="dev-dev1-b", key=51)
    seed_user(ctx, "dev1", did="dev-dev1-r", key=52, device_status="revoked")
    token = login_token(ctx, 50)
    ops = accounts.block_user(ctx, ADMIN, "dev1")
    assert user(ctx, "dev1").status == "blocked"
    assert refused(sessions.authenticate, ctx, token) == P.UNAUTHORIZED
    with ctx.repo.read() as tx:
        assert sorted((tx.get_op(o).device_id, tx.get_op(o).action) for o in ops) == [
            ("dev-dev1", "disable"), ("dev-dev1-b", "disable")]
    assert refused(accounts.block_user, ctx, ADMIN, "dev1") == P.INVALID_STATE
    ops = accounts.unblock_user(ctx, ADMIN, "dev1")
    assert user(ctx, "dev1").status == "active"
    with ctx.repo.read() as tx:
        assert sorted((tx.get_op(o).device_id, tx.get_op(o).action) for o in ops) == [
            ("dev-dev1", "enable"), ("dev-dev1-b", "enable")]
    assert refused(sessions.authenticate, ctx, token) == P.UNAUTHORIZED  # sessão não volta
    assert sessions.authenticate(ctx, login_token(ctx, 50)).scope == "full"
    assert refused(accounts.unblock_user, ctx, ADMIN, "dev1") == P.INVALID_STATE
    events = [e["event"] for e in audit_events(database)]
    assert "user_blocked" in events and "user_unblocked" in events


def test_block_rules(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    assert refused(accounts.block_user, ctx, ADMIN, "nada") == P.NOT_FOUND
    assert refused(accounts.block_user, ctx, Actor("dev1", "dev-dev1"), "adm") == P.FORBIDDEN
    assert refused(accounts.block_user, ctx, ADMIN, "adm") == P.LAST_ADMIN
    assert refused(accounts.block_user, ctx, OPERATOR, "adm") == P.LAST_ADMIN
    assert refused(accounts.unblock_user, ctx, ADMIN, "nada") == P.NOT_FOUND


def test_blocking_a_developer_without_any_admin_is_allowed(ctx):
    seed_user(ctx, "dev1", key=50)
    assert accounts.block_user(ctx, OPERATOR, "dev1")


def test_second_admin_can_be_blocked(ctx):
    with_admin(ctx)
    seed_user(ctx, "adm2", role="admin", key=1001)
    accounts.block_user(ctx, ADMIN, "adm2")
    assert refused(accounts.block_user, ctx, ADMIN, "adm") == P.LAST_ADMIN


def test_admin_without_active_device_does_not_count(ctx):
    with_admin(ctx)
    seed_user(ctx, "adm2", role="admin", key=1001, device_status="pending")
    assert refused(accounts.block_user, ctx, ADMIN, "adm") == P.LAST_ADMIN
    assert accounts.block_user(ctx, ADMIN, "adm2") == []


# ---------------------------------------------------------------- promoção e rebaixamento


def test_promote_and_demote_only_by_operator(ctx, database):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    assert refused(accounts.promote, ctx, ADMIN, "dev1") == P.FORBIDDEN
    assert accounts.promote(ctx, OPERATOR, "dev1").role == "admin"
    assert refused(accounts.promote, ctx, OPERATOR, "dev1") == P.INVALID_STATE
    assert refused(accounts.demote, ctx, ADMIN, "dev1") == P.FORBIDDEN
    assert accounts.demote(ctx, OPERATOR, "dev1").role == "developer"
    assert refused(accounts.demote, ctx, OPERATOR, "dev1") == P.INVALID_STATE
    assert refused(accounts.demote, ctx, OPERATOR, "adm") == P.LAST_ADMIN
    assert refused(accounts.promote, ctx, OPERATOR, "nada") == P.NOT_FOUND
    assert refused(accounts.demote, ctx, OPERATOR, "nada") == P.NOT_FOUND
    events = [e["event"] for e in audit_events(database)]
    assert "user_promoted" in events and "user_demoted" in events


# ---------------------------------------------------------------- listagens


def test_list_requests(ctx):
    boot = enroll(ctx, invites.create_bootstrap(ctx, OPERATOR, project_id="demo").code, 1)
    with_admin(ctx)
    reg = enroll(ctx, code_for(ctx), 2, name="Fulana")
    requests = accounts.list_requests(ctx, ADMIN)
    assert [(r.device.id, r.user.display_name, r.invite.kind) for r in requests] == [
        (reg.device_id, "Fulana", "new_user")]
    assert refused(accounts.list_requests, ctx, ADMIN, include_bootstrap=True) == P.FORBIDDEN
    every = accounts.list_requests(ctx, OPERATOR, include_bootstrap=True)
    assert {r.device.id for r in every} == {boot.device_id, reg.device_id}
    seed_user(ctx, "dev1", key=50)
    assert refused(accounts.list_requests, ctx, Actor("dev1", "dev-dev1")) == P.FORBIDDEN


def test_list_devices_shows_pending_operations(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    op = accounts.revoke(ctx, ADMIN, "dev-dev1")
    views = {v.device.id: v for v in accounts.list_devices(ctx, ADMIN)}
    assert [o.id for o in views["dev-dev1"].pending_ops] == [op]
    assert views["dev-dev1"].user.id == "dev1"
    assert views["dev-adm"].pending_ops == []


def test_list_users_requires_admin(ctx):
    with_admin(ctx)
    seed_user(ctx, "dev1", key=50)
    assert [u.id for u in accounts.list_users(ctx, ADMIN)] == ["adm", "dev1"]
    assert refused(accounts.list_users, ctx, Actor("dev1", "dev-dev1")) == P.FORBIDDEN
