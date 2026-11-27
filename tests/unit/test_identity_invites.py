"""Convites: formato, hash, tipos, validade, revogação, uso único e erro genérico."""

from __future__ import annotations

import hashlib
import re
import threading

import pytest

from tests.unit.identity_fakes import (
    audit_events,
    seed_user,
)
from tsm_common import protocol as P
from tsm_manager.identity import invites
from tsm_manager.identity.base import Actor, IdentityError

OPERATOR = Actor.operator()


def admin(ctx) -> Actor:
    uid, did = seed_user(ctx, "adm", role="admin")
    return Actor(uid, did)


def take(ctx, code):
    with ctx.repo.write() as tx:
        return invites.take(tx, code, now=ctx.now_ts())


def test_code_format_and_entropy(ctx, rng):
    actor = admin(ctx)
    created = invites.create(ctx, actor, project_id="demo")
    assert re.fullmatch(r"tsm-inv-[a-z2-7]{26}", created.code)
    assert 17 in rng.calls  # 136 bits sorteados, 130 usados
    other = invites.create(ctx, actor, project_id="demo")
    assert other.code != created.code


def test_only_the_hash_is_stored(ctx, database):
    created = invites.create(ctx, admin(ctx), project_id="demo")
    digest = hashlib.sha256(created.code.encode()).hexdigest()
    assert created.invite.code_sha256 == digest
    with database.read() as conn:
        dump = "\n".join(str(tuple(r)) for r in conn.execute("SELECT * FROM invites"))
        dump += "\n".join(str(tuple(r)) for r in conn.execute("SELECT * FROM audit_logs"))
    assert created.code not in dump
    assert created.code[len("tsm-inv-"):] not in dump


def test_code_accepted_case_insensitive_and_trimmed(ctx):
    created = invites.create(ctx, admin(ctx), project_id="demo")
    assert invites.code_hash(f"  {created.code.upper().replace('TSM-INV-', 'tsm-inv-')}\n") \
        == created.invite.code_sha256
    assert invites.code_hash(created.code.upper()) == created.invite.code_sha256


@pytest.mark.parametrize("code", ["", "tsm-inv-", "tsm-inv-abc", "tsm-inv-" + "a" * 27,
                                  "tsm-inv-" + "1" * 26, "x" * 34, None, 42])
def test_malformed_codes_have_no_hash(code):
    assert invites.code_hash(code) is None


def test_default_and_maximum_validity(ctx, clock):
    actor = admin(ctx)
    default = invites.create(ctx, actor, project_id="demo")
    assert default.invite.expires_at == ctx.after(86_400)
    longest = invites.create(ctx, actor, project_id="demo", ttl_s=604_800)
    assert longest.invite.expires_at == ctx.after(604_800)
    for bad in (604_801, 0, -1, 1.5, "60"):
        with pytest.raises(IdentityError) as err:
            invites.create(ctx, actor, project_id="demo", ttl_s=bad)
        assert err.value.code == P.INVALID_REQUEST


def test_new_user_invite_roles(ctx):
    actor = admin(ctx)
    assert invites.create(ctx, actor, project_id="demo").invite.role == "developer"
    assert invites.create(ctx, actor, project_id="demo", role="admin").invite.role == "admin"
    with pytest.raises(IdentityError):
        invites.create(ctx, actor, project_id="demo", role="root")
    with pytest.raises(IdentityError):  # new_user não aponta usuário
        invites.create(ctx, actor, project_id="demo", for_user="adm")


def test_new_device_invite_takes_the_user_role(ctx):
    actor = admin(ctx)
    seed_user(ctx, "dev1")
    created = invites.create(ctx, actor, project_id="demo", kind="new_device",
                             for_user="dev1", role="admin")
    assert (created.invite.kind, created.invite.user_id, created.invite.role) == (
        "new_device", "dev1", "developer")


@pytest.mark.parametrize("user", [None, "ninguem", "bloq"])
def test_new_device_invite_needs_an_active_user(ctx, user):
    actor = admin(ctx)
    seed_user(ctx, "bloq", status="blocked")
    with pytest.raises(IdentityError) as err:
        invites.create(ctx, actor, project_id="demo", kind="new_device", for_user=user)
    assert err.value.code == P.INVALID_REQUEST


def test_unknown_project_or_kind_refused(ctx):
    actor = admin(ctx)
    with pytest.raises(IdentityError) as err:
        invites.create(ctx, actor, project_id="nao-existe")
    assert err.value.code == P.INVALID_REQUEST
    with pytest.raises(IdentityError) as err:
        invites.create(ctx, actor, project_id="demo", kind="qualquer")
    assert err.value.code == P.INVALID_REQUEST


def test_bootstrap_kind_never_through_create(ctx):
    with pytest.raises(IdentityError) as err:
        invites.create(ctx, admin(ctx), project_id="demo", kind="bootstrap")
    assert err.value.code == P.FORBIDDEN


def test_create_requires_an_active_admin(ctx):
    seed_user(ctx, "dev1")
    seed_user(ctx, "adm-b", role="admin", status="blocked")
    seed_user(ctx, "adm-r", role="admin", device_status="revoked")
    for actor in (Actor("dev1", "dev-dev1"), Actor("adm-b", "dev-adm-b"),
                  Actor("adm-r", "dev-adm-r"), Actor("dev1", "dev-adm-b"), Actor()):
        with pytest.raises(IdentityError) as err:
            invites.create(ctx, actor, project_id="demo")
        assert err.value.code == P.FORBIDDEN
    assert invites.create(ctx, OPERATOR, project_id="demo").invite.created_by is None


def test_creation_is_audited_without_the_code(ctx, database):
    created = invites.create(ctx, admin(ctx), project_id="demo")
    event = audit_events(database)[-1]
    assert event == {"event": "invite_created", "project": "demo", "user": "adm",
                     "device": "dev-adm", "invite": created.invite.id, "kind": "new_user",
                     "role": "developer", "expires_at": created.invite.expires_at}


# ---------------------------------------------------------------- bootstrap


def test_bootstrap_only_by_operator_and_without_active_admin(ctx):
    created = invites.create_bootstrap(ctx, OPERATOR, project_id="demo")
    assert (created.invite.kind, created.invite.role) == ("bootstrap", "admin")
    seed_user(ctx, "adm", role="admin")
    with pytest.raises(IdentityError) as err:
        invites.create_bootstrap(ctx, OPERATOR, project_id="demo")
    assert err.value.code == P.INVALID_STATE
    with pytest.raises(IdentityError) as err:
        invites.create_bootstrap(ctx, Actor("adm", "dev-adm"), project_id="demo")
    assert err.value.code == P.FORBIDDEN


def test_admin_without_active_device_does_not_block_bootstrap(ctx):
    seed_user(ctx, "adm", role="admin", device_status="revoked")
    assert invites.create_bootstrap(ctx, OPERATOR, project_id="demo").invite.kind == "bootstrap"


def test_new_bootstrap_revokes_the_open_ones(ctx):
    first = invites.create_bootstrap(ctx, OPERATOR, project_id="demo")
    second = invites.create_bootstrap(ctx, OPERATOR, project_id="demo")
    with pytest.raises(IdentityError):
        take(ctx, first.code)
    assert take(ctx, second.code).id == second.invite.id


# ---------------------------------------------------------------- uso


def test_take_consumes_once(ctx):
    created = invites.create(ctx, admin(ctx), project_id="demo")
    taken = take(ctx, created.code)
    assert taken.id == created.invite.id and taken.used_at is not None
    with pytest.raises(IdentityError) as err:
        take(ctx, created.code)
    assert err.value.code == P.INVALID_INVITE


def test_every_bad_invite_gives_the_same_error(ctx, clock):
    actor = admin(ctx)
    used = invites.create(ctx, actor, project_id="demo")
    take(ctx, used.code)
    revoked = invites.create(ctx, actor, project_id="demo")
    invites.revoke(ctx, actor, revoked.invite.id)
    expired = invites.create(ctx, actor, project_id="demo", ttl_s=10)
    clock.advance(10)
    errors = []
    for code in (used.code, revoked.code, expired.code, "tsm-inv-" + "a" * 26, "lixo"):
        with pytest.raises(IdentityError) as err:
            take(ctx, code)
        errors.append((err.value.code, err.value.message))
    assert len(set(errors)) == 1 and errors[0][0] == P.INVALID_INVITE


def test_invite_used_by_two_concurrent_transactions(ctx):
    created = invites.create(ctx, admin(ctx), project_id="demo")
    barrier = threading.Barrier(2)
    results: list[str] = []

    def worker():
        barrier.wait()
        try:
            take(ctx, created.code)
            results.append("ok")
        except IdentityError as exc:
            results.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == sorted(["ok", P.INVALID_INVITE])


# ---------------------------------------------------------------- listagem e revogação


def test_states_in_listing(ctx, clock):
    actor = admin(ctx)
    used = invites.create(ctx, actor, project_id="demo")
    take(ctx, used.code)
    revoked = invites.create(ctx, actor, project_id="demo")
    invites.revoke(ctx, actor, revoked.invite.id)
    expiring = invites.create(ctx, actor, project_id="demo", ttl_s=10)
    still_open = invites.create(ctx, actor, project_id="demo")
    clock.advance(10)
    states = {i.id: s for i, s in invites.list_invites(ctx, actor)}
    assert states[used.invite.id] == "used"
    assert states[revoked.invite.id] == "revoked"
    assert states[expiring.invite.id] == "expired"
    assert states[still_open.invite.id] == "open"


def test_listing_requires_admin(ctx):
    seed_user(ctx, "dev1")
    with pytest.raises(IdentityError):
        invites.list_invites(ctx, Actor("dev1", "dev-dev1"))


def test_revoke_rules(ctx):
    actor = admin(ctx)
    created = invites.create(ctx, actor, project_id="demo")
    revoked = invites.revoke(ctx, actor, created.invite.id)
    assert revoked.revoked_at is not None
    with pytest.raises(IdentityError) as err:
        invites.revoke(ctx, actor, created.invite.id)
    assert err.value.code == P.INVALID_STATE
    with pytest.raises(IdentityError) as err:
        invites.revoke(ctx, actor, "nao-existe")
    assert err.value.code == P.NOT_FOUND


def test_bootstrap_invite_revoked_only_by_operator(ctx):
    boot = invites.create_bootstrap(ctx, OPERATOR, project_id="demo")
    actor = admin(ctx)
    with pytest.raises(IdentityError) as err:
        invites.revoke(ctx, actor, boot.invite.id)
    assert err.value.code == P.FORBIDDEN
    assert invites.revoke(ctx, OPERATOR, boot.invite.id).revoked_at is not None
