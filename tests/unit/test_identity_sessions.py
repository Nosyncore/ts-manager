"""Sessões: login por challenge-response, escopo, expiração, revogação e reconferência."""

from __future__ import annotations

import hashlib
import re
from datetime import timedelta

import pytest

from tests.unit.identity_fakes import (
    SERVER_ID,
    FakeVerifier,
    audit_events,
    fake_key,
    seed_user,
)
from tsm_common import protocol as P
from tsm_common.authmsg import AuthMessage
from tsm_common.sshkeys import parse_public_key
from tsm_manager.db.connection import ts
from tsm_manager.identity import challenges, sessions
from tsm_manager.identity.base import IdentityError

KEY = 7


def fp(n: int = KEY) -> str:
    return parse_public_key(fake_key(n)).fingerprint


def openssh(n: int = KEY) -> str:
    return parse_public_key(fake_key(n)).openssh


def login(ctx, *, key: int = KEY, signer_key: int | None = None, **over):
    issued = challenges.issue_login(ctx, fp(key))
    fields = dict(server_id=issued.server_id, purpose=issued.purpose,
                  challenge_id=issued.challenge_id, nonce=issued.nonce,
                  fingerprint=issued.fingerprint, expires=issued.expires_at)
    namespace = over.pop("namespace", "ts-manager-auth")
    fields.update(over)
    message = AuthMessage(**fields).to_bytes()
    signature = FakeVerifier.sign(openssh(signer_key or key), message, namespace)
    return issued, signature


def do_login(ctx, **kw):
    issued, signature = login(ctx, **kw)
    return sessions.login(ctx, issued.challenge_id, signature)


def refused(fn, *args) -> str:
    with pytest.raises(IdentityError) as err:
        fn(*args)
    return err.value.code


# ---------------------------------------------------------------- login


def test_login_of_active_device_gives_full_session(ctx, database, clock):
    seed_user(ctx, "u1", key=KEY)
    issued = do_login(ctx)
    assert issued.scope == "full"
    assert re.fullmatch(r"tsm-s-[A-Za-z0-9_-]{43}", issued.token)
    expected = clock().replace(microsecond=0) + timedelta(seconds=1800)
    assert issued.expires_at == expected
    with ctx.repo.read() as tx:
        stored = tx.session_by_token_hash(hashlib.sha256(issued.token.encode()).hexdigest())
        device = tx.get_device("dev-u1")
    assert stored.id == issued.session_id and stored.scope == "full"
    assert stored.expires_at == ts(expected)
    assert stored.token_sha256 != issued.token
    assert device.last_seen_at == ctx.now_ts()
    assert audit_events(database)[-1]["event"] == "login"


def test_session_expiration_is_absolute_thirty_minutes(ctx, clock):
    seed_user(ctx, "u1", key=KEY)
    issued = do_login(ctx)
    clock.advance(1799)
    assert sessions.authenticate(ctx, issued.token).scope == "full"
    clock.advance(1)
    assert refused(sessions.authenticate, ctx, issued.token) == P.SESSION_EXPIRED


@pytest.mark.parametrize("status", ["pending", "provisioning"])
def test_login_of_pending_device_gives_pending_session(ctx, status):
    seed_user(ctx, "u1", key=KEY, device_status=status)
    assert do_login(ctx).scope == "pending"


@pytest.mark.parametrize("status", ["rejected", "revoked", "expired"])
def test_login_of_closed_device_refused(ctx, status):
    seed_user(ctx, "u1", key=KEY, device_status=status)
    issued, signature = login(ctx)
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED


def test_login_of_blocked_user_refused(ctx):
    seed_user(ctx, "u1", key=KEY, status="blocked")
    issued, signature = login(ctx)
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED


def test_unknown_fingerprint_never_logs_in(ctx, verifier):
    issued, signature = login(ctx, key=99)
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED
    assert verifier.calls == []  # nada a verificar: não há chave registrada


@pytest.mark.parametrize("over", [
    {"server_id": "5e1f0000-0000-4000-8000-00000000beef"},   # outro Manager
    {"purpose": "register"},                                  # outro propósito
    {"challenge_id": "00000000-0000-4000-8000-000000000000"},  # outro desafio
    {"nonce": "A" * 43},
    {"namespace": "file"},                                    # outro namespace
    {"signer_key": 8},                                        # outra chave
])
def test_signature_over_anything_else_refused(ctx, database, over):
    seed_user(ctx, "u1", key=KEY)
    seed_user(ctx, "u2", key=8)
    issued, signature = login(ctx, **over)
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED
    assert audit_events(database)[-1]["step"] == "signature"


def test_replay_of_a_valid_signature_refused(ctx):
    seed_user(ctx, "u1", key=KEY)
    issued, signature = login(ctx)
    sessions.login(ctx, issued.challenge_id, signature)
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED


def test_wrong_signature_spends_the_challenge(ctx):
    seed_user(ctx, "u1", key=KEY)
    issued, signature = login(ctx)
    assert refused(sessions.login, ctx, issued.challenge_id, "errada") == P.UNAUTHORIZED
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED


def test_expired_challenge_refused(ctx, clock):
    seed_user(ctx, "u1", key=KEY)
    issued, signature = login(ctx)
    clock.advance(61)
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED


def test_register_challenge_cannot_log_in(ctx):
    seed_user(ctx, "u1", key=KEY)
    issued = challenges.issue_register(ctx, fake_key(KEY))
    signature = FakeVerifier.sign(openssh(), issued.message())
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED


@pytest.mark.parametrize("signature", [None, 42, "", "x" * 10_000])
def test_malformed_signature_refused(ctx, signature):
    seed_user(ctx, "u1", key=KEY)
    issued, _ = login(ctx)
    assert refused(sessions.login, ctx, issued.challenge_id, signature) == P.UNAUTHORIZED


# ---------------------------------------------------------------- reconferência por requisição


def test_authenticate_returns_the_principal(ctx):
    seed_user(ctx, "u1", key=KEY, role="admin")
    issued = do_login(ctx)
    principal = sessions.authenticate(ctx, issued.token)
    assert (principal.user_id, principal.device_id, principal.role, principal.scope,
            principal.fingerprint, principal.session_id) == (
        "u1", "dev-u1", "admin", "full", fp(), issued.session_id)
    assert principal.is_admin and principal.is_full


def test_revoked_device_loses_access_on_the_next_request(ctx):
    seed_user(ctx, "u1", key=KEY)
    issued = do_login(ctx)
    with ctx.repo.write() as tx:  # sessões continuam no banco: a reconferência basta
        tx.update_device("dev-u1", status="revoked")
    assert refused(sessions.authenticate, ctx, issued.token) == P.UNAUTHORIZED


def test_blocked_user_loses_access_on_the_next_request(ctx):
    seed_user(ctx, "u1", key=KEY)
    issued = do_login(ctx)
    with ctx.repo.write() as tx:
        tx.update_user("u1", now=ctx.now_ts(), status="blocked")
    assert refused(sessions.authenticate, ctx, issued.token) == P.UNAUTHORIZED


def test_role_change_is_seen_on_the_next_request(ctx):
    seed_user(ctx, "u1", key=KEY, role="admin")
    issued = do_login(ctx)
    with ctx.repo.write() as tx:
        tx.update_user("u1", now=ctx.now_ts(), role="developer")
    assert sessions.authenticate(ctx, issued.token).role == "developer"


def test_pending_session_stays_pending_after_approval(ctx):
    seed_user(ctx, "u1", key=KEY, device_status="pending")
    issued = do_login(ctx)
    with ctx.repo.write() as tx:
        tx.update_device("dev-u1", status="active")
    assert sessions.authenticate(ctx, issued.token).scope == "pending"
    assert do_login(ctx).scope == "full"  # o Client refaz o login


def test_expired_session_of_revoked_device_is_unauthorized(ctx, clock):
    seed_user(ctx, "u1", key=KEY)
    issued = do_login(ctx)
    clock.advance(4000)
    with ctx.repo.write() as tx:
        tx.update_device("dev-u1", status="revoked")
    assert refused(sessions.authenticate, ctx, issued.token) == P.UNAUTHORIZED


@pytest.mark.parametrize("token", [None, "", "tsm-s-curto", "Bearer x",
                                   "tsm-s-" + "A" * 43, "tsm-s-" + "A" * 42 + "!"])
def test_unknown_or_malformed_token(ctx, token):
    assert refused(sessions.authenticate, ctx, token) == P.UNAUTHORIZED


def test_full_session_of_device_back_to_pending_is_refused(ctx):
    # não há transição active → pending; a regra protege contra estado inconsistente
    seed_user(ctx, "u1", key=KEY)
    issued = do_login(ctx)
    with ctx.repo.write() as tx:
        tx.update_device("dev-u1", status="provisioning")
    assert refused(sessions.authenticate, ctx, issued.token) == P.UNAUTHORIZED


# ---------------------------------------------------------------- logout e limpeza


def test_logout_revokes_only_the_current_session(ctx, database):
    seed_user(ctx, "u1", key=KEY)
    a = do_login(ctx)
    b = do_login(ctx)
    sessions.logout(ctx, sessions.authenticate(ctx, a.token))
    assert refused(sessions.authenticate, ctx, a.token) == P.UNAUTHORIZED
    assert sessions.authenticate(ctx, b.token).scope == "full"
    assert audit_events(database)[-1]["event"] == "logout"


def test_purge_removes_only_old_sessions(ctx, clock):
    seed_user(ctx, "u1", key=KEY)
    old = do_login(ctx)
    clock.advance(1800 + 86_400 + 1)
    recent = do_login(ctx)
    assert sessions.purge(ctx) == 1
    assert refused(sessions.authenticate, ctx, old.token) == P.UNAUTHORIZED
    assert sessions.authenticate(ctx, recent.token).scope == "full"


def test_response_never_contains_the_hash(ctx):
    seed_user(ctx, "u1", key=KEY)
    issued = do_login(ctx)
    body = issued.to_response()
    assert body == {"token": issued.token, "scope": "full", "expires_at": body["expires_at"],
                    "user_id": "u1", "device_id": "dev-u1"}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["expires_at"])
    assert SERVER_ID not in body.values()
