"""Desafios do challenge-response: emissão, expiração, uso único e mensagem."""

from __future__ import annotations

from datetime import timedelta

import pytest

from tests.unit.identity_fakes import (
    SERVER_ID,
    audit_events,
    fake_key,
)
from tsm_common import protocol as P
from tsm_common.authmsg import AuthMessage, is_nonce, parse_expires
from tsm_common.sshkeys import parse_public_key
from tsm_manager.identity import challenges
from tsm_manager.identity.base import IdentityError


def test_register_challenge_stores_normalized_key(ctx, database):
    key = parse_public_key(fake_key(1, "dev@pc"))
    issued = challenges.issue_register(ctx, fake_key(1, "dev@pc"))
    assert issued.purpose == "register"
    assert issued.server_id == SERVER_ID
    assert is_nonce(issued.nonce)
    with ctx.repo.read() as tx:
        stored = tx.get_challenge(issued.challenge_id)
    assert stored.public_key == key.openssh          # sem comentário
    assert stored.fingerprint == key.fingerprint      # calculado no servidor
    assert stored.purpose == "register" and stored.used_at is None


def test_register_challenge_refuses_bad_key(ctx):
    with pytest.raises(IdentityError) as err:
        challenges.issue_register(ctx, "ssh-rsa AAAA")
    assert err.value.code == P.INVALID_REQUEST


def test_expiration_in_whole_seconds(ctx, clock):
    issued = challenges.issue_login(ctx, parse_public_key(fake_key(1)).fingerprint)
    expected = clock().replace(microsecond=0) + timedelta(seconds=60)
    assert issued.expires_at == expected
    body = issued.to_response()
    assert body == {"challenge_id": issued.challenge_id, "nonce": issued.nonce,
                    "expires_at": "2026-11-26T12:01:00Z", "server_id": SERVER_ID,
                    "purpose": "login"}
    assert parse_expires(body["expires_at"]) == expected


def test_login_challenge_for_unknown_fingerprint_looks_the_same(ctx):
    known = challenges.issue_login(ctx, parse_public_key(fake_key(1)).fingerprint)
    unknown = challenges.issue_login(ctx, parse_public_key(fake_key(2)).fingerprint)
    assert set(known.to_response()) == set(unknown.to_response())
    assert len(known.challenge_id) == len(unknown.challenge_id)
    assert len(known.nonce) == len(unknown.nonce)
    with ctx.repo.read() as tx:  # ambos gravados: o caminho é o mesmo
        assert tx.get_challenge(unknown.challenge_id) is not None


@pytest.mark.parametrize("fp", ["", "SHA256:curto", "MD5:aa", None, 42])
def test_login_challenge_refuses_malformed_fingerprint(ctx, fp):
    with pytest.raises(IdentityError) as err:
        challenges.issue_login(ctx, fp)
    assert err.value.code == P.INVALID_REQUEST


def test_ids_and_nonces_come_from_injected_random(ctx, rng):
    a = challenges.issue_login(ctx, parse_public_key(fake_key(1)).fingerprint)
    b = challenges.issue_login(ctx, parse_public_key(fake_key(1)).fingerprint)
    assert a.challenge_id != b.challenge_id and a.nonce != b.nonce
    assert rng.calls.count(32) == 2 and rng.calls.count(16) == 2


def test_claim_is_single_use(ctx, database):
    issued = challenges.issue_login(ctx, parse_public_key(fake_key(1)).fingerprint)
    ch = challenges.claim(ctx, issued.challenge_id, "login")
    assert ch.id == issued.challenge_id and ch.used_at is not None
    with pytest.raises(IdentityError) as err:
        challenges.claim(ctx, issued.challenge_id, "login")
    assert err.value.code == P.UNAUTHORIZED
    assert audit_events(database)[-1] == {
        "event": "auth_refused", "project": None, "user": None, "device": None,
        "reason": P.UNAUTHORIZED, "step": "challenge", "purpose": "login"}


def test_claim_at_the_expiration_instant_is_refused(ctx, clock):
    fp = parse_public_key(fake_key(1)).fingerprint
    ok = challenges.issue_login(ctx, fp)
    late = challenges.issue_login(ctx, fp)
    expires = ok.expires_at
    clock.current = expires - timedelta(microseconds=1)
    challenges.claim(ctx, ok.challenge_id, "login")
    clock.current = expires
    with pytest.raises(IdentityError):
        challenges.claim(ctx, late.challenge_id, "login")


def test_claim_with_other_purpose_spends_the_challenge(ctx):
    issued = challenges.issue_register(ctx, fake_key(1))
    with pytest.raises(IdentityError):
        challenges.claim(ctx, issued.challenge_id, "login")
    with pytest.raises(IdentityError):  # uma tentativa só, certa ou errada
        challenges.claim(ctx, issued.challenge_id, "register")


@pytest.mark.parametrize("cid", ["nada", "", None, "x" * 500])
def test_claim_unknown_or_malformed(ctx, cid):
    with pytest.raises(IdentityError) as err:
        challenges.claim(ctx, cid, "login")
    assert err.value.code == P.UNAUTHORIZED


def test_message_is_rebuilt_from_the_record(ctx):
    fp = parse_public_key(fake_key(1)).fingerprint
    issued = challenges.issue_login(ctx, fp)
    ch = challenges.claim(ctx, issued.challenge_id, "login")
    expected = AuthMessage(SERVER_ID, "login", issued.challenge_id, issued.nonce, fp,
                           issued.expires_at).to_bytes()
    assert challenges.message_for(ctx, ch) == expected
    assert challenges.message_for(ctx, ch) == issued.message()


def test_purge_removes_only_old_challenges(ctx, clock):
    fp = parse_public_key(fake_key(1)).fingerprint
    old = challenges.issue_login(ctx, fp)
    clock.advance(86_400 + 120)
    recent = challenges.issue_login(ctx, fp)
    assert challenges.purge(ctx) == 1
    with ctx.repo.read() as tx:
        assert tx.get_challenge(old.challenge_id) is None
        assert tx.get_challenge(recent.challenge_id) is not None
