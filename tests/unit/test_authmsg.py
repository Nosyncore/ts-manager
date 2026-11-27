"""Mensagem canônica assinada no challenge-response."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta, timezone

import pytest

from tsm_common.authmsg import (
    NAMESPACE,
    NONCE_BYTES,
    AuthMessage,
    AuthMessageError,
    encode_nonce,
    format_expires,
    is_nonce,
    parse_expires,
)

FP = "SHA256:abBPfU7aCcoDwiDDdarFS0BxHQhEyGBlZ6EXeF5Tucc"
NONCE = encode_nonce(bytes(range(32)))
EXPIRES = datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)


def message(**over) -> AuthMessage:
    base = dict(server_id="7f0c2b9e-0000-4000-8000-000000000001", purpose="login",
                challenge_id="c0ffee00-0000-4000-8000-000000000002", nonce=NONCE,
                fingerprint=FP, expires=EXPIRES)
    base.update(over)
    return AuthMessage(**base)


def test_canonical_bytes_exact():
    assert message().to_bytes() == (
        b"tsm-auth-v1\n"
        b"server: 7f0c2b9e-0000-4000-8000-000000000001\n"
        b"purpose: login\n"
        b"challenge: c0ffee00-0000-4000-8000-000000000002\n"
        b"nonce: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n"
        b"key: SHA256:abBPfU7aCcoDwiDDdarFS0BxHQhEyGBlZ6EXeF5Tucc\n"
        b"expires: 2026-11-26T12:00:00Z\n"
    )
    assert NAMESPACE == "ts-manager-auth"


def test_every_field_changes_the_bytes():
    base = message().to_bytes()
    variants = [
        message(server_id="7f0c2b9e-0000-4000-8000-000000000009"),
        message(purpose="register"),
        message(challenge_id="c0ffee00-0000-4000-8000-000000000009"),
        message(nonce=encode_nonce(b"\x01" * 32)),
        message(fingerprint="SHA256:dDefZ4hGmbhKLrer8QXXIOsCzOBcACx++yhp4Vp+nPI"),
        message(expires=EXPIRES + timedelta(seconds=1)),
    ]
    assert len({v.to_bytes() for v in variants} | {base}) == len(variants) + 1


def test_expires_in_other_timezone_is_normalized_to_utc():
    local = EXPIRES.astimezone(timezone(timedelta(hours=-3)))
    assert message(expires=local).to_bytes() == message().to_bytes()


def test_nonce_encoding():
    assert NONCE_BYTES == 32
    assert is_nonce(NONCE) and len(NONCE) == 43 and "=" not in NONCE
    assert not is_nonce(NONCE + "A")
    assert not is_nonce(NONCE[:-1] + "+")
    assert not is_nonce(None)
    with pytest.raises(AuthMessageError):
        encode_nonce(b"\x00" * 16)


@pytest.mark.parametrize("field,value", [
    ("server_id", "a\nb"),
    ("server_id", ""),
    ("server_id", "x" * 65),
    ("purpose", "admin"),
    ("challenge_id", "id com espaço"),
    ("nonce", "curto"),
    ("fingerprint", "SHA256:x\nkey: SHA256:y"),
    ("expires", datetime(2026, 11, 26, 12, 0, 0)),                    # sem fuso
    ("expires", EXPIRES.replace(microsecond=5)),                       # fração de segundo
    ("expires", "2026-11-26T12:00:00Z"),
])
def test_invalid_fields_refused(field, value):
    with pytest.raises(AuthMessageError):
        message(**{field: value}).to_bytes()


def test_expires_text_roundtrip():
    assert format_expires(EXPIRES) == "2026-11-26T12:00:00Z"
    assert parse_expires("2026-11-26T12:00:00Z") == EXPIRES
    for bad in ["2026-11-26T12:00:00", "2026-11-26T12:00:00.5Z", "amanhã", None]:
        with pytest.raises(AuthMessageError):
            parse_expires(bad)  # type: ignore[arg-type]


def test_message_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        message().purpose = "register"  # type: ignore[misc]
