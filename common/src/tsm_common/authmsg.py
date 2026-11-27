"""Mensagem canônica do challenge-response (assinada com ``ssh-keygen -Y sign``).

O Client monta a mensagem a partir da resposta do desafio; o Manager a remonta a partir do
registro do desafio, nunca do corpo da requisição. Os dois lados usam este módulo, então os
bytes são os mesmos::

    tsm-auth-v1
    server: <server_id>
    purpose: login
    challenge: <challenge_id>
    nonce: <base64url, 32 bytes>
    key: SHA256:<fingerprint>
    expires: 2026-11-26T12:00:00Z

Cada linha termina em ``\\n``. O namespace SSHSIG é ``ts-manager-auth``.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from tsm_common.sshkeys import is_fingerprint

NAMESPACE = "ts-manager-auth"
VERSION_LINE = "tsm-auth-v1"
PURPOSES = ("register", "login")
NONCE_BYTES = 32

_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_EXPIRES_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_EXPIRES_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class AuthMessageError(ValueError):
    """Campo inválido para a mensagem canônica."""


def encode_nonce(raw: bytes) -> str:
    if len(raw) != NONCE_BYTES:
        raise AuthMessageError(f"nonce deve ter {NONCE_BYTES} bytes")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def is_nonce(value: object) -> bool:
    return isinstance(value, str) and bool(_NONCE_RE.match(value))


def format_expires(moment: datetime) -> str:
    if not isinstance(moment, datetime) or moment.tzinfo is None:
        raise AuthMessageError("expiração sem fuso")
    if moment.microsecond:
        raise AuthMessageError("expiração com fração de segundo")
    return moment.astimezone(UTC).strftime(_EXPIRES_FORMAT)


def parse_expires(text: str) -> datetime:
    if not isinstance(text, str) or not _EXPIRES_RE.match(text):
        raise AuthMessageError(f"expiração inválida: {text!r}")
    try:
        return datetime.strptime(text, _EXPIRES_FORMAT).replace(tzinfo=UTC)
    except ValueError as exc:
        raise AuthMessageError(f"expiração inválida: {text!r}") from exc


@dataclass(frozen=True)
class AuthMessage:
    server_id: str
    purpose: str
    challenge_id: str
    nonce: str
    fingerprint: str
    expires: datetime

    def _check(self) -> None:
        for name in ("server_id", "challenge_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _ID_RE.match(value):
                raise AuthMessageError(f"{name} inválido")
        if self.purpose not in PURPOSES:
            raise AuthMessageError(f"propósito inválido: {self.purpose!r}")
        if not is_nonce(self.nonce):
            raise AuthMessageError("nonce inválido")
        if not is_fingerprint(self.fingerprint):
            raise AuthMessageError("fingerprint inválido")

    def to_bytes(self) -> bytes:
        self._check()
        lines = [
            VERSION_LINE,
            f"server: {self.server_id}",
            f"purpose: {self.purpose}",
            f"challenge: {self.challenge_id}",
            f"nonce: {self.nonce}",
            f"key: {self.fingerprint}",
            f"expires: {format_expires(self.expires)}",
        ]
        return ("\n".join(lines) + "\n").encode("ascii")
