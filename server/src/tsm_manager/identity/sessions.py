"""Sessões da API: login por challenge-response e reconferência a cada requisição.

- ``login`` consome o desafio, verifica a assinatura com a chave **registrada** sobre a
  mensagem remontada do registro e, numa segunda transação, reconfere dispositivo e
  usuário e emite a sessão.
- Escopo ``full`` para dispositivo ``active`` de usuário ``active``; ``pending`` para
  dispositivo ``pending`` ou ``provisioning``. Qualquer outro caso: ``unauthorized``.
- Token ``tsm-s-`` + 256 bits em base64url; o banco guarda só o SHA-256. Expiração
  absoluta, sem renovação.
- ``authenticate`` reconfere sessão, dispositivo e usuário a cada chamada: revogar ou
  bloquear vale na requisição seguinte. A sessão nunca ganha privilégio: uma ``pending``
  continua ``pending`` após a aprovação, e o Client refaz o login.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from tsm_common import protocol as P
from tsm_common.authmsg import NAMESPACE, format_expires
from tsm_manager.db.connection import parse_ts, ts
from tsm_manager.db.repository import Device, Session, User
from tsm_manager.identity import challenges
from tsm_manager.identity.base import (
    SCOPE_FULL,
    SCOPE_PENDING,
    Actor,
    IdentityContext,
    IdentityError,
    Principal,
    unauthorized,
)

TOKEN_PREFIX = "tsm-s-"
_TOKEN_RE = re.compile(rf"^{TOKEN_PREFIX}[A-Za-z0-9_-]{{43}}$")
_MAX_SIGNATURE_CHARS = 4096


@dataclass(frozen=True)
class IssuedSession:
    token: str     # só existe aqui; o banco guarda o hash
    session_id: str
    scope: str
    expires_at: datetime
    user_id: str
    device_id: str

    def to_response(self) -> dict[str, str]:
        return {"token": self.token, "scope": self.scope,
                "expires_at": format_expires(self.expires_at), "user_id": self.user_id,
                "device_id": self.device_id}


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def scope_for(user: User | None, device: Device | None) -> str | None:
    """Escopo que o estado atual permite, ou ``None`` (sem acesso)."""
    if user is None or device is None or user.status != "active":
        return None
    if device.status == "active":
        return SCOPE_FULL
    if device.status in ("pending", "provisioning"):
        return SCOPE_PENDING
    return None


def _verified_device(ctx: IdentityContext, challenge_id: str, signature: object) -> Device:
    challenge = challenges.claim(ctx, challenge_id, challenges.LOGIN)
    with ctx.repo.read() as tx:
        device = tx.device_by_fingerprint(challenge.fingerprint)
    if (device is None or not isinstance(signature, str) or not signature
            or len(signature) > _MAX_SIGNATURE_CHARS
            or not ctx.verifier.verify(device.public_key, NAMESPACE,
                                       challenges.message_for(ctx, challenge), signature)):
        raise ctx.refuse("auth_refused", unauthorized(), step="signature", purpose="login")
    return device


def login(ctx: IdentityContext, challenge_id: str, signature: str) -> IssuedSession:
    device = _verified_device(ctx, challenge_id, signature)
    now = ctx.now()
    expires = now.replace(microsecond=0) + timedelta(seconds=ctx.settings.session_ttl_s)
    token = TOKEN_PREFIX + base64.urlsafe_b64encode(ctx.random(32)).decode().rstrip("=")
    with ctx.repo.write() as tx:
        current = tx.get_device(device.id)
        user = tx.get_user(current.user_id) if current else None
        scope = scope_for(user, current)
        if scope is not None and current is not None and user is not None:
            session = Session(id=ctx.new_id(), token_sha256=token_hash(token),
                              device_id=current.id, scope=scope, created_at=ts(now),
                              expires_at=ts(expires))
            tx.insert_session(session)
            tx.update_device(current.id, last_seen_at=ts(now))
            ctx.audit(tx, "login", actor=Actor(user.id, current.id), scope=scope,
                      session=session.id)
            return IssuedSession(token, session.id, scope, expires, user.id, current.id)
    raise ctx.refuse("auth_refused", unauthorized(), step="status", purpose="login",
                     device=device.id)


def authenticate(ctx: IdentityContext, token: object) -> Principal:
    """Token → ``Principal``; ``unauthorized`` ou ``session_expired``."""
    if not isinstance(token, str) or not _TOKEN_RE.match(token):
        raise unauthorized()
    with ctx.repo.read() as tx:
        session = tx.session_by_token_hash(token_hash(token))
        if session is None or session.revoked_at is not None:
            raise unauthorized()
        device = tx.get_device(session.device_id)
        user = tx.get_user(device.user_id) if device else None
    allowed = scope_for(user, device)
    if (allowed is None or user is None or device is None
            or (session.scope == SCOPE_FULL and allowed != SCOPE_FULL)):
        raise unauthorized()
    if ctx.now() >= parse_ts(session.expires_at):
        raise IdentityError(P.SESSION_EXPIRED, "sessão expirada")
    return Principal(session.id, user.id, user.role, device.id, device.fingerprint,
                     session.scope, session.expires_at)


def logout(ctx: IdentityContext, principal: Principal) -> None:
    with ctx.repo.write() as tx:
        if tx.revoke_session(principal.session_id, now=ctx.now_ts()):
            ctx.audit(tx, "logout", actor=Actor.of(principal), session=principal.session_id)


def purge(ctx: IdentityContext) -> int:
    """Apaga sessões expiradas há mais de ``purge_after_s``."""
    with ctx.repo.write() as tx:
        return tx.purge_sessions(before=ctx.after(-ctx.settings.purge_after_s))
