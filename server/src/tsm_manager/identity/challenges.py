"""Desafios do challenge-response (prova de posse da chave do dispositivo).

- ``register`` fixa a chave pública (normalizada) e o fingerprint calculado aqui;
  ``login`` fixa o fingerprint. Para um fingerprint desconhecido o desafio é emitido e
  gravado do mesmo jeito: a resposta não revela se o dispositivo existe, e o desafio nunca
  será aceito porque não há chave para verificar.
- Expiração em segundos inteiros; válido enquanto ``agora < expires_at``.
- ``claim`` consome o desafio **antes** da verificação da assinatura: cada desafio vale uma
  tentativa, certa ou errada, e a verificação (``ssh-keygen``) roda fora da transação.
- A mensagem assinada é sempre remontada do registro, nunca da requisição.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from tsm_common import protocol as P
from tsm_common.authmsg import NONCE_BYTES, AuthMessage, encode_nonce, format_expires
from tsm_common.sshkeys import PublicKeyError, is_fingerprint, parse_public_key
from tsm_manager.db.connection import parse_ts, ts
from tsm_manager.db.repository import Challenge
from tsm_manager.identity.base import IdentityContext, IdentityError, unauthorized

REGISTER = "register"
LOGIN = "login"
_MAX_ID_CHARS = 64


@dataclass(frozen=True)
class IssuedChallenge:
    challenge_id: str
    purpose: str
    nonce: str
    fingerprint: str
    expires_at: datetime
    server_id: str

    def message(self) -> bytes:
        return AuthMessage(self.server_id, self.purpose, self.challenge_id, self.nonce,
                           self.fingerprint, self.expires_at).to_bytes()

    def to_response(self) -> dict[str, str]:
        return {"challenge_id": self.challenge_id, "nonce": self.nonce,
                "expires_at": format_expires(self.expires_at), "server_id": self.server_id,
                "purpose": self.purpose}


def _issue(ctx: IdentityContext, purpose: str, fingerprint: str,
           public_key: str | None) -> IssuedChallenge:
    now = ctx.now()
    expires = now.replace(microsecond=0) + timedelta(seconds=ctx.settings.challenge_ttl_s)
    challenge = Challenge(id=ctx.new_id(), nonce=encode_nonce(ctx.random(NONCE_BYTES)),
                          purpose=purpose, fingerprint=fingerprint, public_key=public_key,
                          created_at=ts(now), expires_at=ts(expires))
    with ctx.repo.write() as tx:
        tx.insert_challenge(challenge)
    return IssuedChallenge(challenge.id, purpose, challenge.nonce, fingerprint, expires,
                           ctx.server_id)


def issue_register(ctx: IdentityContext, public_key: str) -> IssuedChallenge:
    try:
        key = parse_public_key(public_key)
    except PublicKeyError as exc:
        raise IdentityError(P.INVALID_REQUEST, f"chave pública recusada: {exc}") from exc
    return _issue(ctx, REGISTER, key.fingerprint, key.openssh)


def issue_login(ctx: IdentityContext, fingerprint: str) -> IssuedChallenge:
    if not is_fingerprint(fingerprint):
        raise IdentityError(P.INVALID_REQUEST, "fingerprint inválido")
    return _issue(ctx, LOGIN, fingerprint, None)


def claim(ctx: IdentityContext, challenge_id: str, purpose: str) -> Challenge:
    """Consome o desafio (uso único). Inexistente, usado, expirado ou de outro propósito →
    ``unauthorized``, auditado."""
    found = None
    if isinstance(challenge_id, str) and 0 < len(challenge_id) <= _MAX_ID_CHARS:
        now = ctx.now_ts()
        with ctx.repo.write() as tx:
            challenge = tx.get_challenge(challenge_id)
            if challenge is not None and tx.consume_challenge(challenge_id, now=now):
                found = tx.get_challenge(challenge_id)
    if found is None or found.purpose != purpose:
        raise ctx.refuse("auth_refused", unauthorized(), step="challenge", purpose=purpose)
    return found


def message_for(ctx: IdentityContext, challenge: Challenge) -> bytes:
    return AuthMessage(ctx.server_id, challenge.purpose, challenge.id, challenge.nonce,
                       challenge.fingerprint, parse_ts(challenge.expires_at)).to_bytes()


def purge(ctx: IdentityContext) -> int:
    """Apaga desafios expirados há mais de ``purge_after_s``."""
    with ctx.repo.write() as tx:
        return tx.purge_challenges(before=ctx.after(-ctx.settings.purge_after_s))
