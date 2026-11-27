"""Dependências e tipos comuns do domínio de identidade.

O domínio não lê relógio, não gera aleatórios e não executa ``ssh-keygen`` por conta
própria: tudo chega por ``IdentityContext``. Os unitários trocam relógio, aleatórios e
verificador de assinatura por fakes; o repositório é o único ponto que fala com o banco.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from tsm_common import protocol as P
from tsm_manager.db.connection import ts, utcnow
from tsm_manager.db.repository import Repository, Tx

Clock = Callable[[], datetime]
RandomSource = Callable[[int], bytes]

ADMIN = "admin"
DEVELOPER = "developer"
ROLES = (DEVELOPER, ADMIN)
SCOPE_FULL = "full"
SCOPE_PENDING = "pending"


class SignatureVerifier(Protocol):
    def verify(self, public_key: str, namespace: str, message: bytes,
               signature: str) -> bool:
        """``True`` só se ``signature`` (SSHSIG armorado) for da chave sobre a mensagem."""
        ...


class IdentityError(Exception):
    """Recusa do domínio, com um status de ``tsm_common.protocol``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    @property
    def http_status(self) -> int:
        return P.HTTP_STATUS.get(self.code, 500)


def unauthorized() -> IdentityError:
    return IdentityError(P.UNAUTHORIZED, "não autenticado")


@dataclass(frozen=True)
class AuthSettings:
    challenge_ttl_s: int = 60
    session_ttl_s: int = 1800
    invite_ttl_s: int = 86_400
    invite_ttl_max_s: int = 604_800
    pending_ttl_s: int = 604_800
    purge_after_s: int = 86_400


@dataclass(frozen=True)
class Principal:
    """Quem fez a requisição, reconferido no banco a cada chamada."""

    session_id: str
    user_id: str
    role: str
    device_id: str
    fingerprint: str
    scope: str

    @property
    def is_admin(self) -> bool:
        return self.role == ADMIN

    @property
    def is_full(self) -> bool:
        return self.scope == SCOPE_FULL


@dataclass(frozen=True)
class Actor:
    """Autor de uma operação administrativa: sessão pela API ou operador da CLI da VM."""

    user_id: str | None = None
    device_id: str | None = None
    local: bool = False

    @classmethod
    def operator(cls) -> Actor:
        return cls(local=True)

    @classmethod
    def of(cls, principal: Principal) -> Actor:
        return cls(principal.user_id, principal.device_id, False)


@dataclass
class IdentityContext:
    repo: Repository
    server_id: str
    verifier: SignatureVerifier
    projects: frozenset[str]
    settings: AuthSettings = field(default_factory=AuthSettings)
    clock: Clock = utcnow
    random: RandomSource = secrets.token_bytes

    def now(self) -> datetime:
        moment = self.clock()
        if moment.tzinfo is None:
            raise ValueError("relógio sem fuso")
        return moment

    def now_ts(self) -> str:
        return ts(self.now())

    def after(self, seconds: int) -> str:
        return ts(self.now() + timedelta(seconds=seconds))

    def new_id(self) -> str:
        return str(uuid.UUID(bytes=self.random(16), version=4))

    def audit(self, tx: Tx, event: str, *, actor: Actor | None = None,
              project: str | None = None, **fields: Any) -> None:
        if actor is not None and actor.local:
            fields["operator"] = True
        tx.insert_audit(at=self.now_ts(), event=event, project_id=project,
                        actor_user=actor.user_id if actor else None,
                        actor_device=actor.device_id if actor else None, fields=fields)

    def refuse(self, event: str, error: IdentityError, *, actor: Actor | None = None,
               project: str | None = None, **fields: Any) -> IdentityError:
        """Audita a recusa numa transação própria e devolve o erro para ``raise``."""
        with self.repo.write() as tx:
            self.audit(tx, event, actor=actor, project=project, reason=error.code, **fields)
        return error


def require_admin(tx: Tx, actor: Actor) -> None:
    """Operador local, ou admin ativo com dispositivo ativo (reconferido no banco)."""
    if actor.local:
        return
    user = tx.get_user(actor.user_id) if actor.user_id else None
    device = tx.get_device(actor.device_id) if actor.device_id else None
    if (user is None or device is None or device.user_id != user.id or not user.is_admin
            or user.status != "active" or device.status != "active"):
        raise IdentityError(P.FORBIDDEN, "operação exige admin")


def require_operator(actor: Actor, what: str) -> None:
    if not actor.local:
        raise IdentityError(P.FORBIDDEN, f"{what} só pela CLI do servidor")


def has_active_admin(tx: Tx) -> bool:
    """Existe admin ativo com pelo menos um dispositivo ativo (critério do último admin)."""
    return tx.count_admins_with_active_device() > 0
