"""Convites de cadastro.

- Código ``tsm-inv-`` + 26 caracteres base32 minúsculos (130 bits), mostrado uma única vez.
  O banco guarda só o SHA-256 da forma minúscula; a entrada é aceita sem distinção de caixa.
- Tipos: ``new_user`` (role ``developer`` ou ``admin``), ``new_device`` (usuário existente e
  ativo, com a role dele) e ``bootstrap`` (só pela CLI do servidor, sem admin ativo; um novo
  revoga os abertos). Um projeto por convite.
- Formato inválido, convite inexistente, usado, revogado ou expirado: o mesmo
  ``invalid_invite``.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

from tsm_common import protocol as P
from tsm_manager.db.repository import Invite, Tx
from tsm_manager.identity.base import (
    ADMIN,
    ROLES,
    Actor,
    IdentityContext,
    IdentityError,
    has_active_admin,
    require_admin,
    require_operator,
)

PREFIX = "tsm-inv-"
NEW_USER = "new_user"
NEW_DEVICE = "new_device"
BOOTSTRAP = "bootstrap"
_CODE_CHARS = 26
_CODE_RE = re.compile(rf"^{PREFIX}[a-z2-7]{{{_CODE_CHARS}}}$")

OPEN, USED, REVOKED, EXPIRED = "open", "used", "revoked", "expired"


def invalid_invite() -> IdentityError:
    return IdentityError(P.INVALID_INVITE, "convite inválido")


@dataclass(frozen=True)
class CreatedInvite:
    code: str      # só existe aqui; o banco guarda o hash
    invite: Invite


def code_hash(code: object) -> str | None:
    """SHA-256 do código normalizado, ou ``None`` se o formato for inválido."""
    if not isinstance(code, str):
        return None
    normalized = code.strip().lower()
    if not _CODE_RE.match(normalized):
        return None
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def state(invite: Invite, now: str) -> str:
    if invite.used_at is not None:
        return USED
    if invite.revoked_at is not None:
        return REVOKED
    if invite.expires_at <= now:
        return EXPIRED
    return OPEN


def _new_code(ctx: IdentityContext) -> str:
    symbols = base64.b32encode(ctx.random(17)).decode("ascii").lower()
    return PREFIX + symbols[:_CODE_CHARS]


def _ttl(ctx: IdentityContext, ttl_s: object) -> int:
    if ttl_s is None:
        return ctx.settings.invite_ttl_s
    if (not isinstance(ttl_s, int) or isinstance(ttl_s, bool) or ttl_s <= 0
            or ttl_s > ctx.settings.invite_ttl_max_s):
        raise IdentityError(P.INVALID_REQUEST, "validade do convite fora do permitido "
                            f"(1 a {ctx.settings.invite_ttl_max_s} s)")
    return ttl_s


def _check_project(ctx: IdentityContext, project_id: str) -> None:
    if project_id not in ctx.projects:
        raise IdentityError(P.INVALID_REQUEST, f"projeto desconhecido: {project_id!r}")


def _insert(ctx: IdentityContext, tx: Tx, actor: Actor, *, kind: str, role: str,
            project_id: str, user_id: str | None, ttl: int) -> CreatedInvite:
    code = _new_code(ctx)
    invite = Invite(id=ctx.new_id(), code_sha256=code_hash(code) or "", kind=kind, role=role,
                    project_id=project_id, user_id=user_id, created_by=actor.user_id,
                    created_at=ctx.now_ts(), expires_at=ctx.after(ttl))
    tx.insert_invite(invite)
    ctx.audit(tx, "invite_created", actor=actor, project=project_id, invite=invite.id,
              kind=kind, role=role, expires_at=invite.expires_at)
    return CreatedInvite(code, invite)


def create(ctx: IdentityContext, actor: Actor, *, project_id: str, kind: str = NEW_USER,
           role: str = "developer", for_user: str | None = None,
           ttl_s: int | None = None) -> CreatedInvite:
    """Convite ``new_user`` ou ``new_device`` criado por admin (ou pelo operador)."""
    if kind == BOOTSTRAP:
        raise IdentityError(P.FORBIDDEN, "convite de bootstrap só pela CLI do servidor")
    if kind not in (NEW_USER, NEW_DEVICE):
        raise IdentityError(P.INVALID_REQUEST, f"tipo de convite inválido: {kind!r}")
    _check_project(ctx, project_id)
    ttl = _ttl(ctx, ttl_s)
    with ctx.repo.write() as tx:
        require_admin(tx, actor)
        if kind == NEW_USER:
            if role not in ROLES:
                raise IdentityError(P.INVALID_REQUEST, f"role inválida: {role!r}")
            if for_user is not None:
                raise IdentityError(P.INVALID_REQUEST, "convite new_user não aponta usuário")
            user_id = None
        else:
            user = tx.get_user(for_user) if isinstance(for_user, str) else None
            if user is None or user.status != "active":
                raise IdentityError(P.INVALID_REQUEST, "new_device exige usuário ativo")
            role, user_id = user.role, user.id
        return _insert(ctx, tx, actor, kind=kind, role=role, project_id=project_id,
                       user_id=user_id, ttl=ttl)


def create_bootstrap(ctx: IdentityContext, actor: Actor, *, project_id: str,
                     ttl_s: int | None = None) -> CreatedInvite:
    """Convite do primeiro admin: só pelo operador e só sem admin ativo."""
    require_operator(actor, "bootstrap")
    _check_project(ctx, project_id)
    ttl = _ttl(ctx, ttl_s)
    with ctx.repo.write() as tx:
        if has_active_admin(tx):
            raise IdentityError(P.INVALID_STATE, "já existe admin ativo")
        tx.revoke_open_invites(BOOTSTRAP, now=ctx.now_ts())
        return _insert(ctx, tx, actor, kind=BOOTSTRAP, role=ADMIN, project_id=project_id,
                       user_id=None, ttl=ttl)


def take(tx: Tx, code: object, *, now: str) -> Invite:
    """Consome o convite aberto do código, dentro da transação de quem cadastra."""
    digest = code_hash(code)
    invite = tx.invite_by_code_hash(digest) if digest else None
    if invite is None or state(invite, now) != OPEN or not tx.consume_invite(invite.id,
                                                                            now=now):
        raise invalid_invite()
    return tx.get_invite(invite.id) or invite


def list_invites(ctx: IdentityContext, actor: Actor) -> list[tuple[Invite, str]]:
    now = ctx.now_ts()
    with ctx.repo.read() as tx:
        require_admin(tx, actor)
        return [(i, state(i, now)) for i in tx.list_invites()]


def revoke(ctx: IdentityContext, actor: Actor, invite_id: str) -> Invite:
    now = ctx.now_ts()
    with ctx.repo.write() as tx:
        require_admin(tx, actor)
        invite = tx.get_invite(invite_id)
        if invite is None:
            raise IdentityError(P.NOT_FOUND, "convite não encontrado")
        if invite.kind == BOOTSTRAP:
            require_operator(actor, "convite de bootstrap")
        if state(invite, now) != OPEN or not tx.revoke_invite(invite_id, now=now):
            raise IdentityError(P.INVALID_STATE, "convite não está aberto")
        ctx.audit(tx, "invite_revoked", actor=actor, project=invite.project_id,
                  invite=invite_id)
        return tx.get_invite(invite_id) or invite
