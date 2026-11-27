"""Usuários e dispositivos: cadastro com convite, aprovação, revogação, bloqueio, roles.

Máquina de estados do dispositivo::

    pending ─► provisioning ─► active ─► revoked
       │  ◄──────┘ (falha)
       ├─► rejected
       └─► expired

``rejected``, ``revoked`` e ``expired`` são finais: a chave continua registrada e é
recusada em cadastros futuros. A aprovação só marca ``active`` depois do provisionamento
(``begin_approval`` → helper → ``complete_approval``/``fail_approval``); a revogação muda o
banco primeiro e registra a operação ``disable`` para o helper. O provisionamento em si é
de ``provisioning``; aqui ficam só as transições e as regras.

Último admin: bloquear, rebaixar ou revogar é recusado se levar de ≥ 1 para 0 os admins
ativos com dispositivo ativo. Só o operador da CLI do servidor pode revogar o último
dispositivo de admin (``allow_last_admin``), o que reabre o ``bootstrap-admin``.
"""

from __future__ import annotations

import contextlib
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass

from tsm_common import protocol as P
from tsm_common.authmsg import NAMESPACE
from tsm_manager.db.repository import Binding, Device, Invite, ProvisioningOp, Tx, User
from tsm_manager.identity import challenges, invites
from tsm_manager.identity.base import (
    ADMIN,
    DEVELOPER,
    Actor,
    IdentityContext,
    IdentityError,
    has_active_admin,
    require_admin,
    require_operator,
    unauthorized,
)

ACCOUNT_PREFIX = "tsm-d-"
MAX_NAME_CHARS = 64
_MAX_SIGNATURE_CHARS = 4096
_MAX_ERROR_CHARS = 1000


def validate_name(value: object, what: str = "nome") -> str:
    """1 a 64 caracteres, em NFC, sem controle nem formatação invisível."""
    if not isinstance(value, str):
        raise IdentityError(P.INVALID_REQUEST, f"{what} inválido")
    text = unicodedata.normalize("NFC", value).strip()
    if not 1 <= len(text) <= MAX_NAME_CHARS:
        raise IdentityError(P.INVALID_REQUEST, f"{what} deve ter de 1 a {MAX_NAME_CHARS} "
                            "caracteres")
    if any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in text):
        raise IdentityError(P.INVALID_REQUEST, f"{what} com caracteres de controle")
    return text


def ssh_account_for(device_id: str) -> str:
    return ACCOUNT_PREFIX + device_id.replace("-", "")[:12]


@contextlib.contextmanager
def _audited(ctx: IdentityContext, event: str, actor: Actor | None = None,
             **fields: object) -> Iterator[None]:
    """Toda recusa dentro do bloco é auditada (depois do rollback) e propagada."""
    try:
        yield
    except IdentityError as exc:
        raise ctx.refuse(event, exc, actor=actor, **fields) from None


def _would_leave_no_admin(tx: Tx, *, user: str | None = None,
                          device: str | None = None) -> bool:
    before = tx.count_admins_with_active_device()
    after = tx.count_admins_with_active_device(exclude_user=user, exclude_device=device)
    return before > 0 and after == 0


def _last_admin() -> IdentityError:
    return IdentityError(P.LAST_ADMIN, "a operação deixaria o Manager sem admin ativo")


def _invalid_state(message: str) -> IdentityError:
    return IdentityError(P.INVALID_STATE, message)


# ---------------------------------------------------------------- cadastro


@dataclass(frozen=True)
class Registration:
    user_id: str
    device_id: str
    fingerprint: str
    status: str
    project_id: str


def register(ctx: IdentityContext, *, invite_code: str, display_name: str | None,
             device_name: str, challenge_id: str, signature: str) -> Registration:
    """Cadastro com convite e prova de posse → dispositivo ``pending``."""
    device_name = validate_name(device_name, "nome do dispositivo")
    if display_name is not None:
        display_name = validate_name(display_name, "nome de exibição")
    challenge = challenges.claim(ctx, challenge_id, challenges.REGISTER)
    if (not isinstance(signature, str) or not signature
            or len(signature) > _MAX_SIGNATURE_CHARS or challenge.public_key is None
            or not ctx.verifier.verify(challenge.public_key, NAMESPACE,
                                       challenges.message_for(ctx, challenge), signature)):
        raise ctx.refuse("auth_refused", unauthorized(), step="signature",
                         purpose="register")
    with _audited(ctx, "register_refused", fingerprint=challenge.fingerprint), \
            ctx.repo.write() as tx:
        now = ctx.now_ts()
        invite = invites.take(tx, invite_code, now=now)
        if tx.device_by_fingerprint(challenge.fingerprint) is not None:
            raise IdentityError(P.KEY_IN_USE, "esta chave já está registrada")
        if invite.kind == invites.BOOTSTRAP and has_active_admin(tx):
            raise invites.invalid_invite()
        if invite.kind == invites.NEW_DEVICE:
            owner = tx.get_user(invite.user_id or "")
            if owner is None or owner.status != "active":
                raise invites.invalid_invite()
            user_id = owner.id
        else:
            if display_name is None:
                raise IdentityError(P.INVALID_REQUEST, "nome de exibição obrigatório")
            user_id = ctx.new_id()
            tx.insert_user(User(user_id, display_name, invite.role, "active", now, now))
        device = Device(id=ctx.new_id(), user_id=user_id, name=device_name,
                        public_key=challenge.public_key, fingerprint=challenge.fingerprint,
                        status="pending", ssh_account=None, invite_id=invite.id,
                        created_at=now)
        tx.insert_device(device)
        ctx.audit(tx, "device_registered", actor=Actor(user_id, device.id),
                  project=invite.project_id, invite=invite.id, kind=invite.kind,
                  fingerprint=device.fingerprint)
        return Registration(user_id, device.id, device.fingerprint, device.status,
                            invite.project_id)


# ---------------------------------------------------------------- aprovação


@dataclass(frozen=True)
class ApprovalTicket:
    op_id: int
    device_id: str
    ssh_account: str
    project_id: str
    public_key: str


def _device_for_decision(tx: Tx, actor: Actor, device_id: str) -> tuple[Device, Invite]:
    """Dispositivo e convite de origem; admin exigido, operador para o bootstrap."""
    require_admin(tx, actor)
    device = tx.get_device(device_id)
    if device is None:
        raise IdentityError(P.NOT_FOUND, "solicitação não encontrada")
    invite = tx.get_invite(device.invite_id)
    if invite is None:  # FK garante; defensivo
        raise _invalid_state("solicitação sem convite")
    if invite.kind == invites.BOOTSTRAP:
        require_operator(actor, "solicitação de bootstrap")
    return device, invite


def begin_approval(ctx: IdentityContext, actor: Actor, device_id: str, *,
                   fingerprint: str) -> ApprovalTicket:
    """``pending → provisioning``: confere o fingerprint e registra a operação ``create``."""
    with _audited(ctx, "approval_refused", actor, device=device_id), \
            ctx.repo.write() as tx:
        device, invite = _device_for_decision(tx, actor, device_id)
        if device.status != "pending":
            raise _invalid_state(f"dispositivo em {device.status}, não pending")
        if fingerprint != device.fingerprint:
            raise IdentityError(P.FINGERPRINT_MISMATCH,
                                "fingerprint diferente do da solicitação")
        if invite.kind == invites.BOOTSTRAP and has_active_admin(tx):
            raise _invalid_state("já existe admin ativo")
        owner = tx.get_user(device.user_id)
        if owner is None or owner.status != "active":
            raise _invalid_state("usuário bloqueado")
        account = ssh_account_for(device.id)
        tx.update_device(device.id, expect_status="pending", status="provisioning",
                         ssh_account=account, decided_by=actor.user_id, last_error=None)
        op_id = tx.insert_op(device.id, "create", now=ctx.now_ts())
        ctx.audit(tx, "approval_started", actor=actor, project=invite.project_id,
                  device=device.id, account=account, op=op_id)
        return ApprovalTicket(op_id, device.id, account, invite.project_id,
                              device.public_key)


def _provisioning_op(tx: Tx, device_id: str, op_id: object) -> tuple[Device, Invite]:
    device = tx.get_device(device_id)
    op = tx.get_op(op_id) if isinstance(op_id, int) else None
    if (device is None or device.status != "provisioning" or op is None
            or op.device_id != device_id or op.action != "create" or op.status != "pending"):
        raise _invalid_state("aprovação não está em andamento")
    invite = tx.get_invite(device.invite_id)
    if invite is None:
        raise _invalid_state("solicitação sem convite")
    return device, invite


def complete_approval(ctx: IdentityContext, device_id: str, op_id: int) -> Binding:
    """``provisioning → active`` com vínculo e operação concluída, numa transação."""
    with ctx.repo.write() as tx:
        device, invite = _provisioning_op(tx, device_id, op_id)
        now = ctx.now_ts()
        binding = tx.binding_for(invite.project_id, device.id)
        if binding is None:
            binding = Binding(id="b-" + ctx.random(10).hex(), project_id=invite.project_id,
                              device_id=device.id, workspace=device.ssh_account or "",
                              created_at=now)
            tx.insert_binding(binding)
        tx.update_device(device.id, expect_status="provisioning", status="active",
                         decided_at=now, last_error=None)
        tx.finish_op(op_id, status="done", now=now)
        ctx.audit(tx, "device_approved", actor=Actor(device.decided_by, None,
                                                     device.decided_by is None),
                  project=invite.project_id, device=device.id, binding=binding.id,
                  op=op_id)
        return binding


def fail_approval(ctx: IdentityContext, device_id: str, op_id: int, error: str) -> None:
    """``provisioning → pending`` com o erro; aprovar de novo é seguro."""
    message = str(error)[:_MAX_ERROR_CHARS]
    with ctx.repo.write() as tx:
        device, invite = _provisioning_op(tx, device_id, op_id)
        now = ctx.now_ts()
        tx.update_device(device.id, expect_status="provisioning", status="pending",
                         decided_by=None, last_error=message)
        tx.finish_op(op_id, status="failed", now=now, error=message)
        ctx.audit(tx, "approval_failed", project=invite.project_id, device=device.id,
                  op=op_id, error=message)


def reject(ctx: IdentityContext, actor: Actor, device_id: str) -> Device:
    with _audited(ctx, "reject_refused", actor, device=device_id), ctx.repo.write() as tx:
        device, invite = _device_for_decision(tx, actor, device_id)
        now = ctx.now_ts()
        if not tx.update_device(device.id, expect_status="pending", status="rejected",
                                decided_at=now, decided_by=actor.user_id):
            raise _invalid_state(f"dispositivo em {device.status}, não pending")
        tx.revoke_device_sessions(device.id, now=now)
        ctx.audit(tx, "request_rejected", actor=actor, project=invite.project_id,
                  device=device.id)
        return tx.get_device(device.id) or device


def expire_pending(ctx: IdentityContext) -> list[str]:
    """Solicitações ``pending`` mais antigas que ``pending_ttl_s`` → ``expired``."""
    cutoff = ctx.after(-ctx.settings.pending_ttl_s)
    expired = []
    with ctx.repo.write() as tx:
        now = ctx.now_ts()
        for device in tx.list_devices(status="pending"):
            if device.created_at <= cutoff and tx.update_device(
                    device.id, expect_status="pending", status="expired"):
                tx.revoke_device_sessions(device.id, now=now)
                ctx.audit(tx, "request_expired", device=device.id)
                expired.append(device.id)
    return expired


# ---------------------------------------------------------------- revogação


def revoke(ctx: IdentityContext, actor: Actor, device_id: str, *,
           allow_last_admin: bool = False) -> int:
    """``active → revoked``: sessões revogadas e operação ``disable`` registrada."""
    with _audited(ctx, "revoke_refused", actor, device=device_id), ctx.repo.write() as tx:
        if allow_last_admin:
            require_operator(actor, "revogar o último admin")
        require_admin(tx, actor)
        device = tx.get_device(device_id)
        if device is None:
            raise IdentityError(P.NOT_FOUND, "dispositivo não encontrado")
        if device.status != "active":
            raise _invalid_state(f"dispositivo em {device.status}, não active")
        if not allow_last_admin and _would_leave_no_admin(tx, device=device.id):
            raise _last_admin()
        now = ctx.now_ts()
        tx.update_device(device.id, expect_status="active", status="revoked")
        sessions_revoked = tx.revoke_device_sessions(device.id, now=now)
        op_id = tx.insert_op(device.id, "disable", now=now)
        extra = {"allow_last_admin": True} if allow_last_admin else {}
        ctx.audit(tx, "device_revoked", actor=actor, device=device.id, op=op_id,
                  sessions=sessions_revoked, **extra)
        return op_id


# ---------------------------------------------------------------- usuários


def _user(tx: Tx, user_id: str) -> User:
    user = tx.get_user(user_id)
    if user is None:
        raise IdentityError(P.NOT_FOUND, "usuário não encontrado")
    return user


def block_user(ctx: IdentityContext, actor: Actor, user_id: str) -> list[int]:
    """Bloqueia o usuário: sessões revogadas e ``disable`` dos dispositivos ativos."""
    with _audited(ctx, "block_refused", actor, target=user_id), ctx.repo.write() as tx:
        require_admin(tx, actor)
        user = _user(tx, user_id)
        if user.status != "active":
            raise _invalid_state("usuário já bloqueado")
        if _would_leave_no_admin(tx, user=user.id):
            raise _last_admin()
        now = ctx.now_ts()
        tx.update_user(user.id, now=now, status="blocked")
        ops = []
        for device in tx.list_devices(user_id=user.id):
            tx.revoke_device_sessions(device.id, now=now)
            if device.status == "active":
                ops.append(tx.insert_op(device.id, "disable", now=now))
        ctx.audit(tx, "user_blocked", actor=actor, target=user.id, ops=ops)
        return ops


def unblock_user(ctx: IdentityContext, actor: Actor, user_id: str) -> list[int]:
    """Desbloqueia: ``enable`` dos dispositivos ativos; revogados continuam revogados."""
    with _audited(ctx, "unblock_refused", actor, target=user_id), ctx.repo.write() as tx:
        require_admin(tx, actor)
        user = _user(tx, user_id)
        if user.status != "blocked":
            raise _invalid_state("usuário não está bloqueado")
        now = ctx.now_ts()
        tx.update_user(user.id, now=now, status="active")
        ops = [tx.insert_op(d.id, "enable", now=now)
               for d in tx.list_devices(user_id=user.id, status="active")]
        ctx.audit(tx, "user_unblocked", actor=actor, target=user.id, ops=ops)
        return ops


def promote(ctx: IdentityContext, actor: Actor, user_id: str) -> User:
    with _audited(ctx, "promote_refused", actor, target=user_id), ctx.repo.write() as tx:
        require_operator(actor, "promoção")
        user = _user(tx, user_id)
        if user.role == ADMIN:
            raise _invalid_state("usuário já é admin")
        tx.update_user(user.id, now=ctx.now_ts(), role=ADMIN)
        ctx.audit(tx, "user_promoted", actor=actor, target=user.id)
        return tx.get_user(user.id) or user


def demote(ctx: IdentityContext, actor: Actor, user_id: str) -> User:
    with _audited(ctx, "demote_refused", actor, target=user_id), ctx.repo.write() as tx:
        require_operator(actor, "rebaixamento")
        user = _user(tx, user_id)
        if user.role != ADMIN:
            raise _invalid_state("usuário não é admin")
        if _would_leave_no_admin(tx, user=user.id):
            raise _last_admin()
        tx.update_user(user.id, now=ctx.now_ts(), role=DEVELOPER)
        ctx.audit(tx, "user_demoted", actor=actor, target=user.id)
        return tx.get_user(user.id) or user


# ---------------------------------------------------------------- listagens


@dataclass(frozen=True)
class Request:
    device: Device
    user: User
    invite: Invite


@dataclass(frozen=True)
class DeviceView:
    device: Device
    user: User
    pending_ops: list[ProvisioningOp]


def list_requests(ctx: IdentityContext, actor: Actor, *,
                  include_bootstrap: bool = False) -> list[Request]:
    """Solicitações ``pending`` e em ``provisioning``; as de bootstrap só para o operador."""
    if include_bootstrap:
        require_operator(actor, "solicitações de bootstrap")
    with ctx.repo.read() as tx:
        require_admin(tx, actor)
        out = []
        for device in tx.list_devices(status=("pending", "provisioning")):
            invite = tx.get_invite(device.invite_id)
            user = tx.get_user(device.user_id)
            if invite is None or user is None:
                continue
            if invite.kind == invites.BOOTSTRAP and not include_bootstrap:
                continue
            out.append(Request(device, user, invite))
        return out


def list_devices(ctx: IdentityContext, actor: Actor) -> list[DeviceView]:
    with ctx.repo.read() as tx:
        require_admin(tx, actor)
        pending: dict[str, list[ProvisioningOp]] = {}
        for op in tx.pending_ops():
            pending.setdefault(op.device_id, []).append(op)
        users = {u.id: u for u in tx.list_users()}
        return [DeviceView(d, users[d.user_id], pending.get(d.id, []))
                for d in tx.list_devices()]


def list_users(ctx: IdentityContext, actor: Actor) -> list[User]:
    with ctx.repo.read() as tx:
        require_admin(tx, actor)
        return tx.list_users()
