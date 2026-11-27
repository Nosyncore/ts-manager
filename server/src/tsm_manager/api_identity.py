"""Rotas de identidade (config ``version: 2``): ``/auth``, ``/me``, ``/connection``, ``/admin``.

- Autenticação só por ``Authorization: Bearer tsm-s-…``; a sessão, o dispositivo e o
  usuário são reconferidos no banco a cada requisição (``sessions.authenticate``).
- Autorização pela matriz de ``identity.authz``; nas rotas ``/admin`` o domínio reconfere
  o admin.
- Rate limit nas três rotas públicas de ``/auth`` (classe ``auth``); falha = qualquer recusa
  de cadastro ou de verificação. A chave é o endereço do par da conexão: nenhum cabeçalho é
  considerado (a API só escuta em loopback). As recusas são auditadas de forma agregada.
- Uma falha do helper depois de o banco já ter mudado (revogar, bloquear, desbloquear) não é
  erro HTTP: o estado já vale na API, e a resposta traz ``ssh: pending`` até o ``recover``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, NoReturn

from fastapi import APIRouter, Body, Header, Query, Request
from fastapi.responses import JSONResponse

from tsm_common import protocol as P
from tsm_common.authmsg import format_expires
from tsm_manager.config import BindingConfig
from tsm_manager.connection import connection_config
from tsm_manager.db import parse_ts
from tsm_manager.db.repository import Device, Invite, ProvisioningOp, User
from tsm_manager.identity import accounts, authz, challenges, invites, sessions
from tsm_manager.identity.authz import Operation
from tsm_manager.identity.base import Actor, IdentityError, Principal, unauthorized
from tsm_manager.identity.ratelimit import RateLimiter, RefusalAudit
from tsm_manager.project import ProjectService, Requester
from tsm_manager.provisioning.service import OpResult

if TYPE_CHECKING:
    from tsm_manager.services import IdentityServices, Manager

IDENTITY_PREFIXES = ("/auth", "/me", "/connection", "/admin")
AUTH_CLASS = "auth"
_BEARER = "Bearer "


class RateLimited(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("rate limited")
        self.retry_after = max(1, int(retry_after))


def invalid(message: str) -> NoReturn:
    raise IdentityError(P.INVALID_REQUEST, message)


def _body(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        invalid("corpo JSON (objeto) esperado")
    return body


def _text(body: dict[str, Any], key: str, *, required: bool = True) -> str | None:
    value = body.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        invalid(f"campo {key!r}: texto esperado")
    return value


def client_ip(request: Request) -> str:
    """Endereço do par da conexão; cabeçalhos de proxy não são considerados."""
    return request.client.host if request.client and request.client.host else "unknown"


def _expires(db_ts: str | None) -> str | None:
    return format_expires(parse_ts(db_ts).replace(microsecond=0)) if db_ts else None


# ---------------------------------------------------------------- serialização


def user_view(u: User) -> dict[str, Any]:
    return {"id": u.id, "display_name": u.display_name, "role": u.role, "status": u.status,
            "created_at": u.created_at}


def device_view(d: Device) -> dict[str, Any]:
    return {"id": d.id, "user_id": d.user_id, "name": d.name, "fingerprint": d.fingerprint,
            "status": d.status, "ssh_account": d.ssh_account, "created_at": d.created_at,
            "decided_at": d.decided_at, "last_error": d.last_error,
            "last_seen_at": d.last_seen_at}


def invite_view(i: Invite, state: str) -> dict[str, Any]:
    return {"id": i.id, "kind": i.kind, "role": i.role, "project_id": i.project_id,
            "user_id": i.user_id, "created_by": i.created_by, "created_at": i.created_at,
            "expires_at": i.expires_at, "used_at": i.used_at, "revoked_at": i.revoked_at,
            "state": state}


def op_view(op: ProvisioningOp) -> dict[str, Any]:
    return {"id": op.id, "action": op.action, "status": op.status, "error": op.error,
            "created_at": op.created_at}


def result_view(r: OpResult) -> dict[str, Any]:
    return {"device_id": r.device_id, "op": r.op_id, "action": r.action, "ssh": r.status,
            "error": r.error}


# ---------------------------------------------------------------- portão das rotas de projeto


class SessionGate:
    """Autenticação e autorização das rotas (de projeto e de identidade) por sessão."""

    def __init__(self, manager: Manager) -> None:
        assert manager.identity is not None
        self.manager = manager
        self.identity: IdentityServices = manager.identity

    def principal(self, authorization: str | None) -> Principal:
        if not authorization or not authorization.startswith(_BEARER):
            raise unauthorized()
        return sessions.authenticate(self.identity.ctx, authorization[len(_BEARER):].strip())

    def requester(self, principal: Principal) -> Requester:
        with self.identity.repo.read() as tx:
            user = tx.get_user(principal.user_id)
        name = user.display_name if user else principal.user_id
        return Requester(name, principal.user_id, principal.device_id, principal.is_admin)

    def _readable(self, authorization: str | None, project_id: str
                  ) -> tuple[ProjectService, Principal, authz.Access]:
        principal = self.principal(authorization)
        if not principal.is_full:
            authz.require(principal, Operation.PROJECT_READ)
        svc = self.manager.projects.get(project_id)
        if svc is None:
            raise IdentityError(P.NOT_FOUND, "projeto não encontrado")
        access = authz.project_access(self.identity.ctx, principal, project_id)
        authz.require(principal, Operation.PROJECT_READ, member=access.member)
        if not svc.initialized:
            raise IdentityError(P.NOT_FOUND, "projeto não inicializado")
        return svc, principal, access

    def project(self, authorization: str | None, project_id: str
                ) -> tuple[ProjectService, Requester]:
        svc, principal, _ = self._readable(authorization, project_id)
        return svc, self.requester(principal)

    def owned_binding(self, authorization: str | None, project_id: str, binding_id: str
                      ) -> tuple[ProjectService, Requester, BindingConfig]:
        svc, principal, access = self._readable(authorization, project_id)
        binding = svc.bindings.get(binding_id)
        owns = (binding is not None and access.binding_id == binding.id
                and authz.owns(principal, binding.device))
        authz.require(principal, Operation.PUBLISH, member=access.member, owns_binding=owns)
        assert binding is not None
        return svc, self.requester(principal), binding

    def admin(self, authorization: str | None, project_id: str, _what: str
              ) -> tuple[ProjectService, Requester]:
        svc, principal, _ = self._readable(authorization, project_id)
        authz.require(principal, Operation.ADMIN)
        return svc, self.requester(principal)

    def admin_actor(self, authorization: str | None) -> Actor:
        principal = self.principal(authorization)
        authz.require(principal, Operation.ADMIN)
        return Actor.of(principal)


# ---------------------------------------------------------------- rotas


def refusal_writer(ids: IdentityServices) -> Callable[[str, str, int], None]:
    def write(ip: str, route_class: str, count: int) -> None:
        with ids.repo.write() as tx:
            ids.ctx.audit(tx, "rate_limited", ip=ip, route_class=route_class, count=count)
    return write


def identity_router(manager: Manager, gate: SessionGate, *,
                    limiter: RateLimiter | None = None,
                    refusals: RefusalAudit | None = None) -> APIRouter:
    ids = gate.identity
    ctx = ids.ctx
    limiter = limiter or RateLimiter()
    refusals = refusals or RefusalAudit(refusal_writer(ids))
    router = APIRouter()

    def guard(request: Request) -> str:
        ip = client_ip(request)
        verdict = limiter.check(ip, AUTH_CLASS)
        if not verdict.allowed:
            refusals.refused(ip, AUTH_CLASS)
            raise RateLimited(verdict.retry_after)
        return ip

    # ------------------------------------------------------------ /auth

    @router.post("/auth/challenge")
    def challenge(request: Request, body: Any = Body(None)):
        guard(request)
        data = _body(body)
        purpose = data.get("purpose")
        if purpose == challenges.REGISTER:
            issued = challenges.issue_register(ctx, _text(data, "public_key"))
        elif purpose == challenges.LOGIN:
            issued = challenges.issue_login(ctx, _text(data, "fingerprint"))
        else:
            invalid("purpose: use register ou login")
        return issued.to_response()

    @router.post("/auth/register")
    def register(request: Request, body: Any = Body(None)):
        ip = guard(request)
        try:
            data = _body(body)
            reg = accounts.register(
                ctx, invite_code=_text(data, "invite"),
                display_name=_text(data, "display_name", required=False),
                device_name=_text(data, "device_name"),
                challenge_id=_text(data, "challenge_id"), signature=_text(data, "signature"))
        except IdentityError:
            limiter.record_failure(ip)
            raise
        return JSONResponse({"user_id": reg.user_id, "device_id": reg.device_id,
                             "fingerprint": reg.fingerprint, "status": reg.status,
                             "project_id": reg.project_id}, status_code=201)

    @router.post("/auth/verify")
    def verify(request: Request, body: Any = Body(None)):
        ip = guard(request)
        try:
            data = _body(body)
            issued = sessions.login(ctx, _text(data, "challenge_id"),
                                    _text(data, "signature"))
        except IdentityError:
            limiter.record_failure(ip)
            raise
        return issued.to_response()

    @router.post("/auth/logout")
    def logout(authorization: str | None = Header(None)):
        principal = gate.principal(authorization)
        authz.require(principal, Operation.LOGOUT)
        sessions.logout(ctx, principal)
        return {"ok": True}

    # ------------------------------------------------------------ /me e /connection

    @router.get("/me")
    def me(authorization: str | None = Header(None)):
        principal = gate.principal(authorization)
        authz.require(principal, Operation.ME)
        with ids.repo.read() as tx:
            user = tx.get_user(principal.user_id)
            device = tx.get_device(principal.device_id)
            bindings = tx.list_bindings(device_id=principal.device_id) \
                if principal.is_full else []
        if user is None or device is None:  # removidos entre a autenticação e a leitura
            raise unauthorized()
        return {"server_id": ctx.server_id, "user": user_view(user),
                "device": device_view(device),
                "session": {"scope": principal.scope,
                            "expires_at": _expires(principal.expires_at)},
                "bindings": [{"id": b.id, "project_id": b.project_id} for b in bindings]}

    @router.get("/connection/config")
    def connection(project: str | None = Query(None),
                   authorization: str | None = Header(None)):
        principal = gate.principal(authorization)
        if not principal.is_full:
            authz.require(principal, Operation.CONNECTION_CONFIG)
        if not project:
            invalid("parâmetro project obrigatório")
        project_cfg = manager.cfg.projects.get(project)
        if project_cfg is None:
            raise IdentityError(P.NOT_FOUND, "projeto não encontrado")
        access = authz.project_access(ctx, principal, project)
        authz.require(principal, Operation.CONNECTION_CONFIG, member=access.member,
                      owns_binding=access.binding_id is not None)
        with ids.repo.read() as tx:
            binding = tx.get_binding(access.binding_id or "")
            device = tx.get_device(principal.device_id)
        if binding is None or device is None or device.ssh_account is None:
            raise IdentityError(P.NOT_FOUND, "projeto não encontrado")
        return connection_config(
            server_id=ctx.server_id, project=project_cfg,
            layout=manager.projects[project].layout, binding=binding, device=device,
            ssh=manager.cfg.ssh, host_keys=ids.host_keys,
            workspace_group=manager.cfg.workspace_group or "", transport=ids.transport)

    # ------------------------------------------------------------ /admin

    @router.post("/admin/invites")
    def create_invite(body: Any = Body(None), authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        data = _body(body)
        kind = data.get("kind", invites.NEW_USER)
        role = data.get("role", "developer")
        ttl = data.get("ttl_s")
        if not isinstance(kind, str) or not isinstance(role, str):
            invalid("kind e role: texto esperado")
        created = invites.create(ctx, actor, project_id=_text(data, "project"), kind=kind,
                                 role=role, for_user=_text(data, "user_id", required=False),
                                 ttl_s=ttl)
        view = invite_view(created.invite, invites.OPEN)
        return JSONResponse({**view, "code": created.code}, status_code=201)

    @router.get("/admin/invites")
    def list_invites(authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        return {"invites": [invite_view(i, st) for i, st in invites.list_invites(ctx, actor)]}

    @router.post("/admin/invites/{invite_id}/revoke")
    def revoke_invite(invite_id: str, authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        invite = invites.revoke(ctx, actor, invite_id)
        return invite_view(invite, invites.state(invite, ctx.now_ts()))

    @router.get("/admin/requests")
    def list_requests(authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        return {"requests": [
            {"device": device_view(r.device), "user": user_view(r.user),
             "invite": {"id": r.invite.id, "kind": r.invite.kind,
                        "project_id": r.invite.project_id}}
            for r in accounts.list_requests(ctx, actor)]}

    @router.post("/admin/requests/{device_id}/approve")
    def approve(device_id: str, body: Any = Body(None),
                authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        fingerprint = _text(_body(body), "fingerprint")
        binding = ids.provisioning.approve(actor, device_id, fingerprint)
        with ids.repo.read() as tx:
            device = tx.get_device(device_id)
        return {"device": device_view(device) if device else None,
                "binding": {"id": binding.id, "project_id": binding.project_id,
                            "workspace": binding.workspace}}

    @router.post("/admin/requests/{device_id}/reject")
    def reject(device_id: str, authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        return {"device": device_view(accounts.reject(ctx, actor, device_id))}

    @router.get("/admin/devices")
    def list_devices(authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        return {"devices": [
            {**device_view(v.device), "user": user_view(v.user),
             "pending_ops": [op_view(op) for op in v.pending_ops],
             "ssh_revocation_pending": any(op.action == "disable" for op in v.pending_ops)}
            for v in accounts.list_devices(ctx, actor)]}

    @router.post("/admin/devices/{device_id}/revoke")
    def revoke_device(device_id: str, authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        result = ids.provisioning.revoke(actor, device_id)
        return {"device_id": device_id, "status": "revoked", **result_view(result)}

    @router.get("/admin/users")
    def list_users(authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        return {"users": [user_view(u) for u in accounts.list_users(ctx, actor)]}

    @router.post("/admin/users/{user_id}/block")
    def block(user_id: str, authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        results = ids.provisioning.block(actor, user_id)
        return {"user_id": user_id, "status": "blocked",
                "devices": [result_view(r) for r in results]}

    @router.post("/admin/users/{user_id}/unblock")
    def unblock(user_id: str, authorization: str | None = Header(None)):
        actor = gate.admin_actor(authorization)
        results = ids.provisioning.unblock(actor, user_id)
        return {"user_id": user_id, "status": "active",
                "devices": [result_view(r) for r in results]}

    return router
