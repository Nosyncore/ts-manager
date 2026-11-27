"""API HTTP do Manager (FastAPI). Rotas finas sobre ``ProjectService`` e o domínio.

Só escuta em loopback. O modo é fixado pela config ao abrir o Manager, nunca por requisição:

- ``version: 2``: sessão por challenge-response (``Authorization: Bearer tsm-s-…``),
  reconferida no banco a cada requisição; rotas ``/auth``, ``/me``, ``/connection`` e
  ``/admin``; vínculos do banco; autorização pela matriz de ``identity.authz``;
- ``version: 1``: identidade de teste por token fixo da config, só com as rotas de projeto
  (será removida). Nenhum token de teste é aceito na ``version: 2``.

Erros: corpo ``{status, message}`` com o código HTTP de ``tsm_common.protocol``.
"""

from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, Header, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from tsm_common import protocol as P
from tsm_manager import __version__
from tsm_manager.api_identity import (
    IDENTITY_PREFIXES,
    RateLimited,
    SessionGate,
    identity_router,
)
from tsm_manager.auth import authenticate, can_read, owns_binding
from tsm_manager.config import BindingConfig
from tsm_manager.identity.base import IdentityError
from tsm_manager.identity.ratelimit import RateLimiter, RefusalAudit
from tsm_manager.project import Outcome, ProjectService, Requester
from tsm_manager.services import Manager


def error_response(status: str, message: str) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if P.HTTP_STATUS[status] == 401 else None
    return JSONResponse({"status": status, "message": message},
                        status_code=P.HTTP_STATUS[status], headers=headers)


def _outcome(o: Outcome) -> JSONResponse:
    return JSONResponse(o.body(), status_code=o.http_status)


class LegacyGate:
    """Identidade de teste (config ``version: 1``): token fixo → identidade da config."""

    def __init__(self, manager: Manager) -> None:
        self.manager = manager

    def project(self, authorization: str | None, project_id: str
                ) -> tuple[ProjectService, Requester]:
        identity = authenticate(self.manager.cfg, authorization)
        if identity is None:
            raise IdentityError(P.UNAUTHORIZED, "token ausente ou inválido")
        svc = self.manager.projects.get(project_id)
        if svc is None or not can_read(identity, svc.bindings):
            raise IdentityError(P.NOT_FOUND, "projeto não encontrado")
        if not svc.initialized:
            raise IdentityError(P.NOT_FOUND, "projeto não inicializado")
        return svc, Requester.of(identity)

    def owned_binding(self, authorization: str | None, project_id: str, binding_id: str
                      ) -> tuple[ProjectService, Requester, BindingConfig]:
        svc, who = self.project(authorization, project_id)
        binding = svc.bindings.get(binding_id)
        identity = authenticate(self.manager.cfg, authorization)
        if binding is None or identity is None or not owns_binding(identity, binding):
            raise IdentityError(P.FORBIDDEN, "vínculo não pertence a este dispositivo")
        return svc, who, binding

    def admin(self, authorization: str | None, project_id: str, what: str
              ) -> tuple[ProjectService, Requester]:
        svc, who = self.project(authorization, project_id)
        if not who.is_admin and what == "audit":
            raise IdentityError(P.FORBIDDEN, "auditoria exige admin")
        return svc, who  # rollback: o ProjectService recusa quem não é admin


def create_app(manager: Manager, *, limiter: RateLimiter | None = None,
               refusals: RefusalAudit | None = None) -> FastAPI:
    app = FastAPI(title="TS Manager", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)
    identity = manager.identity
    gate: LegacyGate | SessionGate
    if identity is None:
        gate = LegacyGate(manager)
    else:
        gate = SessionGate(manager)
        app.include_router(identity_router(manager, gate, limiter=limiter,
                                           refusals=refusals))

    @app.exception_handler(IdentityError)
    def _identity_error(_request: Request, exc: IdentityError) -> JSONResponse:
        return error_response(exc.code, exc.message)

    @app.exception_handler(RateLimited)
    def _rate_limited(_request: Request, exc: RateLimited) -> JSONResponse:
        return JSONResponse({"status": P.RATE_LIMITED, "message": "muitas tentativas; aguarde"},
                            status_code=P.HTTP_STATUS[P.RATE_LIMITED],
                            headers={"Retry-After": str(exc.retry_after)})

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        if identity is not None and request.url.path.startswith(IDENTITY_PREFIXES):
            return error_response(P.INVALID_REQUEST, "requisição inválida")
        return await request_validation_exception_handler(request, exc)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "version": __version__, "server_id": manager.server_id}

    @app.get("/projects/{project_id}")
    def project_info(project_id: str, authorization: str | None = Header(None)):
        svc, _ = gate.project(authorization, project_id)
        return svc.info()

    @app.post("/projects/{project_id}/bindings/{binding_id}/publish")
    def publish(project_id: str, binding_id: str, body: Any = Body(None),
                authorization: str | None = Header(None)):
        svc, who, binding = gate.owned_binding(authorization, project_id, binding_id)
        return _outcome(svc.publish(who, binding, body))

    @app.get("/projects/{project_id}/revisions")
    def revisions(project_id: str, limit: int = Query(50, ge=1, le=1000),
                  authorization: str | None = Header(None)):
        svc, _ = gate.project(authorization, project_id)
        return {"revisions": svc.revisions(limit)}

    @app.get("/projects/{project_id}/revisions/{number}")
    def revision(project_id: str, number: int, authorization: str | None = Header(None)):
        svc, _ = gate.project(authorization, project_id)
        detail = svc.revision_detail(number)
        if detail is None:
            raise IdentityError(P.NOT_FOUND, f"r{number} não existe")
        return detail

    @app.post("/projects/{project_id}/rollback")
    def rollback(project_id: str, body: Any = Body(None),
                 authorization: str | None = Header(None)):
        svc, who = gate.admin(authorization, project_id, "rollback")
        return _outcome(svc.rollback(who, body))

    @app.get("/projects/{project_id}/audit")
    def audit(project_id: str, limit: int = Query(100, ge=1, le=10000),
              authorization: str | None = Header(None)):
        svc, _ = gate.admin(authorization, project_id, "audit")
        return {"events": svc.store.read_audit(limit)}

    return app

