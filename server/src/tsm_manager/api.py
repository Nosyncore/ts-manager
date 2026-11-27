"""API HTTP do Manager (FastAPI). Rotas finas sobre ``ProjectService``.

Por enquanto a API só escuta em loopback e usa a identidade de teste.
"""

from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, Header, Query
from fastapi.responses import JSONResponse

from tsm_common import protocol as P
from tsm_manager import __version__
from tsm_manager.auth import authenticate, can_read, owns_binding
from tsm_manager.config import Identity, ManagerConfig
from tsm_manager.faults import Faults
from tsm_manager.project import Outcome, ProjectService


def _error(status: str, message: str) -> JSONResponse:
    return JSONResponse({"status": status, "message": message},
                        status_code=P.HTTP_STATUS[status])


def _outcome(o: Outcome) -> JSONResponse:
    return JSONResponse(o.body(), status_code=o.http_status)


class Manager:
    """Serviços por projeto, construídos a partir da config."""

    def __init__(self, cfg: ManagerConfig, *, faults: Faults | None = None,
                 git_executable: str = "git") -> None:
        self.cfg = cfg
        faults = faults or Faults.from_env(cfg.test_faults)
        self.projects = {
            pid: ProjectService(cfg.root, p, shared_group=cfg.shared_group,
                                git_executable=git_executable, faults=faults)
            for pid, p in cfg.projects.items()
        }

    def recover_all(self) -> list[str]:
        notes = []
        for pid, svc in self.projects.items():
            if svc.initialized:
                notes += [f"{pid}: {n}" for n in svc.recover()]
        return notes


def create_app(manager: Manager) -> FastAPI:
    app = FastAPI(title="TS Manager", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)
    cfg = manager.cfg

    def ident(authorization: str | None) -> Identity | None:
        return authenticate(cfg, authorization)

    def project_for(identity: Identity | None, project_id: str
                    ) -> tuple[ProjectService | None, JSONResponse | None]:
        if identity is None:
            return None, _error(P.UNAUTHORIZED, "token ausente ou inválido")
        svc = manager.projects.get(project_id)
        if svc is None or not can_read(identity, svc.project):
            return None, _error(P.NOT_FOUND, "projeto não encontrado")
        if not svc.initialized:
            return None, _error(P.NOT_FOUND, "projeto não inicializado")
        return svc, None

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "version": __version__}

    @app.get("/projects/{project_id}")
    def project_info(project_id: str, authorization: str | None = Header(None)):
        svc, err = project_for(ident(authorization), project_id)
        return err or svc.info()

    @app.post("/projects/{project_id}/bindings/{binding_id}/publish")
    def publish(project_id: str, binding_id: str, body: Any = Body(None),
                authorization: str | None = Header(None)):
        identity = ident(authorization)
        svc, err = project_for(identity, project_id)
        if err:
            return err
        binding = svc.project.bindings.get(binding_id)
        if binding is None or not owns_binding(identity, binding):
            return _error(P.FORBIDDEN, "vínculo não pertence a este dispositivo")
        return _outcome(svc.publish(identity, binding, body))

    @app.get("/projects/{project_id}/revisions")
    def revisions(project_id: str, limit: int = Query(50, ge=1, le=1000),
                  authorization: str | None = Header(None)):
        svc, err = project_for(ident(authorization), project_id)
        return err or {"revisions": svc.revisions(limit)}

    @app.get("/projects/{project_id}/revisions/{number}")
    def revision(project_id: str, number: int, authorization: str | None = Header(None)):
        svc, err = project_for(ident(authorization), project_id)
        if err:
            return err
        detail = svc.revision_detail(number)
        return detail if detail is not None else _error(P.NOT_FOUND, f"r{number} não existe")

    @app.post("/projects/{project_id}/rollback")
    def rollback(project_id: str, body: Any = Body(None),
                 authorization: str | None = Header(None)):
        identity = ident(authorization)
        svc, err = project_for(identity, project_id)
        if err:
            return err
        return _outcome(svc.rollback(identity, body))

    @app.get("/projects/{project_id}/audit")
    def audit(project_id: str, limit: int = Query(100, ge=1, le=10000),
              authorization: str | None = Header(None)):
        identity = ident(authorization)
        svc, err = project_for(identity, project_id)
        if err:
            return err
        if not identity.is_admin:
            return _error(P.FORBIDDEN, "auditoria exige admin")
        return {"events": svc.store.read_audit(limit)}

    return app
