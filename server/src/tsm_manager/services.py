"""Montagem do Manager a partir da config: um banco e um ``ProjectService`` por projeto.

Não verifica o esquema: quem abre o Manager (``serve``, ``init-project``, ``recover``,
``verify``) chama ``db.require_current`` antes.
"""

from __future__ import annotations

from tsm_manager.config import ManagerConfig
from tsm_manager.db.connection import Database
from tsm_manager.faults import Faults
from tsm_manager.project import ProjectService, open_project


class Manager:
    def __init__(self, cfg: ManagerConfig, *, db: Database | None = None,
                 faults: Faults | None = None, git_executable: str = "git") -> None:
        self.cfg = cfg
        self.db = db or Database(cfg.database)
        faults = faults or Faults.from_env(cfg.test_faults)
        self.projects: dict[str, ProjectService] = {
            pid: open_project(cfg.root, p, self.db, shared_group=cfg.shared_group,
                              git_executable=git_executable, faults=faults)
            for pid, p in cfg.projects.items()
        }

    def recover_all(self) -> list[str]:
        notes = []
        for pid, svc in self.projects.items():
            if svc.initialized:
                notes += [f"{pid}: {n}" for n in svc.recover()]
        return notes

    def close(self) -> None:
        self.db.close()
