"""Layout de um projeto no servidor."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProjectLayout:
    root: Path
    project_id: str

    @property
    def project_dir(self) -> Path:
        return self.root / "projects" / self.project_id

    @property
    def workspaces(self) -> Path:
        return self.project_dir / "workspaces"

    def workspace(self, name: str) -> Path:
        return self.workspaces / name

    @property
    def shared(self) -> Path:
        return self.project_dir / "shared"

    @property
    def history(self) -> Path:
        return self.project_dir / "history"

    @property
    def repo(self) -> Path:
        return self.history / "repo.git"

    @property
    def git_global_config(self) -> Path:
        return self.history / "git-global.cfg"

    @property
    def staging(self) -> Path:
        return self.history / "staging"

    @property
    def tmp(self) -> Path:
        return self.history / "tmp"

    @property
    def journal(self) -> Path:
        return self.history / "journal"

    @property
    def state(self) -> Path:
        return self.history / "state"

    @property
    def lock(self) -> Path:
        return self.history / "lock"

    def ensure_history(self) -> None:
        for d in (self.history, self.staging, self.tmp, self.journal, self.state):
            d.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            self.history.chmod(0o700)
