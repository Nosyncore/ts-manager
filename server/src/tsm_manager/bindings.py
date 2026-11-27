"""Fonte dos vínculos de um projeto (dispositivo ↔ workspace).

O ``ProjectService`` e a API consultam os vínculos só por esta interface. ``ConfigBindings``
lê a config do Manager; ``DbBindings`` lê ``workspace_bindings`` (vínculos criados na
aprovação de dispositivos) e a substitui sem mudar quem consulta.
"""

from __future__ import annotations

from typing import Protocol

from tsm_manager.config import BindingConfig, ProjectConfig
from tsm_manager.db.repository import Binding, Repository


class BindingSource(Protocol):
    def get(self, binding_id: str) -> BindingConfig | None:
        """Vínculo pelo id, ou ``None``."""
        ...

    def for_device(self, device: str) -> BindingConfig | None:
        """O vínculo do dispositivo neste projeto (no máximo um), ou ``None``."""
        ...


class ConfigBindings:
    """Vínculos declarados em ``projects[].bindings`` da config."""

    def __init__(self, project: ProjectConfig) -> None:
        self._by_id = dict(project.bindings)

    def get(self, binding_id: str) -> BindingConfig | None:
        return self._by_id.get(binding_id)

    def for_device(self, device: str) -> BindingConfig | None:
        return next((b for b in self._by_id.values() if b.device == device), None)


def _config(binding: Binding | None) -> BindingConfig | None:
    if binding is None:
        return None
    return BindingConfig(binding.id, binding.device_id, binding.workspace)


class DbBindings:
    """Vínculos de um projeto no banco; ``device`` é o UUID do dispositivo."""

    def __init__(self, repo: Repository, project_id: str) -> None:
        self._repo = repo
        self.project_id = project_id

    def get(self, binding_id: str) -> BindingConfig | None:
        with self._repo.read() as tx:
            binding = tx.get_binding(binding_id)
        if binding is None or binding.project_id != self.project_id:
            return None
        return _config(binding)

    def for_device(self, device: str) -> BindingConfig | None:
        with self._repo.read() as tx:
            return _config(tx.binding_for(self.project_id, device))
