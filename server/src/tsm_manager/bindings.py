"""Fonte dos vínculos de um projeto (dispositivo ↔ workspace).

O ``ProjectService`` e a API consultam os vínculos só por esta interface. A implementação
atual lê a config do Manager; a que lê o banco a substitui sem mudar quem consulta.
"""

from __future__ import annotations

from typing import Protocol

from tsm_manager.config import BindingConfig, ProjectConfig


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
