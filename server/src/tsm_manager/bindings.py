"""Fonte dos vínculos de um projeto (dispositivo ↔ workspace).

O ``ProjectService`` e a API consultam os vínculos só por esta interface. ``DbBindings`` lê
``workspace_bindings`` (vínculos criados na aprovação de dispositivos). A fonte também diz
onde fica o diretório sincronizado de cada vínculo.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from tsm_manager.config import BindingConfig
from tsm_manager.db.repository import Binding, Repository
from tsm_manager.layout import ProjectLayout


class BindingSource(Protocol):
    def get(self, binding_id: str) -> BindingConfig | None:
        """Vínculo pelo id, ou ``None``."""
        ...

    def for_device(self, device: str) -> BindingConfig | None:
        """O vínculo do dispositivo neste projeto (no máximo um), ou ``None``."""
        ...

    def workspace_path(self, layout: ProjectLayout, binding: BindingConfig) -> Path:
        """Diretório sincronizado do vínculo, de onde a publicação copia os arquivos."""
        ...


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

    def workspace_path(self, layout: ProjectLayout, binding: BindingConfig) -> Path:
        """``workspaces/<conta>/tree``: o portão da conta guarda a raiz sincronizada."""
        return layout.sync_root(binding.workspace)
