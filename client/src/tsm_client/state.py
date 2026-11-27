"""Estado local do Client por vínculo, fora de qualquer endpoint de sincronização.

Layout::

    <state_directory>/
      lock                         exclusão mútua entre init, publish e pull
      objects/ab/cdef…             conteúdo por SHA-256 (objects.py)
      manifests/<commit>.json      manifesto {caminho: sha256} de cada base
      bindings/<id>/state.json     base, publicação pendente, marcadores
      bindings/<id>/pulls/*.json   registro de cada pull (conteúdos anteriores)
      git-global.cfg               config global vazia para o git do Client
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tsm_client.objects import ObjectStore
from tsm_common.fsutil import LockTimeout, atomic_write_json, file_lock, read_json

STATE_FORMAT = 1


class StateError(RuntimeError):
    """Estado local ausente, corrompido ou ocupado por outra operação."""


@dataclass
class BindingState:
    binding_id: str
    base_commit: str
    base_revision: int  # revisão do último init/pull (a base pode estar à frente: publicação)
    pending_publish: dict[str, Any] | None = None
    markers: list[str] = field(default_factory=list)
    format: int = STATE_FORMAT

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Any) -> BindingState:
        if not isinstance(data, dict) or data.get("format") != STATE_FORMAT:
            raise StateError("state.json com formato desconhecido")
        try:
            return cls(
                binding_id=str(data["binding_id"]),
                base_commit=str(data["base_commit"]),
                base_revision=int(data["base_revision"]),
                pending_publish=data.get("pending_publish"),
                markers=[str(m) for m in data.get("markers", [])],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError(f"state.json inválido: {exc}") from exc


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class StateStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.objects = ObjectStore(root / "objects")

    def _binding_dir(self, binding_id: str) -> Path:
        return self.root / "bindings" / binding_id

    @property
    def git_global_config(self) -> Path:
        return self.root / "git-global.cfg"

    # ------------------------------------------------------------ vínculo

    def load(self, binding_id: str) -> BindingState | None:
        p = self._binding_dir(binding_id) / "state.json"
        if not p.is_file():
            return None
        try:
            data = read_json(p)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise StateError(f"{p}: estado corrompido ({exc}); não é seguro adivinhar") from exc
        st = BindingState.from_dict(data)
        if st.binding_id != binding_id:
            raise StateError(f"{p}: pertence a outro vínculo ({st.binding_id})")
        return st

    def save(self, st: BindingState) -> None:
        atomic_write_json(self._binding_dir(st.binding_id) / "state.json", st.to_dict())

    def initialized(self, binding_id: str) -> bool:
        return self.load(binding_id) is not None

    # ------------------------------------------------------------ manifestos

    def manifest(self, commit: str) -> dict[str, str]:
        p = self.root / "manifests" / f"{commit}.json"
        try:
            return read_json(p)
        except FileNotFoundError as exc:
            raise StateError(f"manifesto da base {commit[:12]} ausente no estado local") from exc

    def put_manifest(self, commit: str, files: dict[str, str]) -> None:
        atomic_write_json(self.root / "manifests" / f"{commit}.json", dict(sorted(files.items())))

    # ------------------------------------------------------------ pulls

    def record_pull(self, binding_id: str, record: dict[str, Any]) -> Path:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        p = self._binding_dir(binding_id) / "pulls" / f"{stamp}.json"
        atomic_write_json(p, record)
        return p

    def pulls(self, binding_id: str) -> list[Path]:
        d = self._binding_dir(binding_id) / "pulls"
        return sorted(d.glob("*.json")) if d.is_dir() else []

    # ------------------------------------------------------------ lock

    @contextlib.contextmanager
    def locked(self, timeout: float = 2.0) -> Iterator[None]:
        try:
            with file_lock(self.root / "lock", timeout=timeout):
                yield
        except LockTimeout as exc:
            raise StateError("outra operação do tsm (init/publish/pull) está em andamento"
                             ) from exc
