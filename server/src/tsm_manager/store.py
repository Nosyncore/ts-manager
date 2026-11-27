"""Estado do Manager: arquivos em ``history/state``.

O Git é a fonte de verdade das revisões. Aqui ficam só registros que o Git não guarda:
resultados idempotentes por chave, auditoria e caches derivados (manifesto SHA-256 por
commit, commit materializado no shared). A interface passará a usar SQLite.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tsm_common.fsutil import atomic_write_json, read_json

_KEY_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, state_dir: Path) -> None:
        self.dir = state_dir
        self._audit_lock = threading.Lock()

    # ------------------------------------------------------------ idempotência

    @staticmethod
    def valid_key(key: str) -> bool:
        return bool(isinstance(key, str) and _KEY_RE.match(key))

    def _pub_path(self, key: str) -> Path:
        if not self.valid_key(key):
            raise ValueError(f"chave de idempotência inválida: {key!r}")
        return self.dir / "publications" / f"{key}.json"

    def get_result(self, key: str) -> dict[str, Any] | None:
        p = self._pub_path(key)
        return read_json(p) if p.is_file() else None

    def put_result(self, key: str, request_hash: str, result: dict[str, Any]) -> None:
        atomic_write_json(self._pub_path(key), {
            "request_hash": request_hash, "result": result, "at": now_iso(),
        })

    # ------------------------------------------------------------ auditoria

    def audit(self, event: str, **fields: Any) -> None:
        rec = {"at": now_iso(), "event": event, **fields}
        line = json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"
        self.dir.mkdir(parents=True, exist_ok=True)
        with self._audit_lock, open(self.dir / "audit.jsonl", "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    def read_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        p = self.dir / "audit.jsonl"
        if not p.is_file():
            return []
        lines = p.read_text(encoding="utf-8").splitlines()
        return [json.loads(x) for x in lines[-limit:] if x.strip()][::-1]

    # ------------------------------------------------------------ caches derivados

    def get_manifest(self, commit: str) -> dict[str, str] | None:
        p = self.dir / "manifests" / f"{commit}.json"
        return read_json(p) if p.is_file() else None

    def put_manifest(self, commit: str, files: dict[str, str]) -> None:
        atomic_write_json(self.dir / "manifests" / f"{commit}.json", files, fsync=False)

    def shared_commit(self) -> str | None:
        p = self.dir / "shared.json"
        return read_json(p).get("commit") if p.is_file() else None

    def set_shared_commit(self, commit: str) -> None:
        atomic_write_json(self.dir / "shared.json", {"commit": commit, "at": now_iso()})
