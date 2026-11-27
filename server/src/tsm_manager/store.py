"""Estado do Manager no banco, com escopo por projeto.

O Git é a fonte de verdade das revisões. Aqui ficam só registros que o Git não guarda:
resultados idempotentes por chave, auditoria (só INSERT) e caches derivados (manifesto
SHA-256 por commit, commit materializado no shared). O diário das operações de Git não
está aqui: continua em arquivo, porque precisa existir antes do ``update-ref`` e a
recuperação não deve depender do banco.

Cada método é uma transação própria.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from tsm_manager.db.connection import Database, ts, utcnow

_KEY_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
_ACTOR_FIELDS = ("user", "device")


def now_iso() -> str:
    return ts(utcnow())


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Store:
    def __init__(self, db: Database, project_id: str, *,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self.db = db
        self.project_id = project_id
        self._clock = clock

    def _now(self) -> str:
        return ts(self._clock())

    # ------------------------------------------------------------ idempotência

    @staticmethod
    def valid_key(key: str) -> bool:
        return bool(isinstance(key, str) and _KEY_RE.match(key))

    @classmethod
    def _check_key(cls, key: str) -> None:
        if not cls.valid_key(key):
            raise ValueError(f"chave de idempotência inválida: {key!r}")

    def get_result(self, key: str) -> dict[str, Any] | None:
        self._check_key(key)
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT request_hash, result, at FROM publications "
                "WHERE project_id = ? AND idempotency_key = ?", (self.project_id, key),
            ).fetchone()
        if row is None:
            return None
        return {"request_hash": row["request_hash"], "result": json.loads(row["result"]),
                "at": row["at"]}

    def put_result(self, key: str, request_hash: str, result: dict[str, Any]) -> None:
        """Grava ou substitui: a recuperação pode concluir de novo a mesma operação."""
        self._check_key(key)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO publications (project_id, idempotency_key, request_hash, result, "
                "at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (project_id, idempotency_key) DO "
                "UPDATE SET request_hash = excluded.request_hash, result = excluded.result, "
                "at = excluded.at",
                (self.project_id, key, request_hash, _dump(result), self._now()))

    # ------------------------------------------------------------ auditoria

    def audit(self, event: str, **fields: Any) -> None:
        user, device = (fields.pop(k, None) for k in _ACTOR_FIELDS)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO audit_logs (at, event, project_id, actor_user, actor_device, "
                "fields) VALUES (?, ?, ?, ?, ?, ?)",
                (self._now(), event, self.project_id, user, device, _dump(fields)))

    def read_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        """Eventos do projeto, do mais recente para o mais antigo."""
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT at, event, actor_user, actor_device, fields FROM audit_logs "
                "WHERE project_id = ? ORDER BY id DESC LIMIT ?", (self.project_id, limit),
            ).fetchall()
        out = []
        for r in rows:
            rec: dict[str, Any] = {"at": r["at"], "event": r["event"]}
            rec.update(json.loads(r["fields"]))
            if r["actor_user"] is not None:
                rec["user"] = r["actor_user"]
            if r["actor_device"] is not None:
                rec["device"] = r["actor_device"]
            out.append(rec)
        return out

    # ------------------------------------------------------------ caches derivados

    def get_manifest(self, commit: str) -> dict[str, str] | None:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT files FROM revision_manifests WHERE project_id = ? AND commit_id = ?",
                (self.project_id, commit)).fetchone()
        return None if row is None else json.loads(row["files"])

    def put_manifest(self, commit: str, files: dict[str, str]) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO revision_manifests (project_id, commit_id, files) VALUES (?, ?, ?) "
                "ON CONFLICT (project_id, commit_id) DO UPDATE SET files = excluded.files",
                (self.project_id, commit, _dump(files)))

    def shared_commit(self) -> str | None:
        with self.db.read() as conn:
            row = conn.execute("SELECT commit_id FROM shared_state WHERE project_id = ?",
                               (self.project_id,)).fetchone()
        return None if row is None else str(row["commit_id"])

    def set_shared_commit(self, commit: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO shared_state (project_id, commit_id, at) VALUES (?, ?, ?) "
                "ON CONFLICT (project_id) DO UPDATE SET commit_id = excluded.commit_id, "
                "at = excluded.at", (self.project_id, commit, self._now()))
