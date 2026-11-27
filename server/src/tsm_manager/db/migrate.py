"""Migrations do banco: arquivos ``migrations/NNNN_nome.sql`` aplicados em ordem.

- ``schema_migrations`` registra versão, nome, SHA-256 do SQL e horário. Uma migration já
  aplicada cujo arquivo mudou é erro (o banco não corresponde mais ao código).
- Cada migration roda numa transação própria; erro → rollback e nada dela fica no banco.
- Antes de alterar um banco existente, uma cópia consistente (API de backup do SQLite) vai
  para o diretório de backups.
- Banco numa versão mais nova que a deste código é recusado: não há downgrade.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from pathlib import Path

from tsm_manager.db.connection import Database, ts, utcnow

_FILE_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
_TX_RE = re.compile(r"^\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b",
                    re.IGNORECASE | re.MULTILINE)

_BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL
) STRICT;
"""


class MigrationError(RuntimeError):
    """Banco incompatível com as migrations deste código."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SchemaStatus:
    current: int
    latest: int
    pending: tuple[Migration, ...] = field(default_factory=tuple)

    @property
    def up_to_date(self) -> bool:
        return not self.pending


def load_migrations(files: dict[str, str]) -> tuple[Migration, ...]:
    """Valida e ordena ``{nome do arquivo: SQL}``; versões contíguas a partir de 1."""
    found: list[Migration] = []
    for fname, sql in files.items():
        m = _FILE_RE.match(fname)
        if not m:
            raise MigrationError(f"nome de migration inválido: {fname}")
        if _TX_RE.search(sql):
            raise MigrationError(f"{fname}: controle de transação não é permitido na migration")
        found.append(Migration(int(m.group(1)), m.group(2), sql))
    found.sort(key=lambda mg: mg.version)
    for expected, mg in enumerate(found, start=1):
        if mg.version != expected:
            raise MigrationError(f"migrations fora de sequência: esperada {expected:04d}, "
                                 f"encontrada {mg.version:04d}")
    return tuple(found)


def packaged_migrations() -> tuple[Migration, ...]:
    root = resources.files("tsm_manager.db") / "migrations"
    files = {p.name: p.read_text(encoding="utf-8") for p in root.iterdir()
             if p.name.endswith(".sql")}
    return load_migrations(files)


def _applied(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' "
                          "AND name = 'schema_migrations'").fetchone()
    if not exists:
        return []
    return conn.execute("SELECT version, name, checksum FROM schema_migrations "
                        "ORDER BY version").fetchall()


def schema_status(db: Database, migrations: tuple[Migration, ...] | None = None
                  ) -> SchemaStatus:
    migrations = packaged_migrations() if migrations is None else migrations
    latest = len(migrations)
    with db.read() as conn:
        applied = _applied(conn)
    for expected, row in enumerate(applied, start=1):
        if row["version"] != expected:
            raise MigrationError(f"histórico de migrations com lacuna na versão {expected}")
        if row["version"] > latest:
            raise MigrationError(f"banco na versão {applied[-1]['version']}, mais nova que "
                                 f"este Manager (conhece até {latest}); não há downgrade")
        mg = migrations[row["version"] - 1]
        if row["checksum"] != mg.checksum or row["name"] != mg.name:
            raise MigrationError(f"migration {row['version']:04d} aplicada difere do arquivo "
                                 f"{mg.version:04d}_{mg.name}.sql")
    current = len(applied)
    return SchemaStatus(current, latest, migrations[current:])


def backup(db: Database, backup_dir: Path, label: str) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = backup_dir / f"manager-{label}.db"
    if target.exists():
        raise MigrationError(f"backup já existe: {target}")
    src = sqlite3.connect(db.path)
    try:
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    return target


def upgrade(db: Database, *, backup_dir: Path | None = None,
            migrations: tuple[Migration, ...] | None = None,
            clock: Callable[[], datetime] = utcnow,
            new_id: Callable[[], str] = lambda: str(uuid.uuid4())) -> list[int]:
    """Aplica as migrations pendentes; devolve as versões aplicadas."""
    migrations = packaged_migrations() if migrations is None else migrations
    with db.transaction() as conn:
        conn.execute(_BOOTSTRAP)
    status = schema_status(db, migrations)
    if status.up_to_date:
        _ensure_meta(db, clock, new_id)
        return []
    if status.current > 0 and backup_dir is not None:
        stamp = clock().strftime("%Y%m%dT%H%M%S")
        backup(db, backup_dir, f"v{status.current:04d}-{stamp}")
    applied: list[int] = []
    conn = db._connection()
    for mg in status.pending:
        script = (
            "BEGIN IMMEDIATE;\n" + mg.sql + "\n"
            f"INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES "
            f"({mg.version}, '{mg.name}', '{mg.checksum}', '{ts(clock())}');\n"
            "COMMIT;\n"
        )
        try:
            conn.executescript(script)
        except sqlite3.Error as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise MigrationError(f"migration {mg.version:04d}_{mg.name} falhou: {exc}") from exc
        applied.append(mg.version)
    _ensure_meta(db, clock, new_id)
    return applied


def _ensure_meta(db: Database, clock: Callable[[], datetime], new_id: Callable[[], str]
                 ) -> None:
    with db.transaction() as conn:
        has_meta = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' "
                                "AND name = 'meta'").fetchone()
        if not has_meta:
            return
        conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('server_id', ?)",
                     (new_id(),))
        conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('created_at', ?)",
                     (ts(clock()),))


def require_current(db: Database) -> SchemaStatus:
    """Para o ``serve``: recusa banco ausente, desatualizado ou incompatível."""
    if not db.path.is_file():
        raise MigrationError(f"banco não encontrado em {db.path}: rode tsm-manager migrate")
    status = schema_status(db)
    if not status.up_to_date:
        raise MigrationError(f"banco na versão {status.current}, esperada {status.latest}: "
                             "rode tsm-manager migrate")
    return status


def server_id(db: Database) -> str:
    with db.read() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key = 'server_id'").fetchone()
    if row is None:
        raise MigrationError("server_id ausente: rode tsm-manager migrate")
    return str(row["value"])
