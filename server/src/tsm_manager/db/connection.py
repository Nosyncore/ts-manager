"""Conexão com o banco do Manager (SQLite da stdlib).

- Uma conexão por thread (a API atende em threads); todas com WAL, chaves estrangeiras e
  ``busy_timeout``.
- Autocommit desligado no driver (``isolation_level=None``): as transações são explícitas.
  Escritas usam ``BEGIN IMMEDIATE``, que obtém o lock de escrita no início e evita o erro de
  upgrade de lock no meio da transação.
- Horários são texto UTC de largura fixa (``2026-11-26T12:00:00.000000Z``), comparáveis
  como texto no SQL.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_BUSY_TIMEOUT_MS = 10_000
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class DatabaseError(RuntimeError):
    """Falha de acesso ao banco do Manager."""


def ts(moment: datetime) -> str:
    """Horário → texto UTC de largura fixa."""
    if moment.tzinfo is None:
        raise ValueError("horário sem fuso")
    return moment.astimezone(UTC).strftime(_TS_FORMAT)


def parse_ts(text: str) -> datetime:
    return datetime.strptime(text, _TS_FORMAT).replace(tzinfo=UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


def _secure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)


def open_connection(path: Path, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS
                    ) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=busy_timeout_ms / 1000, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise DatabaseError(f"não foi possível ativar WAL em {path} (modo {mode})")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA foreign_keys = ON")
    except BaseException:
        conn.close()
        raise
    return conn


class Database:
    """Banco do Manager: conexões por thread e transações explícitas."""

    def __init__(self, path: str | os.PathLike[str], *,
                 busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> None:
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._all_lock = threading.Lock()
        self._closed = False

    def _connection(self) -> sqlite3.Connection:
        if self._closed:
            raise DatabaseError("banco fechado")
        conn = getattr(self._local, "conn", None)
        if conn is None:
            created = not self.path.exists()
            _secure_parent(self.path)
            conn = open_connection(self.path, busy_timeout_ms=self.busy_timeout_ms)
            if created and os.name == "posix":
                os.chmod(self.path, 0o600)
            self._local.conn = conn
            with self._all_lock:
                self._all.append(conn)
        return conn

    @contextlib.contextmanager
    def transaction(self, *, write: bool = True) -> Iterator[sqlite3.Connection]:
        """Transação; ``write=True`` usa ``BEGIN IMMEDIATE``. Erro → rollback."""
        conn = self._connection()
        if conn.in_transaction:
            raise DatabaseError("transação aninhada não é suportada")
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    def read(self) -> contextlib.AbstractContextManager[sqlite3.Connection]:
        return self.transaction(write=False)

    def close(self) -> None:
        self._closed = True
        with self._all_lock:
            for conn in self._all:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
            self._all.clear()
