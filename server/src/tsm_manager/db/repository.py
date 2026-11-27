"""Acesso SQL às entidades de identidade: a única camada que monta consultas.

O domínio abre uma transação (``Repository.write()`` ou ``read()``) e chama os métodos de
``Tx``. Os horários chegam prontos (texto de ``connection.ts``): o repositório não lê
relógio. Transições condicionais (consumir convite ou desafio, mudar o estado de um
dispositivo) devolvem ``True`` só se a linha estava no estado esperado, o que torna as
corridas entre requisições explícitas.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import astuple, dataclass, fields
from typing import Any

from tsm_manager.db.connection import Database


class RepositoryConflict(RuntimeError):
    """Violação de unicidade ou de integridade referencial."""


@dataclass(frozen=True)
class User:
    id: str
    display_name: str
    role: str
    status: str
    created_at: str
    updated_at: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


@dataclass(frozen=True)
class Device:
    id: str
    user_id: str
    name: str
    public_key: str
    fingerprint: str
    status: str
    ssh_account: str | None
    invite_id: str
    created_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    last_error: str | None = None
    last_seen_at: str | None = None


@dataclass(frozen=True)
class Invite:
    id: str
    code_sha256: str
    kind: str
    role: str
    project_id: str
    user_id: str | None
    created_by: str | None
    created_at: str
    expires_at: str
    used_at: str | None = None
    revoked_at: str | None = None


@dataclass(frozen=True)
class Challenge:
    id: str
    nonce: str
    purpose: str
    fingerprint: str
    public_key: str | None
    created_at: str
    expires_at: str
    used_at: str | None = None


@dataclass(frozen=True)
class Session:
    id: str
    token_sha256: str
    device_id: str
    scope: str
    created_at: str
    expires_at: str
    revoked_at: str | None = None


@dataclass(frozen=True)
class Binding:
    id: str
    project_id: str
    device_id: str
    workspace: str
    created_at: str


@dataclass(frozen=True)
class ProvisioningOp:
    id: int
    device_id: str
    action: str
    status: str
    error: str | None
    created_at: str
    finished_at: str | None



_DEVICE_UPDATABLE = {"status", "ssh_account", "decided_at", "decided_by", "last_error",
                     "last_seen_at"}
_USER_UPDATABLE = {"role", "status", "display_name"}


def _row[T](cls: type[T], row: sqlite3.Row | None) -> T | None:
    return None if row is None else cls(**dict(row))


def _rows[T](cls: type[T], rows: Iterable[sqlite3.Row]) -> list[T]:
    return [cls(**dict(r)) for r in rows]


def _insert(conn: sqlite3.Connection, table: str, obj: Any) -> None:
    cols = [f.name for f in fields(obj)]
    sql = (f"INSERT INTO {table} ({', '.join(cols)}) "
           f"VALUES ({', '.join('?' for _ in cols)})")
    try:
        conn.execute(sql, astuple(obj))
    except sqlite3.IntegrityError as exc:
        raise RepositoryConflict(f"{table}: {exc}") from exc


def _assignments(values: dict[str, Any], allowed: set[str]) -> tuple[str, list[Any]]:
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"campos não atualizáveis: {', '.join(sorted(unknown))}")
    if not values:
        raise ValueError("nenhum campo para atualizar")
    cols = sorted(values)
    return ", ".join(f"{c} = ?" for c in cols), [values[c] for c in cols]


class Tx:
    """Operações dentro de uma transação aberta."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # ------------------------------------------------------------ meta

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                          "ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, value))

    # ------------------------------------------------------------ usuários

    def insert_user(self, user: User) -> None:
        _insert(self.conn, "users", user)

    def get_user(self, user_id: str) -> User | None:
        return _row(User, self.conn.execute("SELECT * FROM users WHERE id = ?",
                                            (user_id,)).fetchone())

    def list_users(self) -> list[User]:
        return _rows(User, self.conn.execute("SELECT * FROM users ORDER BY created_at, id"))

    def update_user(self, user_id: str, *, now: str, **values: Any) -> bool:
        sets, params = _assignments(values, _USER_UPDATABLE)
        cur = self.conn.execute(f"UPDATE users SET {sets}, updated_at = ? WHERE id = ?",
                                [*params, now, user_id])
        return cur.rowcount == 1

    def count_admins_with_active_device(self, *, exclude_user: str | None = None,
                                        exclude_device: str | None = None) -> int:
        """Admins ativos com pelo menos um dispositivo ativo, descontando o que sairia."""
        row = self.conn.execute(
            "SELECT COUNT(DISTINCT u.id) AS n FROM users u JOIN devices d ON d.user_id = u.id "
            "WHERE u.role = 'admin' AND u.status = 'active' AND d.status = 'active' "
            "AND (? IS NULL OR u.id <> ?) AND (? IS NULL OR d.id <> ?)",
            (exclude_user, exclude_user, exclude_device, exclude_device)).fetchone()
        return int(row["n"])

    # ------------------------------------------------------------ dispositivos

    def insert_device(self, device: Device) -> None:
        _insert(self.conn, "devices", device)

    def get_device(self, device_id: str) -> Device | None:
        return _row(Device, self.conn.execute("SELECT * FROM devices WHERE id = ?",
                                              (device_id,)).fetchone())

    def device_by_fingerprint(self, fingerprint: str) -> Device | None:
        return _row(Device, self.conn.execute("SELECT * FROM devices WHERE fingerprint = ?",
                                              (fingerprint,)).fetchone())

    def list_devices(self, *, status: str | Iterable[str] | None = None,
                     user_id: str | None = None) -> list[Device]:
        where, params = [], []
        if status is not None:
            statuses = [status] if isinstance(status, str) else list(status)
            where.append(f"status IN ({', '.join('?' for _ in statuses)})")
            params += statuses
        if user_id is not None:
            where.append("user_id = ?")
            params.append(user_id)
        sql = "SELECT * FROM devices"
        if where:
            sql += " WHERE " + " AND ".join(where)
        return _rows(Device, self.conn.execute(sql + " ORDER BY created_at, id", params))

    def update_device(self, device_id: str, *, expect_status: str | Iterable[str] | None = None,
                      **values: Any) -> bool:
        """Atualiza campos; com ``expect_status``, só se o estado atual for um deles."""
        sets, params = _assignments(values, _DEVICE_UPDATABLE)
        sql = f"UPDATE devices SET {sets} WHERE id = ?"
        params.append(device_id)
        if expect_status is not None:
            statuses = [expect_status] if isinstance(expect_status, str) else list(expect_status)
            sql += f" AND status IN ({', '.join('?' for _ in statuses)})"
            params += statuses
        try:
            return self.conn.execute(sql, params).rowcount == 1
        except sqlite3.IntegrityError as exc:
            raise RepositoryConflict(f"devices: {exc}") from exc

    # ------------------------------------------------------------ convites

    def insert_invite(self, invite: Invite) -> None:
        _insert(self.conn, "invites", invite)

    def get_invite(self, invite_id: str) -> Invite | None:
        return _row(Invite, self.conn.execute("SELECT * FROM invites WHERE id = ?",
                                              (invite_id,)).fetchone())

    def invite_by_code_hash(self, code_sha256: str) -> Invite | None:
        return _row(Invite, self.conn.execute("SELECT * FROM invites WHERE code_sha256 = ?",
                                              (code_sha256,)).fetchone())

    def list_invites(self, *, kind: str | None = None) -> list[Invite]:
        if kind is None:
            return _rows(Invite, self.conn.execute(
                "SELECT * FROM invites ORDER BY created_at, id"))
        return _rows(Invite, self.conn.execute(
            "SELECT * FROM invites WHERE kind = ? ORDER BY created_at, id", (kind,)))

    def revoke_open_invites(self, kind: str, *, now: str) -> int:
        """Revoga os convites do tipo ainda abertos (sem uso, sem revogação, no prazo)."""
        return self.conn.execute(
            "UPDATE invites SET revoked_at = ? WHERE kind = ? AND used_at IS NULL "
            "AND revoked_at IS NULL AND expires_at > ?", (now, kind, now)).rowcount

    def consume_invite(self, invite_id: str, *, now: str) -> bool:
        cur = self.conn.execute(
            "UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL "
            "AND revoked_at IS NULL AND expires_at > ?", (now, invite_id, now))
        return cur.rowcount == 1

    def revoke_invite(self, invite_id: str, *, now: str) -> bool:
        cur = self.conn.execute("UPDATE invites SET revoked_at = ? WHERE id = ? "
                                "AND used_at IS NULL AND revoked_at IS NULL", (now, invite_id))
        return cur.rowcount == 1

    # ------------------------------------------------------------ desafios

    def insert_challenge(self, challenge: Challenge) -> None:
        _insert(self.conn, "auth_challenges", challenge)

    def get_challenge(self, challenge_id: str) -> Challenge | None:
        return _row(Challenge, self.conn.execute("SELECT * FROM auth_challenges WHERE id = ?",
                                                 (challenge_id,)).fetchone())

    def consume_challenge(self, challenge_id: str, *, now: str) -> bool:
        cur = self.conn.execute("UPDATE auth_challenges SET used_at = ? WHERE id = ? "
                                "AND used_at IS NULL AND expires_at > ?",
                                (now, challenge_id, now))
        return cur.rowcount == 1

    def purge_challenges(self, *, before: str) -> int:
        return self.conn.execute("DELETE FROM auth_challenges WHERE expires_at < ?",
                                 (before,)).rowcount

    # ------------------------------------------------------------ sessões

    def insert_session(self, session: Session) -> None:
        _insert(self.conn, "sessions", session)

    def session_by_token_hash(self, token_sha256: str) -> Session | None:
        return _row(Session, self.conn.execute("SELECT * FROM sessions WHERE token_sha256 = ?",
                                               (token_sha256,)).fetchone())

    def revoke_session(self, session_id: str, *, now: str) -> bool:
        cur = self.conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ? "
                                "AND revoked_at IS NULL", (now, session_id))
        return cur.rowcount == 1

    def revoke_device_sessions(self, device_id: str, *, now: str) -> int:
        return self.conn.execute("UPDATE sessions SET revoked_at = ? WHERE device_id = ? "
                                 "AND revoked_at IS NULL", (now, device_id)).rowcount

    def purge_sessions(self, *, before: str) -> int:
        return self.conn.execute("DELETE FROM sessions WHERE expires_at < ?",
                                 (before,)).rowcount

    # ------------------------------------------------------------ vínculos

    def insert_binding(self, binding: Binding) -> None:
        _insert(self.conn, "workspace_bindings", binding)

    def get_binding(self, binding_id: str) -> Binding | None:
        return _row(Binding, self.conn.execute("SELECT * FROM workspace_bindings WHERE id = ?",
                                               (binding_id,)).fetchone())

    def binding_for(self, project_id: str, device_id: str) -> Binding | None:
        return _row(Binding, self.conn.execute(
            "SELECT * FROM workspace_bindings WHERE project_id = ? AND device_id = ?",
            (project_id, device_id)).fetchone())

    def user_has_active_binding(self, user_id: str, project_id: str) -> bool:
        """O usuário tem vínculo no projeto por algum dispositivo ``active``."""
        row = self.conn.execute(
            "SELECT 1 FROM workspace_bindings b JOIN devices d ON d.id = b.device_id "
            "WHERE b.project_id = ? AND d.user_id = ? AND d.status = 'active' LIMIT 1",
            (project_id, user_id)).fetchone()
        return row is not None

    def list_bindings(self, *, project_id: str | None = None,
                      device_id: str | None = None) -> list[Binding]:
        where, params = [], []
        if project_id is not None:
            where.append("project_id = ?")
            params.append(project_id)
        if device_id is not None:
            where.append("device_id = ?")
            params.append(device_id)
        sql = "SELECT * FROM workspace_bindings"
        if where:
            sql += " WHERE " + " AND ".join(where)
        return _rows(Binding, self.conn.execute(sql + " ORDER BY created_at, id", params))

    # ------------------------------------------------------------ auditoria

    def insert_audit(self, *, at: str, event: str, project_id: str | None,
                     actor_user: str | None, actor_device: str | None,
                     fields: dict[str, Any]) -> None:
        """Evento de auditoria (só ``INSERT``; o banco recusa alteração e remoção)."""
        self.conn.execute(
            "INSERT INTO audit_logs (at, event, project_id, actor_user, actor_device, fields) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (at, event, project_id, actor_user, actor_device,
             json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))))

    # ------------------------------------------------------------ provisionamento

    def insert_op(self, device_id: str, action: str, *, now: str) -> int:
        try:
            cur = self.conn.execute(
                "INSERT INTO provisioning_ops (device_id, action, status, created_at) "
                "VALUES (?, ?, 'pending', ?)", (device_id, action, now))
        except sqlite3.IntegrityError as exc:
            raise RepositoryConflict(f"provisioning_ops: {exc}") from exc
        return int(cur.lastrowid)

    def finish_op(self, op_id: int, *, status: str, now: str, error: str | None = None) -> bool:
        if status not in ("done", "failed"):
            raise ValueError(f"status final inválido: {status}")
        cur = self.conn.execute("UPDATE provisioning_ops SET status = ?, error = ?, "
                                "finished_at = ? WHERE id = ? AND status = 'pending'",
                                (status, error, now, op_id))
        return cur.rowcount == 1

    def get_op(self, op_id: int) -> ProvisioningOp | None:
        return _row(ProvisioningOp, self.conn.execute(
            "SELECT * FROM provisioning_ops WHERE id = ?", (op_id,)).fetchone())

    def pending_ops(self) -> list[ProvisioningOp]:
        return _rows(ProvisioningOp, self.conn.execute(
            "SELECT * FROM provisioning_ops WHERE status = 'pending' ORDER BY id"))

    def ops_for_device(self, device_id: str) -> list[ProvisioningOp]:
        return _rows(ProvisioningOp, self.conn.execute(
            "SELECT * FROM provisioning_ops WHERE device_id = ? ORDER BY id", (device_id,)))


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @contextlib.contextmanager
    def write(self) -> Iterator[Tx]:
        with self.db.transaction() as conn:
            yield Tx(conn)

    @contextlib.contextmanager
    def read(self) -> Iterator[Tx]:
        with self.db.read() as conn:
            yield Tx(conn)
