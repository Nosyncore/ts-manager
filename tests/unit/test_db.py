"""Banco do Manager: conexão, migrations e repositório (SQLite real em tmp_path)."""

from __future__ import annotations

import os
import sqlite3
import threading
from datetime import UTC, datetime, timedelta, timezone

import pytest

from tsm_manager.db import (
    Database,
    DatabaseError,
    MigrationError,
    Repository,
    RepositoryConflict,
    parse_ts,
    require_current,
    schema_status,
    server_id,
    ts,
    upgrade,
)
from tsm_manager.db.migrate import load_migrations, packaged_migrations
from tsm_manager.db.repository import (
    Binding,
    Challenge,
    Device,
    Invite,
    Session,
    User,
)

T0 = datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)


def at(seconds: float = 0) -> str:
    return ts(T0 + timedelta(seconds=seconds))


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "manager" / "manager.db")
    yield database
    database.close()


@pytest.fixture
def repo(db) -> Repository:
    upgrade(db, clock=lambda: T0, new_id=lambda: "server-1")
    return Repository(db)


def user(uid="u1", role="developer", status="active") -> User:
    return User(uid, f"Nome {uid}", role, status, at(), at())


def invite(iid="i1", kind="new_user", user_id=None, expires=3600, code=None) -> Invite:
    return Invite(iid, code or f"hash-{iid}", kind, "developer", "demo", user_id, None, at(),
                  at(expires))


def device(did="d1", uid="u1", iid="i1", status="pending", fp=None) -> Device:
    return Device(did, uid, f"pc {did}", "ssh-ed25519 AAAA", fp or f"SHA256:{did}", status,
                  None, iid, at())


def seed_device(tx, did="d1", uid="u1", iid="i1", role="developer", status="active",
                device_status="active"):
    if tx.get_user(uid) is None:
        tx.insert_user(user(uid, role, status))
    tx.insert_invite(invite(iid))
    tx.insert_device(device(did, uid, iid, device_status))


# ---------------------------------------------------------------- horários


def test_ts_roundtrip_and_fixed_width():
    later = T0 + timedelta(microseconds=5)
    assert parse_ts(ts(later)) == later
    assert len(ts(T0)) == len(ts(later)) == 27
    assert ts(T0) < ts(later)  # comparável como texto
    other_tz = T0.astimezone(timezone(timedelta(hours=-3)))
    assert ts(other_tz) == ts(T0)


def test_ts_rejects_naive():
    with pytest.raises(ValueError):
        ts(datetime(2026, 1, 1))


# ---------------------------------------------------------------- conexão


def test_connection_pragmas(db):
    with db.read() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == db.busy_timeout_ms


def test_transaction_commits_and_rolls_back(db):
    with db.transaction() as conn:
        conn.execute("CREATE TABLE t (x INTEGER)")
    with pytest.raises(RuntimeError), db.transaction() as conn:
        conn.execute("INSERT INTO t VALUES (1)")
        raise RuntimeError("falha")
    with db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0


def test_nested_transaction_refused(db):
    with db.transaction(), pytest.raises(DatabaseError), db.transaction():
        pass


def test_closed_database_refused(db):
    with db.read():
        pass
    db.close()
    with pytest.raises(DatabaseError):
        db.transaction().__enter__()


def test_connection_per_thread(db):
    with db.transaction() as conn:
        conn.execute("CREATE TABLE t (x INTEGER)")
    seen = []

    def work():
        with db.transaction() as c:
            c.execute("INSERT INTO t VALUES (1)")
            seen.append(id(c))

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(seen)) == 4
    with db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 4


@pytest.mark.skipif(os.name != "posix", reason="modos POSIX")
def test_posix_permissions(db):
    with db.read():
        pass
    assert (db.path.stat().st_mode & 0o777) == 0o600
    assert (db.path.parent.stat().st_mode & 0o777) == 0o700


# ---------------------------------------------------------------- migrations


def test_load_migrations_validates():
    with pytest.raises(MigrationError, match="nome"):
        load_migrations({"1_x.sql": ""})
    with pytest.raises(MigrationError, match="sequência"):
        load_migrations({"0001_a.sql": "", "0003_c.sql": ""})
    with pytest.raises(MigrationError, match="transação"):
        load_migrations({"0001_a.sql": "CREATE TABLE a (x);\nCOMMIT;"})
    migs = load_migrations({"0002_b.sql": "B", "0001_a.sql": "A"})
    assert [(m.version, m.name) for m in migs] == [(1, "a"), (2, "b")]


def test_packaged_migrations_load():
    migs = packaged_migrations()
    assert [m.name for m in migs] == ["identity", "state"]


def test_upgrade_fresh_database(db):
    assert upgrade(db, clock=lambda: T0, new_id=lambda: "server-1") == [1, 2]
    st = schema_status(db)
    assert st.up_to_date and st.current == st.latest == 2
    assert server_id(db) == "server-1"
    with db.read() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master "
                                             "WHERE type = 'table'")}
        strict = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'users'").fetchone()[0]
    assert {"users", "devices", "invites", "auth_challenges", "sessions",
            "workspace_bindings", "provisioning_ops", "publications", "audit_logs",
            "revision_manifests", "shared_state", "meta", "schema_migrations"} <= tables
    assert "STRICT" in strict


def test_upgrade_is_idempotent_and_keeps_server_id(db):
    upgrade(db, new_id=lambda: "server-1")
    assert upgrade(db, new_id=lambda: "server-2") == []
    assert server_id(db) == "server-1"


def test_upgrade_with_backup(db, tmp_path):
    migs = packaged_migrations()
    backups = tmp_path / "backups"
    assert upgrade(db, migrations=migs[:1], backup_dir=backups, clock=lambda: T0) == [1]
    assert not backups.exists()  # banco novo: nada a preservar
    assert schema_status(db, migs).pending == migs[1:]
    assert upgrade(db, migrations=migs, backup_dir=backups, clock=lambda: T0) == [2]
    copies = list(backups.iterdir())
    assert len(copies) == 1 and copies[0].name == "manager-v0001-20261126T120000.db"
    old = sqlite3.connect(copies[0])
    try:
        names = {r[0] for r in old.execute("SELECT name FROM sqlite_master")}
    finally:
        old.close()
    assert "users" in names and "publications" not in names
    with pytest.raises(MigrationError, match="já existe"):
        from tsm_manager.db.migrate import backup
        backup(db, backups, "v0001-20261126T120000")


def test_failed_migration_rolls_back(db):
    migs = load_migrations({
        "0001_a.sql": "CREATE TABLE a (x INTEGER) STRICT;",
        "0002_b.sql": "CREATE TABLE b (x INTEGER) STRICT;\nCREATE TABLE a (x INTEGER);",
    })
    with pytest.raises(MigrationError, match="0002_b"):
        upgrade(db, migrations=migs)
    st = schema_status(db, migs)
    assert st.current == 1
    with db.transaction() as conn:  # nenhuma transação ficou aberta pela falha
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'b'").fetchone() is None


def test_changed_migration_detected(db):
    upgrade(db, migrations=load_migrations({"0001_a.sql": "CREATE TABLE a (x INTEGER);"}))
    edited = load_migrations({"0001_a.sql": "CREATE TABLE a (x TEXT);"})
    with pytest.raises(MigrationError, match="difere"):
        schema_status(db, edited)


def test_newer_database_refused(db):
    migs = load_migrations({"0001_a.sql": "CREATE TABLE a (x INTEGER);",
                            "0002_b.sql": "CREATE TABLE b (x INTEGER);"})
    upgrade(db, migrations=migs)
    with pytest.raises(MigrationError, match="downgrade"):
        schema_status(db, migs[:1])


def test_gap_in_history_detected(db):
    migs = load_migrations({"0001_a.sql": "CREATE TABLE a (x INTEGER);",
                            "0002_b.sql": "CREATE TABLE b (x INTEGER);"})
    upgrade(db, migrations=migs)
    with db.transaction() as conn:
        conn.execute("DELETE FROM schema_migrations WHERE version = 1")
    with pytest.raises(MigrationError, match="lacuna"):
        schema_status(db, migs)


def test_require_current(tmp_path):
    missing = Database(tmp_path / "x" / "manager.db")
    with pytest.raises(MigrationError, match="não encontrado"):
        require_current(missing)
    assert not missing.path.exists()  # a checagem não cria o arquivo
    partial = Database(tmp_path / "p.db")
    upgrade(partial, migrations=packaged_migrations()[:1])
    with pytest.raises(MigrationError, match="migrate"):
        require_current(partial)
    upgrade(partial)
    assert require_current(partial).up_to_date
    partial.close()
    missing.close()


def test_server_id_missing(db):
    upgrade(db, migrations=load_migrations({"0001_a.sql": "CREATE TABLE meta "
                                            "(key TEXT PRIMARY KEY, value TEXT NOT NULL);"}),
            new_id=lambda: "s")
    with db.transaction() as conn:
        conn.execute("DELETE FROM meta")
    with pytest.raises(MigrationError, match="server_id"):
        server_id(db)


# ---------------------------------------------------------------- repositório


def test_meta(repo):
    with repo.write() as tx:
        assert tx.get_meta("server_id") == "server-1"
        assert tx.get_meta("nada") is None
        tx.set_meta("k", "1")
        tx.set_meta("k", "2")
    with repo.read() as tx:
        assert tx.get_meta("k") == "2"


def test_users(repo):
    with repo.write() as tx:
        tx.insert_user(user("u1"))
        tx.insert_user(user("u2", role="admin"))
        with pytest.raises(RepositoryConflict):
            tx.insert_user(user("u1"))
        assert tx.update_user("u1", now=at(5), status="blocked")
        assert not tx.update_user("nada", now=at(5), status="blocked")
        with pytest.raises(ValueError, match="não atualizáveis"):
            tx.update_user("u1", now=at(5), id="x")
        with pytest.raises(ValueError, match="nenhum"):
            tx.update_user("u1", now=at(5))
    with repo.read() as tx:
        u1 = tx.get_user("u1")
        assert u1.status == "blocked" and u1.updated_at == at(5)
        assert tx.get_user("u2").is_admin and not u1.is_admin
        assert [u.id for u in tx.list_users()] == ["u1", "u2"]
        assert tx.get_user("nada") is None


def test_check_constraints(repo):
    with repo.write() as tx:
        with pytest.raises(RepositoryConflict):
            tx.insert_user(user("x", role="root"))
        with pytest.raises(RepositoryConflict):  # new_device exige usuário
            tx.insert_invite(invite("i9", kind="new_device"))
        with pytest.raises(RepositoryConflict):  # chave estrangeira
            tx.insert_device(device("d9", uid="ninguem", iid="i9"))


def test_count_admins_with_active_device(repo):
    with repo.write() as tx:
        seed_device(tx, "d1", "a1", "i1", role="admin")
        seed_device(tx, "d2", "a2", "i2", role="admin", device_status="pending")
        seed_device(tx, "d3", "u3", "i3")
        assert tx.count_admins_with_active_device() == 1
        assert tx.count_admins_with_active_device(exclude_user="a1") == 0
        assert tx.count_admins_with_active_device(exclude_device="d1") == 0
        assert tx.count_admins_with_active_device(exclude_user="a2") == 1
        tx.update_device("d2", status="active")
        assert tx.count_admins_with_active_device(exclude_device="d1") == 1
        tx.update_user("a2", now=at(), status="blocked")
        assert tx.count_admins_with_active_device(exclude_device="d1") == 0


def test_devices(repo):
    with repo.write() as tx:
        seed_device(tx, "d1", device_status="pending")
        tx.insert_invite(invite("i2"))
        with pytest.raises(RepositoryConflict):  # fingerprint único
            tx.insert_device(device("d2", iid="i2", fp="SHA256:d1"))
        tx.insert_device(device("d2", iid="i2"))
        assert tx.update_device("d1", expect_status="pending", status="provisioning",
                                ssh_account="tsm-d-aaaaaaaaaaaa")
        assert not tx.update_device("d1", expect_status="pending", status="active")
        with pytest.raises(RepositoryConflict):  # conta SSH única
            tx.update_device("d2", ssh_account="tsm-d-aaaaaaaaaaaa")
        with pytest.raises(ValueError):
            tx.update_device("d1", fingerprint="SHA256:x")
        assert tx.update_device("d1", expect_status=["provisioning", "pending"],
                                status="active", decided_at=at(9), decided_by="u1")
    with repo.read() as tx:
        d1 = tx.get_device("d1")
        assert (d1.status, d1.decided_at, d1.ssh_account) == ("active", at(9),
                                                              "tsm-d-aaaaaaaaaaaa")
        assert tx.device_by_fingerprint("SHA256:d2").id == "d2"
        assert tx.device_by_fingerprint("SHA256:x") is None
        assert [d.id for d in tx.list_devices(status="pending")] == ["d2"]
        assert [d.id for d in tx.list_devices(status=["active", "pending"], user_id="u1")] \
            == ["d1", "d2"]
        assert [d.id for d in tx.list_devices()] == ["d1", "d2"]


def test_invites(repo):
    with repo.write() as tx:
        tx.insert_user(user("u1"))
        tx.insert_invite(invite("i1"))
        tx.insert_invite(invite("i2", expires=10))
        tx.insert_invite(invite("i3"))
        tx.insert_invite(invite("i4", kind="new_device", user_id="u1"))
        with pytest.raises(RepositoryConflict):  # hash único
            tx.insert_invite(invite("i5", code="hash-i1"))
        assert tx.consume_invite("i1", now=at(1))
        assert not tx.consume_invite("i1", now=at(2))  # uso único
        assert not tx.consume_invite("i2", now=at(10))  # expirado no limite
        assert tx.revoke_invite("i3", now=at(1))
        assert not tx.revoke_invite("i3", now=at(2))
        assert not tx.consume_invite("i3", now=at(2))  # revogado
        assert not tx.revoke_invite("i1", now=at(2))  # já usado
    with repo.read() as tx:
        assert tx.invite_by_code_hash("hash-i1").used_at == at(1)
        assert tx.get_invite("i4").user_id == "u1"
        assert tx.invite_by_code_hash("nada") is None
        assert [i.id for i in tx.list_invites()] == ["i1", "i2", "i3", "i4"]


def test_invite_consumed_once_under_concurrency(repo):
    with repo.write() as tx:
        tx.insert_invite(invite("i1"))
    results = []
    barrier = threading.Barrier(6)

    def work():
        barrier.wait()
        with repo.write() as tx:
            results.append(tx.consume_invite("i1", now=at(1)))

    threads = [threading.Thread(target=work) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [False] * 5 + [True]


def test_challenges(repo):
    def ch(cid, purpose="login", expires=60):
        return Challenge(cid, "nonce", purpose, "SHA256:x",
                         "ssh-ed25519 AAAA" if purpose == "register" else None, at(),
                         at(expires))

    with repo.write() as tx:
        tx.insert_challenge(ch("c1"))
        tx.insert_challenge(ch("c2", purpose="register"))
        tx.insert_challenge(ch("c3", expires=5))
        with pytest.raises(RepositoryConflict):  # register exige chave
            tx.insert_challenge(Challenge("c4", "n", "register", "SHA256:x", None, at(), at(9)))
        assert tx.consume_challenge("c1", now=at(1))
        assert not tx.consume_challenge("c1", now=at(2))
        assert not tx.consume_challenge("c3", now=at(5))
        assert tx.get_challenge("c2").public_key == "ssh-ed25519 AAAA"
        assert tx.purge_challenges(before=at(30)) == 1  # só c3 expirou antes
        assert tx.get_challenge("c3") is None and tx.get_challenge("nada") is None


def test_sessions(repo):
    with repo.write() as tx:
        seed_device(tx)
        for sid, exp in (("s1", 1800), ("s2", 1800), ("s3", 10)):
            tx.insert_session(Session(sid, f"tok-{sid}", "d1", "full", at(), at(exp)))
        with pytest.raises(RepositoryConflict):
            tx.insert_session(Session("s4", "tok-s1", "d1", "full", at(), at(9)))
        assert tx.revoke_session("s1", now=at(1))
        assert not tx.revoke_session("s1", now=at(2))
        assert tx.revoke_device_sessions("d1", now=at(3)) == 2
        assert tx.session_by_token_hash("tok-s2").revoked_at == at(3)
        assert tx.session_by_token_hash("nada") is None
        assert tx.purge_sessions(before=at(60)) == 1


def test_bindings(repo):
    with repo.write() as tx:
        seed_device(tx, "d1")
        seed_device(tx, "d2", "u2", "i2")
        tx.insert_binding(Binding("b1", "demo", "d1", "tsm-d-aaaaaaaaaaaa", at()))
        tx.insert_binding(Binding("b2", "demo", "d2", "tsm-d-bbbbbbbbbbbb", at(1)))
        tx.insert_binding(Binding("b3", "outro", "d1", "tsm-d-aaaaaaaaaaaa", at(2)))
        with pytest.raises(RepositoryConflict):  # um vínculo por dispositivo e projeto
            tx.insert_binding(Binding("b4", "demo", "d1", "tsm-d-cccccccccccc", at()))
        with pytest.raises(RepositoryConflict):  # workspace único no projeto
            tx.insert_binding(Binding("b5", "outro", "d2", "tsm-d-aaaaaaaaaaaa", at()))
    with repo.read() as tx:
        assert tx.get_binding("b1").workspace == "tsm-d-aaaaaaaaaaaa"
        assert tx.get_binding("nada") is None
        assert tx.binding_for("demo", "d2").id == "b2"
        assert tx.binding_for("demo", "d9") is None
        assert [b.id for b in tx.list_bindings(project_id="demo")] == ["b1", "b2"]
        assert [b.id for b in tx.list_bindings(device_id="d1")] == ["b1", "b3"]
        assert [b.id for b in tx.list_bindings()] == ["b1", "b2", "b3"]


def test_provisioning_ops(repo):
    with repo.write() as tx:
        seed_device(tx)
        op1 = tx.insert_op("d1", "create", now=at())
        op2 = tx.insert_op("d1", "disable", now=at(1))
        with pytest.raises(RepositoryConflict):
            tx.insert_op("d1", "format", now=at())
        with pytest.raises(RepositoryConflict):
            tx.insert_op("nada", "create", now=at())
        assert [o.id for o in tx.pending_ops()] == [op1, op2]
        assert tx.finish_op(op1, status="done", now=at(2))
        assert not tx.finish_op(op1, status="failed", now=at(3))
        with pytest.raises(ValueError):
            tx.finish_op(op2, status="pending", now=at(3))
        assert tx.finish_op(op2, status="failed", now=at(3), error="useradd falhou")
        assert tx.pending_ops() == []
        assert tx.get_op(op2).error == "useradd falhou"
        assert tx.get_op(999) is None
        assert [(o.action, o.status) for o in tx.ops_for_device("d1")] == [
            ("create", "done"), ("disable", "failed")]


def test_audit_insert_is_append_only(repo, db):
    with repo.write() as tx:
        tx.insert_audit(at=at(), event="device_registered", project_id="demo",
                        actor_user="u1", actor_device=None, fields={"b": 2, "a": "é"})
        tx.insert_audit(at=at(1), event="user_blocked", project_id=None, actor_user=None,
                        actor_device=None, fields={})
    with db.read() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
    assert [(r["event"], r["project_id"], r["actor_user"]) for r in rows] == [
        ("device_registered", "demo", "u1"), ("user_blocked", None, None)]
    assert rows[0]["fields"] == '{"a":"é","b":2}'
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        conn.execute("DELETE FROM audit_logs")


def test_user_has_active_binding(repo):
    with repo.write() as tx:
        seed_device(tx, "d1", "u1", "i1")
        seed_device(tx, "d2", "u1", "i2", device_status="revoked")
        seed_device(tx, "d3", "u2", "i3", device_status="revoked")
        tx.insert_binding(Binding("b1", "demo", "d1", "w1", at()))
        tx.insert_binding(Binding("b2", "outro", "d2", "w2", at()))
        tx.insert_binding(Binding("b3", "demo", "d3", "w3", at()))
    with repo.read() as tx:
        assert tx.user_has_active_binding("u1", "demo")
        assert not tx.user_has_active_binding("u1", "outro")  # só com dispositivo revogado
        assert not tx.user_has_active_binding("u2", "demo")
        assert not tx.user_has_active_binding("u9", "demo")


def test_revoke_open_invites_by_kind(repo):
    with repo.write() as tx:
        tx.insert_invite(Invite("b1", "h1", "bootstrap", "admin", "demo", None, None, at(),
                                at(3600)))
        tx.insert_invite(Invite("b2", "h2", "bootstrap", "admin", "demo", None, None, at(),
                                at(3600), used_at=at(1)))
        tx.insert_invite(Invite("b3", "h3", "bootstrap", "admin", "demo", None, None, at(),
                                at(10)))
        tx.insert_invite(invite("n1"))
        assert tx.revoke_open_invites("bootstrap", now=at(20)) == 1
        assert tx.revoke_open_invites("bootstrap", now=at(20)) == 0
        assert tx.get_invite("b1").revoked_at == at(20)
        assert tx.get_invite("b2").revoked_at is None   # usado
        assert tx.get_invite("b3").revoked_at is None   # expirado
        assert tx.get_invite("n1").revoked_at is None   # outro tipo
        assert [i.id for i in tx.list_invites(kind="bootstrap")] == ["b1", "b2", "b3"]
