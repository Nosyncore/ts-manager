"""``Store`` sobre SQLite: idempotência, auditoria append-only, caches e escopo por projeto."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from tsm_manager.db import Database, upgrade
from tsm_manager.store import Store

KEY = "k" * 16
T0 = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "manager" / "manager.db")
    upgrade(d)
    yield d
    d.close()


def test_result_roundtrip_and_overwrite(db):
    st = Store(db, "demo", clock=lambda: T0)
    assert st.get_result(KEY) is None
    st.put_result(KEY, "h1", {"status": "published", "revision": 2, "nome": "ação"})
    got = st.get_result(KEY)
    assert got == {"request_hash": "h1", "at": "2026-11-26T12:00:00.000000Z",
                   "result": {"status": "published", "revision": 2, "nome": "ação"}}
    st.put_result(KEY, "h1", {"status": "published", "revision": 2, "recovered": True})
    assert st.get_result(KEY)["result"]["recovered"] is True


@pytest.mark.parametrize("key", ["", "curta", "x" * 65, "com espaço!", None])
def test_invalid_key(db, key):
    st = Store(db, "demo")
    assert not Store.valid_key(key)
    with pytest.raises(ValueError, match="idempotência"):
        st.get_result(key)
    with pytest.raises(ValueError, match="idempotência"):
        st.put_result(key, "h", {"status": "x"})


def test_results_survive_restart(tmp_path, db):
    Store(db, "demo").put_result(KEY, "h", {"status": "conflict"})
    db.close()
    again = Database(db.path)
    try:
        assert Store(again, "demo").get_result(KEY)["result"] == {"status": "conflict"}
    finally:
        again.close()


def test_scope_by_project(db):
    a, b = Store(db, "demo"), Store(db, "outro")
    a.put_result(KEY, "ha", {"status": "published"})
    assert b.get_result(KEY) is None
    b.put_result(KEY, "hb", {"status": "no_change"})  # mesma chave, outro projeto
    assert a.get_result(KEY)["request_hash"] == "ha"
    assert b.get_result(KEY)["request_hash"] == "hb"
    a.audit("publish", user="dev-a")
    assert b.read_audit() == []
    a.put_manifest("c1", {"x": "1"})
    assert b.get_manifest("c1") is None
    a.set_shared_commit("c1")
    assert b.shared_commit() is None


def test_audit_order_actors_and_limit(db):
    times = iter([T0.replace(second=s) for s in range(10)])
    st = Store(db, "demo", clock=lambda: next(times))
    st.audit("init", revision=1, files=3)
    st.audit("publish", result="published", user="dev-a", device="pca", paths=["a/ç.lua"])
    st.audit("rollback", user="admin", device=None, rollback_to=1)
    events = st.read_audit()
    assert [e["event"] for e in events] == ["rollback", "publish", "init"]
    assert events[0] == {"at": "2026-11-26T12:00:02.000000Z", "event": "rollback",
                         "user": "admin", "rollback_to": 1}
    assert events[1]["device"] == "pca" and events[1]["paths"] == ["a/ç.lua"]
    assert "user" not in events[2] and events[2]["files"] == 3
    assert [e["event"] for e in st.read_audit(1)] == ["rollback"]
    with db.read() as conn:
        row = conn.execute("SELECT actor_user, actor_device, project_id FROM audit_logs "
                           "WHERE event = 'publish'").fetchone()
    assert tuple(row) == ("dev-a", "pca", "demo")


def test_audit_is_append_only(db):
    Store(db, "demo").audit("init")
    for sql in ("UPDATE audit_logs SET event = 'x'", "DELETE FROM audit_logs"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"), db.transaction() as c:
            c.execute(sql)
    assert [e["event"] for e in Store(db, "demo").read_audit()] == ["init"]


def test_manifest_and_shared_commit(db):
    st = Store(db, "demo")
    assert st.get_manifest("c1") is None and st.shared_commit() is None
    st.put_manifest("c1", {"b.lua": "2", "a.lua": "1"})
    assert st.get_manifest("c1") == {"a.lua": "1", "b.lua": "2"}
    st.put_manifest("c1", {"a.lua": "9"})
    assert st.get_manifest("c1") == {"a.lua": "9"}
    st.set_shared_commit("c1")
    st.set_shared_commit("c2")
    assert st.shared_commit() == "c2"
