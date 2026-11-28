"""Mudanças locais, estado/armazenamento e cliente HTTP do Manager."""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from tests.unit.client_fakes import HeaderAuth
from tsm_client.adapters.manager import ManagerClient, ManagerUnavailable
from tsm_client.changes import (
    ADDED,
    DELETED,
    MODIFIED,
    diff,
    local_manifest,
    mass_deletion,
    select,
)
from tsm_client.objects import ObjectStore, ObjectStoreError
from tsm_client.state import BindingState, StateError, StateStore
from tsm_common.rules import ProjectRules

# ---------------------------------------------------------------- changes


def test_diff_and_select():
    base = {"a": "1", "b": "1", "d/x": "1", "d/y": "1"}
    local = {"a": "1", "b": "2", "c": "3", "d/y": "1"}
    changes = diff(base, local)
    assert [(c.path, c.kind) for c in changes] == [("b", MODIFIED), ("c", ADDED),
                                                   ("d/x", DELETED)]
    chosen, missing = select(changes, ["d", ".\\b", "zzz"])
    assert [c.path for c in chosen] == ["b", "d/x"] and missing == ["zzz"]
    assert select(changes, None)[0] == changes


def test_local_manifest_excludes_ignored_and_tsm(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "a.lua").write_bytes(b"1")
    (tmp_path / ".tsm").mkdir()
    (tmp_path / ".tsm" / "revision.json").write_text("{}")
    (tmp_path / "x.tmp").write_bytes(b"t")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    m = local_manifest(tmp_path, ProjectRules())
    assert list(m) == ["data/a.lua"]


@pytest.mark.parametrize(("deleted", "base", "mass"), [
    (10, 1000, False), (11, 1000, True), (2, 10, False), (3, 10, True), (3, 15, False),
    (1, 4, False), (2, 4, False), (3, 4, True), (0, 0, False)])
def test_mass_deletion(deleted, base, mass):
    assert mass_deletion(deleted, base) is mass


# ---------------------------------------------------------------- estado


def test_object_store(tmp_path):
    store = ObjectStore(tmp_path / "o")
    src = tmp_path / "f"
    src.write_bytes(b"conteudo")
    sha, size = store.put_file(src)
    assert sha == hashlib.sha256(b"conteudo").hexdigest() and size == 8
    assert store.put_file(src) == (sha, 8)  # idempotente
    assert store.read(sha) == b"conteudo"
    assert store.put_bytes(b"conteudo") == sha
    store.path(sha).write_bytes(b"adulterado")
    with pytest.raises(ObjectStoreError, match="corrompido"):
        store.read(sha)
    with pytest.raises(ObjectStoreError, match="ausente"):
        store.read("0" * 64)
    assert not [p for p in (tmp_path / "o").iterdir() if p.name.startswith("incoming-")]


def test_state_roundtrip_and_errors(tmp_path):
    store = StateStore(tmp_path / "st")
    assert store.load("demo-pca") is None and not store.initialized("demo-pca")
    st = BindingState("demo-pca", "a" * 40, 3, {"body": {"x": 1}}, ["f.lua"])
    store.save(st)
    assert store.load("demo-pca") == st
    store.put_manifest("a" * 40, {"b": "2", "a": "1"})
    assert list(store.manifest("a" * 40)) == ["a", "b"]
    with pytest.raises(StateError, match="ausente"):
        store.manifest("f" * 40)
    p = tmp_path / "st" / "bindings" / "demo-pca" / "state.json"
    p.write_text("{corrompido", encoding="utf-8")
    with pytest.raises(StateError, match="corrompido"):
        store.load("demo-pca")
    p.write_text(json.dumps({"format": 99}), encoding="utf-8")
    with pytest.raises(StateError, match="formato"):
        store.load("demo-pca")


def test_state_lock_is_exclusive(tmp_path):
    store = StateStore(tmp_path / "st")
    inside = threading.Event()
    release = threading.Event()

    def hold():
        with store.locked():
            inside.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    inside.wait(5)
    with pytest.raises(StateError, match="em andamento"), store.locked(timeout=0.2):
        pass
    release.set()
    t.join()


# ---------------------------------------------------------------- HTTP


class _Handler(BaseHTTPRequestHandler):
    routes: ClassVar[dict] = {}
    seen: ClassVar[list] = []

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.seen.append((self.command, self.path, self.headers.get("Authorization"), body))
        status, payload = self.routes.get((self.command, self.path.split("?")[0]),
                                          (404, {"status": "not_found"}))
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _reply

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    _Handler.routes, _Handler.seen = {}, []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, _Handler
    srv.shutdown()


def test_http_client_results(server):
    srv, handler = server
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    handler.routes = {
        ("GET", "/projects/demo"): (200, {"head": {"revision": 2}}),
        ("POST", "/projects/demo/bindings/demo-pca/publish"): (409, {"status": "conflict"}),
        ("GET", "/projects/demo/audit"): (403, {"status": "forbidden"}),
        ("GET", "/projects/bad"): (500, b"nada"),
    }
    c = ManagerClient(url, HeaderAuth("segredo"), timeout=5)
    r = c.project("demo")
    assert r.ok and r.body["head"]["revision"] == 2
    r = c.publish("demo", "demo-pca", {"x": 1})
    assert r.http_status == 409 and r.status == "conflict"
    assert handler.seen[-1][2] == "Bearer segredo"
    assert json.loads(handler.seen[-1][3]) == {"x": 1}
    assert c.audit("demo").status == "forbidden"
    from tsm_client.adapters.manager import ManagerProtocolError

    with pytest.raises(ManagerProtocolError):
        c.project("bad")


def test_http_client_unavailable():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(ManagerUnavailable):
        ManagerClient(f"http://127.0.0.1:{port}", HeaderAuth("t"), timeout=2).project("demo")
