"""API com a config ``version: 1`` (identidade de teste por token), sem Git real.

O contrato completo das rotas de projeto é coberto com Git real em
``tests/manager/test_api.py``; aqui só a autenticação e a autorização desse modo, e a
ausência das rotas de identidade.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests.unit.api_env import DEMO
from tests.unit.manager_fakes import FakeGit, FakeStore
from tsm_manager.api import create_app
from tsm_manager.auth import token_sha256
from tsm_manager.config import load_manager_config
from tsm_manager.db import Database, upgrade
from tsm_manager.project import ProjectService
from tsm_manager.services import Manager


@pytest.fixture
def client(tmp_path):
    p = tmp_path / "manager.json"
    p.write_text(json.dumps({
        "version": 1, "root": "srv",
        "projects": [{"id": "demo", "bindings": [
            {"id": "demo-pca", "device": "pca", "workspace": "pca"}]}],
        "identities": [
            {"name": "dev-a", "role": "developer", "device": "pca",
             "token_sha256": token_sha256("tok-a")},
            {"name": "admin", "role": "admin", "token_sha256": token_sha256("tok-admin")},
            {"name": "x", "role": "developer", "device": "pcx",
             "token_sha256": token_sha256("tok-x")}]}), encoding="utf-8")
    cfg = load_manager_config(p)
    db = Database(cfg.database)
    upgrade(db)
    manager = Manager(cfg, db=db)
    assert manager.identity is None
    svc = manager.projects["demo"]
    events: list = []
    fake = ProjectService(svc.project, svc.layout, git=FakeGit(events),
                          store=FakeStore(events), bindings=svc.bindings, lock_timeout=5)
    assert fake.init_project(DEMO).status == "published"
    manager.projects["demo"] = fake
    with TestClient(create_app(manager)) as c:
        yield c
    manager.close()


def H(token):
    return {"Authorization": f"Bearer {token}"}


def test_legacy_authentication_and_authorization(client):
    assert client.get("/projects/demo").status_code == 401
    assert client.get("/projects/demo", headers=H("errado")).status_code == 401
    assert client.get("/projects/demo", headers=H("tok-x")).status_code == 404
    assert client.get("/projects/demo", headers=H("tok-a")).status_code == 200
    assert client.get("/projects/nada", headers=H("tok-admin")).status_code == 404
    assert client.get("/projects/demo/revisions/1", headers=H("tok-a")).status_code == 200
    assert client.get("/projects/demo/revisions/9", headers=H("tok-a")).status_code == 404
    r = client.post("/projects/demo/bindings/demo-pca/publish", json={}, headers=H("tok-admin"))
    assert r.status_code == 403
    r = client.post("/projects/demo/bindings/demo-pca/publish", json={}, headers=H("tok-a"))
    assert r.status_code == 422  # passou da autorização; corpo recusado
    assert client.get("/projects/demo/audit", headers=H("tok-a")).status_code == 403
    assert client.get("/projects/demo/audit", headers=H("tok-admin")).status_code == 200
    assert client.post("/projects/demo/rollback", json={}, headers=H("tok-a")).status_code \
        == 403
    assert client.post("/projects/demo/rollback", json={},
                       headers=H("tok-admin")).status_code == 422
    assert client.get("/projects/demo/revisions?limit=0", headers=H("tok-a")).status_code \
        == 422


def test_legacy_has_no_identity_routes(client):
    for method, path in (("post", "/auth/challenge"), ("get", "/me"),
                         ("get", "/connection/config"), ("get", "/admin/users")):
        assert getattr(client, method)(path, headers=H("tok-admin")).status_code == 404
    assert "server_id" in client.get("/health").json()
