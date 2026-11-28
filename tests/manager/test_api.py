"""SU4: contrato da API HTTP sobre o Manager real (Git real, ``TestClient``)."""

from __future__ import annotations

import json
import shutil
import uuid

import pytest
from fastapi.testclient import TestClient

from tests.identity_seed import KEYGEN, Seed
from tests.manager.conftest import DEMO, demo_files, sha
from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager.api import create_app
from tsm_manager.config import load_manager_config
from tsm_manager.db import Database, upgrade
from tsm_manager.services import Manager

pytestmark = pytest.mark.integration

SPELLS = "data/scripts/spells.lua"


def _login(c: TestClient, dev) -> str:
    """Sessão pelas rotas reais: desafio → assinatura do ``ssh-keygen`` → verificação."""
    ch = c.post("/auth/challenge", json={"purpose": "login", "fingerprint": dev.fingerprint})
    assert ch.status_code == 200, ch.text
    r = c.post("/auth/verify", json={"challenge_id": ch.json()["challenge_id"],
                                     "signature": dev.signer.answer(ch.json())})
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture
def env(tmp_path):
    cfg_path = tmp_path / "manager.json"
    cfg_path.write_text(json.dumps({
        "version": 2, "root": "srv", "shared_group": "tsm-readers",
        "workspace_group": "tsm-ws", "provisioner": {"mode": "local"},
        "auth": {"ssh_keygen": str(KEYGEN)},
        "projects": [{"id": "demo"}, {"id": "outro"}],
    }), encoding="utf-8")
    cfg = load_manager_config(cfg_path)
    db = Database(cfg.database)
    upgrade(db)
    manager = Manager(cfg, db=db)
    assert manager.projects["demo"].init_project(DEMO).status == "published"
    other = tmp_path / "outro-src"
    shutil.copytree(DEMO, other)
    (other / "ts-project.json").write_text('{"project_id": "outro", "version": 1}',
                                           encoding="utf-8")
    assert manager.projects["outro"].init_project(other).status == "published"
    seed = Seed(manager.identity, tmp_path / "keys")
    people = {"admin": seed.device("admin", admin=True), "a": seed.device("dev-a"),
              "b": seed.device("dev-b"), "x": seed.device("outro", project="outro")}
    c = TestClient(create_app(manager))
    tokens = {k: _login(c, p) for k, p in people.items()}
    yield manager, c, people, tokens
    manager.close()


def H(token):
    return {"Authorization": f"Bearer {token}"}


def _publish_body(manager, people, files, base=None, key=None):
    svc = manager.projects["demo"]
    ws = svc.layout.sync_root(people["a"].account)
    changes = []
    for rel, data in files.items():
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_bytes(data)
        changes.append({"path": rel, "op": "put", "sha256": sha(data), "size": len(data)})
    return {"idempotency_key": key or str(uuid.uuid4()),
            "base": {"commit": base or svc.git.resolve("refs/heads/main")},
            "rules_digest": rules_digest(ProjectRules()), "changes": changes}


def test_health_and_auth(env):
    _manager, c, _people, tok = env
    assert c.get("/health").json()["ok"] is True
    assert c.get("/projects/demo").status_code == 401
    assert c.get("/projects/demo", headers=H("errado")).status_code == 401
    assert c.get("/projects/demo", headers=H(tok["x"])).status_code == 404  # sem vínculo
    assert c.get("/projects/nope", headers=H(tok["a"])).status_code == 404


def test_project_info(env):
    _manager, c, _people, tok = env
    info = c.get("/projects/demo", headers=H(tok["a"])).json()
    assert info["head"]["revision"] == 1
    assert info["rules_digest"] == rules_digest(ProjectRules())
    assert info["limits"]["max_files"] == 2000


def test_publish_and_history(env):
    manager, c, people, tok = env
    data = demo_files()[SPELLS].replace(b"mana = 20", b"mana = 21")
    body = _publish_body(manager, people, {SPELLS: data})
    url = f"/projects/demo/bindings/{people['a'].binding.id}/publish"
    r = c.post(url, json=body, headers=H(tok["a"]))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "published" and r.json()["revision"] == 2
    # repetição idempotente
    r2 = c.post(url, json=body, headers=H(tok["a"]))
    assert r2.json()["revision"] == 2 and r2.json()["replayed"] is True
    revs = c.get("/projects/demo/revisions?limit=10", headers=H(tok["b"])).json()["revisions"]
    assert [x["revision"] for x in revs] == [2, 1]
    detail = c.get("/projects/demo/revisions/2", headers=H(tok["b"])).json()
    assert detail["changes"] == [{"status": "M", "path": SPELLS}]
    assert c.get("/projects/demo/revisions/9", headers=H(tok["b"])).status_code == 404


def test_publish_forbidden_for_other_binding(env):
    manager, c, people, tok = env
    body = _publish_body(manager, people, {"data/x.lua": b"1"})
    assert c.post(f"/projects/demo/bindings/{people['a'].binding.id}/publish", json=body,
                  headers=H(tok["b"])).status_code == 403
    assert c.post(f"/projects/demo/bindings/{people['a'].binding.id}/publish", json=body,
                  headers=H(tok["admin"])).status_code == 403
    assert c.post("/projects/demo/bindings/nope/publish", json=body,
                  headers=H(tok["a"])).status_code == 403


def test_publish_error_codes(env):
    manager, c, people, tok = env
    url = f"/projects/demo/bindings/{people['a'].binding.id}/publish"
    bad = _publish_body(manager, people, {"data/CON.lua": b"x"})
    r = c.post(url, json=bad, headers=H(tok["a"]))
    assert r.status_code == 422 and r.json()["status"] == "rejected"
    stale = _publish_body(manager, people, {"data/x.lua": b"x"}, base="f" * 40)
    r = c.post(url, json=stale, headers=H(tok["a"]))
    assert r.status_code == 409 and r.json()["status"] == "stale_base"
    r = c.post(url, content=b"nada", headers=H(tok["a"]) | {"content-type": "application/json"})
    assert r.status_code == 422


def test_rollback_and_audit_require_admin(env):
    manager, c, people, tok = env
    body = _publish_body(manager, people, {"data/x.lua": b"x"})
    assert c.post(f"/projects/demo/bindings/{people['a'].binding.id}/publish", json=body,
                  headers=H(tok["a"])).status_code == 200
    rb = {"idempotency_key": str(uuid.uuid4()), "target": 1}
    assert c.post("/projects/demo/rollback", json=rb, headers=H(tok["a"])).status_code == 403
    r = c.post("/projects/demo/rollback", json=rb, headers=H(tok["admin"]))
    assert r.status_code == 200 and r.json()["revision"] == 3
    assert c.get("/projects/demo/audit", headers=H(tok["a"])).status_code == 403
    events = c.get("/projects/demo/audit", headers=H(tok["admin"])).json()["events"]
    assert events[0]["event"] == "rollback"
