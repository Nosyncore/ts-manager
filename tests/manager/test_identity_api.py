"""Identidade pela API real: ``tsm-manager serve`` como processo, config ``version: 2``.

Git, SQLite, ``ssh-keygen`` (assinatura e verificação) e HTTP reais; ``LocalProvisioner``
(sem contas do sistema). Um Manager para o módulo; os cenários seguem em ordem e compartilham
o estado. O papel do ``tsm`` é feito pelo assinador de teste: cada dispositivo tem a própria
chave e sai do próprio endereço de loopback.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from tests.manager.conftest import DEMO
from tests.manager.identity_http import Device, Http
from tests.manager.server import Server, free_port, write_config
from tsm_common import protocol as P
from tsm_common.rules import ProjectRules, rules_digest

pytestmark = pytest.mark.integration

SPELLS = "data/scripts/spells.lua"


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    s = Server(tmp_path_factory.mktemp("identity"))
    s.cli("migrate")
    s.cli("init-project", "--project", "demo", "--from", str(DEMO))
    other = s.tmp / "outro-src"
    shutil.copytree(DEMO, other)
    (other / "ts-project.json").write_text(json.dumps({"project_id": "outro", "version": 1}),
                                           encoding="utf-8")
    s.cli("init-project", "--project", "outro", "--from", str(other))
    s.start()
    s.devices = {}
    yield s
    s.stop()


def approve(admin: Device, dev: Device) -> None:
    r = admin.post(f"/admin/requests/{dev.device_id}/approve",
                   {"fingerprint": dev.fingerprint})
    assert r.status == 200, r
    assert dev.login().status == 200


def enroll(srv: Server, admin: Device, n: int, name: str, *, project: str = "demo",
           **invite) -> Device:
    r = admin.post("/admin/invites", {"project": project, **invite})
    assert r.status == 201, r
    dev = srv.device(n, name)
    assert dev.register(r.body["code"], display_name=name).status == 201
    return dev


def test_serve_started_with_identity(srv):
    log = srv.log.read_text("utf-8", "replace")
    assert "provisionador local" in log
    health = Http(srv.port).get("/health").body
    assert health["ok"] and health["server_id"]


def test_bootstrap(srv):
    boot = json.loads(srv.cli("bootstrap-admin", "--project", "demo", "--json").stdout)
    admin = srv.device(1, "Admin")
    r = admin.register(boot["code"], display_name="Admin")
    assert r.status == 201 and r.body["status"] == "pending"
    assert r.body["fingerprint"] == admin.fingerprint
    assert admin.device_id in srv.cli("requests", "list").stdout
    r = srv.cli("requests", "approve", admin.device_id, "--fingerprint", "SHA256:errado",
                ok=(1,))
    assert "fingerprint_mismatch" in r.stderr
    srv.cli("requests", "approve", admin.device_id, "--fingerprint", admin.fingerprint)
    assert admin.login().status == 200
    me = admin.get("/me").body
    assert me["user"]["role"] == "admin" and me["device"]["status"] == "active"
    assert "invalid_state" in srv.cli("bootstrap-admin", "--project", "demo", ok=(1,)).stderr
    srv.devices["admin"] = admin


def test_invite_and_pending_request(srv):
    admin = srv.devices["admin"]
    dev_a = enroll(srv, admin, 2, "Dev A")
    invites_listed = admin.get("/admin/invites").body["invites"]
    assert sum(i["state"] == "used" for i in invites_listed) == 2  # bootstrap + este
    assert dev_a.login().status == 200
    me = dev_a.get("/me").body
    assert me["device"]["status"] == "pending" and me["session"]["scope"] == "pending"
    for r in (dev_a.get("/connection/config?project=demo"), dev_a.get("/projects/demo"),
              dev_a.post("/projects/demo/bindings/b-x/publish", {})):
        assert r.status == 403 and r.code == P.PENDING_APPROVAL
    srv.devices["a"] = dev_a


def test_approval_checks_the_fingerprint(srv):
    admin, dev_a = srv.devices["admin"], srv.devices["a"]
    r = admin.post(f"/admin/requests/{dev_a.device_id}/approve",
                   {"fingerprint": admin.fingerprint})
    assert r.status == 409 and r.code == P.FINGERPRINT_MISMATCH
    approve(admin, dev_a)
    cfg = dev_a.get("/connection/config?project=demo").body
    assert cfg["transport"] == "local" and cfg["ssh"] is None
    tree = Path(cfg["paths"]["workspace"])
    assert tree.name == "tree" and tree.is_dir() and tree.parent.name.startswith("tsm-d-")
    assert cfg["rules_digest"] == rules_digest(ProjectRules())
    dev_a.extra["tree"], dev_a.extra["binding"] = tree, cfg["binding_id"]


def _publish_body(dev: Device, data: bytes, head: str) -> dict:
    target = dev.extra["tree"] / SPELLS
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"idempotency_key": str(uuid.uuid4()), "base": {"commit": head},
            "rules_digest": rules_digest(ProjectRules()),
            "changes": [{"path": SPELLS, "op": "put",
                         "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}]}


def test_publish_with_session_and_read_by_another_dev(srv):
    admin, dev_a = srv.devices["admin"], srv.devices["a"]
    head = dev_a.get("/projects/demo").body["head"]["commit"]
    r = dev_a.post(f"/projects/demo/bindings/{dev_a.extra['binding']}/publish",
                   _publish_body(dev_a, b"mana = 7\n", head))
    assert r.status == 200 and r.body["status"] == "published", r
    dev_b = enroll(srv, admin, 3, "Dev B")
    approve(admin, dev_b)
    revs = dev_b.get("/projects/demo/revisions").body["revisions"]
    assert revs[0]["revision"] == 2 and revs[0]["user"] == "Dev A"
    assert revs[0]["device"] == dev_a.device_id
    detail = dev_b.get("/projects/demo/revisions/2").body
    assert {"status": "M", "path": SPELLS} in detail["changes"]
    dev_b.extra["binding"] = dev_b.get("/connection/config?project=demo").body["binding_id"]
    srv.devices["b"] = dev_b


def test_replay_and_wrong_signatures(srv):
    dev_a = srv.devices["a"]
    ch = dev_a.challenge("login")
    sig = dev_a.signer.answer(ch)
    ok = dev_a.http.post("/auth/verify", {"challenge_id": ch["challenge_id"], "signature": sig})
    assert ok.status == 200
    replay = dev_a.http.post("/auth/verify", {"challenge_id": ch["challenge_id"],
                                              "signature": sig})
    assert replay.status == 401
    ch = dev_a.challenge("login")
    register_sig = dev_a.signer.sign(dev_a.signer.message(ch, purpose="register"))
    r = dev_a.http.post("/auth/verify", {"challenge_id": ch["challenge_id"],
                                         "signature": register_sig})
    assert r.status == 401
    ch = dev_a.challenge("login")
    other_server = dev_a.signer.sign(dev_a.signer.message({**ch, "server_id": str(uuid.uuid4())}))
    r = dev_a.http.post("/auth/verify", {"challenge_id": ch["challenge_id"],
                                         "signature": other_server})
    assert r.status == 401 and r.code == P.UNAUTHORIZED


def test_invite_errors_are_generic_and_audited(srv):
    admin = srv.devices["admin"]
    listed = admin.get("/admin/invites").body["invites"]
    r = admin.post("/admin/invites", {"project": "demo"})
    revoked_code = r.body["code"]
    assert admin.post(f"/admin/invites/{r.body['id']}/revoke").status == 200
    used = enroll(srv, admin, 4, "Dev C")
    stranger = srv.device(5, "Estranho")
    bodies = []
    for code in (revoked_code, "tsm-inv-" + "a" * 26, "lixo"):
        r = stranger.register(code, display_name="X")
        assert r.status == 422 and r.code == P.INVALID_INVITE
        bodies.append(r.body)
    assert all(b == bodies[0] for b in bodies)
    refused = srv.audit("register_refused")
    assert len(refused) >= 3 and all(e["reason"] == P.INVALID_INVITE for e in refused[-3:])
    assert len(listed) >= 2 and used.device_id


def test_cross_access(srv):
    admin, dev_a, dev_b = srv.devices["admin"], srv.devices["a"], srv.devices["b"]
    head = dev_a.get("/projects/demo").body["head"]["commit"]
    r = dev_a.post(f"/projects/demo/bindings/{dev_b.extra['binding']}/publish",
                   _publish_body(dev_a, b"mana = 8\n", head))
    assert r.status == 403 and r.code == P.FORBIDDEN
    outsider = enroll(srv, admin, 6, "Dev Outro", project="outro")
    approve(admin, outsider)
    r = outsider.get("/projects/demo")
    assert r.status == 404 and r.code == P.NOT_FOUND
    assert outsider.get("/projects/outro").status == 200


def test_operations_without_role(srv):
    admin, dev_a = srv.devices["admin"], srv.devices["a"]
    target = srv.devices["b"].device_id
    for r in (dev_a.post("/admin/invites", {"project": "demo"}),
              dev_a.post(f"/admin/requests/{target}/approve", {"fingerprint": "x"}),
              dev_a.post(f"/admin/devices/{target}/revoke"),
              dev_a.post("/projects/demo/rollback",
                         {"idempotency_key": str(uuid.uuid4()), "target": 1}),
              dev_a.get("/projects/demo/audit")):
        assert r.status == 403 and r.code == P.FORBIDDEN
    assert admin.get("/projects/demo/audit").status == 200


def test_revocation_takes_effect_on_the_next_request(srv):
    admin, dev_b = srv.devices["admin"], srv.devices["b"]
    assert dev_b.get("/me").status == 200
    r = admin.post(f"/admin/devices/{dev_b.device_id}/revoke")
    assert r.status == 200 and r.body["ssh"] == "done"
    r = dev_b.get("/me")
    assert r.status == 401 and r.code == P.UNAUTHORIZED
    assert dev_b.login().status == 401


def test_last_admin(srv):
    admin = srv.devices["admin"]
    me = admin.get("/me").body
    for r in (admin.post(f"/admin/users/{me['user']['id']}/block"),
              admin.post(f"/admin/devices/{admin.device_id}/revoke")):
        assert r.status == 409 and r.code == P.LAST_ADMIN
    assert "last_admin" in srv.cli("users", "demote", me["user"]["id"], ok=(1,)).stderr


def test_new_device_for_existing_user(srv):
    admin, dev_a = srv.devices["admin"], srv.devices["a"]
    user = dev_a.get("/me").body["user"]["id"]
    second = enroll(srv, admin, 7, "Dev A", kind="new_device", user_id=user)
    assert second.login().status == 200
    me = second.get("/me").body
    assert me["user"]["id"] == user and me["device"]["status"] == "pending"
    assert dev_a.get("/me").body["device"]["status"] == "active"
    approve(admin, second)
    assert second.get("/me").body["device"]["status"] == "active"
    assert dev_a.get("/me").body["device"]["status"] == "active"


def test_rate_limit(srv):
    http = Http(srv.port, "127.0.0.99")
    body = {"purpose": "login", "fingerprint": srv.devices["a"].fingerprint}
    statuses = [http.post("/auth/challenge", body).status for _ in range(20)]
    assert statuses == [200] * 20
    r = http.post("/auth/challenge", body)
    assert r.status == 429 and r.code == P.RATE_LIMITED and int(r.headers["retry-after"]) >= 1
    events = [e for e in srv.audit("rate_limited") if e["ip"] == "127.0.0.99"]
    assert len(events) == 1 and events[0]["route_class"] == "auth"
    assert srv.devices["a"].challenge("login")  # outro endereço continua livre


def test_recover_and_verify(srv):
    r = srv.cli("recover")
    assert "recover: ok" in r.stdout
    r = srv.cli("verify")
    assert "verify: ok" in r.stdout, r.stdout
    out = srv.cli("devices", "list").stdout
    assert "revoked" in out and "pending" in out


def test_serve_refuses_unusable_ssh_keygen(tmp_path):
    root = tmp_path / "srv"
    cfg = write_config(tmp_path, root, keygen=tmp_path / "nada" / "ssh-keygen.exe")
    run = [sys.executable, "-m", "tsm_manager"]
    assert subprocess.run([*run, "migrate", "--config", str(cfg)], capture_output=True,
                          timeout=120).returncode == 0
    r = subprocess.run([*run, "serve", "--config", str(cfg), "--port", str(free_port())],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 1 and "verificador" in r.stderr
