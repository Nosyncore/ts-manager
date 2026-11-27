"""Contrato das rotas de identidade e de admin da API (config ``version: 2``)."""

from __future__ import annotations

import hashlib

import pytest

from tests.unit.api_env import HOST_KEY, ApiEnv, bearer, fingerprint, key_line
from tests.unit.identity_fakes import SERVER_ID, fake_key
from tsm_common import protocol as P
from tsm_common.rules import rules_digest
from tsm_manager.db.connection import ts
from tsm_manager.db.repository import Session
from tsm_manager.identity import invites
from tsm_manager.identity.base import Actor
from tsm_manager.identity.sessions import token_hash
from tsm_manager.provisioning.provisioner import LocalProvisioner, ProvisionError

SPELLS = "data/scripts/spells.lua"


@pytest.fixture
def env(tmp_path, clock, rng):
    e = ApiEnv(tmp_path, clock, rng)
    yield e
    e.close()


def status(r) -> str:
    return r.json()["status"]


class FlakyProvisioner(LocalProvisioner):
    """``LocalProvisioner`` com falhas ligadas por verbo."""

    def __init__(self, root) -> None:
        super().__init__(root)
        self.fail: set[str] = set()

    def create_device(self, account, project, public_key):
        if "create" in self.fail:
            raise ProvisionError("system", "useradd falhou")
        super().create_device(account, project, public_key)

    def disable_device(self, account):
        if "disable" in self.fail:
            raise ProvisionError("system", "pkill falhou")
        super().disable_device(account)


# ---------------------------------------------------------------- /health e /auth/challenge


def test_health_reports_server_id(env):
    body = env.client.get("/health").json()
    assert body["ok"] is True and body["server_id"] == SERVER_ID


def test_challenge_register_and_login(env):
    reg = env.challenge("register", 5)
    assert reg["purpose"] == "register" and reg["server_id"] == SERVER_ID
    assert set(reg) == {"challenge_id", "nonce", "expires_at", "server_id", "purpose"}
    login = env.challenge("login", 5)  # fingerprint desconhecido: mesmo formato
    assert set(login) == set(reg) and login["purpose"] == "login"


@pytest.mark.parametrize("body", [
    None, [], {"purpose": "outro"}, {"purpose": "register"},
    {"purpose": "register", "public_key": 7}, {"purpose": "register", "public_key": "ssh-rsa AAA"},
    {"purpose": "login", "fingerprint": "md5:x"}, {"purpose": "login"},
])
def test_challenge_rejects_malformed_requests(env, body):
    r = env.client.post("/auth/challenge", json=body)
    assert r.status_code == 422 and status(r) == P.INVALID_REQUEST


def test_malformed_json_is_invalid_request(env):
    r = env.client.post("/auth/challenge", content=b"{x", headers={
        "Content-Type": "application/json"})
    assert r.status_code == 422 and status(r) == P.INVALID_REQUEST


# ---------------------------------------------------------------- cadastro e login


def test_bootstrap_enrollment_and_me(env):
    code = invites.create_bootstrap(env.ctx, Actor.operator(), project_id="demo").code
    r = env.register(code, 1, name="Admin")
    assert r.status_code == 201
    reg = r.json()
    assert reg["status"] == "pending" and reg["fingerprint"] == fingerprint(1)
    assert reg["project_id"] == "demo"

    pending = env.login(1)
    me = env.client.get("/me", headers=bearer(pending)).json()
    assert me["device"]["status"] == "pending" and me["session"]["scope"] == "pending"
    assert me["bindings"] == [] and me["server_id"] == SERVER_ID
    assert me["user"]["role"] == "admin" and me["device"]["fingerprint"] == fingerprint(1)
    # aprovação de bootstrap só pela CLI do servidor
    assert env.client.get("/admin/requests", headers=bearer(pending)).status_code == 403

    env.ids.provisioning.approve(Actor.operator(), reg["device_id"], fingerprint(1))
    still = env.client.get("/me", headers=bearer(pending)).json()
    assert still["session"]["scope"] == "pending"  # a sessão nunca ganha privilégio
    full = env.login(1)
    me = env.client.get("/me", headers=bearer(full)).json()
    assert me["device"]["status"] == "active" and me["session"]["scope"] == "full"
    assert me["session"]["expires_at"].endswith("Z")
    assert me["bindings"] == [{"id": env.binding_of(reg["device_id"]), "project_id": "demo"}]


def test_register_refusals(env):
    admin, _ = env.bootstrap_admin()
    code = env.invite(admin)
    assert env.register(code, 2).status_code == 201
    for bad in (code, "tsm-inv-" + "a" * 26, "nada", code.upper() + "x"):
        r = env.register(bad, 3)
        assert r.status_code == 422 and status(r) == P.INVALID_INVITE
    r = env.register(env.invite(admin), 2)  # chave já registrada
    assert r.status_code == 409 and status(r) == P.KEY_IN_USE
    fresh = env.invite(admin)
    ch = env.challenge("register", 4)
    r = env.client.post("/auth/register", json={
        "invite": fresh, "display_name": "X", "device_name": "pc",
        "challenge_id": ch["challenge_id"], "signature": env.sign(ch, 5)})
    assert r.status_code == 401 and status(r) == P.UNAUTHORIZED
    assert env.register(fresh, 4).status_code == 201  # assinatura errada não gasta o convite
    for body in (None, {"invite": 1}, {"invite": fresh, "device_name": "pc",
                                        "challenge_id": "x"}):
        r = env.client.post("/auth/register", json=body)
        assert r.status_code == 422


def test_invite_refusals_are_audited(env):
    env.bootstrap_admin()
    env.register("tsm-inv-" + "b" * 26, 3)
    assert any(e["event"] == "register_refused" and e["reason"] == P.INVALID_INVITE
               for e in env.audit())


def test_verify_refusals(env, clock):
    env.bootstrap_admin(1)
    ch = env.challenge("login", 1)
    sig = env.sign(ch, 1)
    ok = env.client.post("/auth/verify", json={"challenge_id": ch["challenge_id"],
                                                "signature": sig})
    assert ok.status_code == 200 and ok.json()["scope"] == "full"
    replay = env.client.post("/auth/verify", json={"challenge_id": ch["challenge_id"],
                                                    "signature": sig})
    assert replay.status_code == 401
    ch = env.challenge("login", 1)
    for wrong in (env.sign(ch, 1, purpose="register"), env.sign(ch, 1, server_id="outro"),
                  env.sign(ch, 2)):
        ch = env.challenge("login", 1)
        r = env.client.post("/auth/verify", json={"challenge_id": ch["challenge_id"],
                                                   "signature": wrong})
        assert r.status_code == 401 and status(r) == P.UNAUTHORIZED
    ch = env.challenge("login", 1)
    clock.advance(61)
    r = env.client.post("/auth/verify", json={"challenge_id": ch["challenge_id"],
                                               "signature": env.sign(ch, 1)})
    assert r.status_code == 401
    assert env.client.post("/auth/verify", json={}).status_code == 422


def test_session_expiry_and_bearer_parsing(env, clock):
    token, _ = env.bootstrap_admin()
    assert env.client.get("/me", headers=bearer(token)).status_code == 200
    for header in ({}, {"Authorization": token}, {"Authorization": "Basic x"},
                   bearer("tsm-s-" + "A" * 43)):
        r = env.client.get("/me", headers=header)
        assert r.status_code == 401 and status(r) == P.UNAUTHORIZED
        assert r.headers["WWW-Authenticate"] == "Bearer"
    clock.advance(1801)
    r = env.client.get("/me", headers=bearer(token))
    assert r.status_code == 401 and status(r) == P.SESSION_EXPIRED


def test_logout_revokes_the_session(env):
    token, _ = env.bootstrap_admin()
    assert env.client.post("/auth/logout", headers=bearer(token)).json() == {"ok": True}
    assert env.client.get("/me", headers=bearer(token)).status_code == 401
    assert env.client.post("/auth/logout", headers=bearer(token)).status_code == 401


# ---------------------------------------------------------------- convites


def test_invites_create_list_revoke(env, clock):
    admin, _ = env.bootstrap_admin()
    r = env.client.post("/admin/invites", json={"project": "demo", "role": "admin",
                                                "ttl_s": 3600}, headers=bearer(admin))
    assert r.status_code == 201
    created = r.json()
    assert created["code"].startswith("tsm-inv-") and created["state"] == "open"
    assert created["role"] == "admin" and created["kind"] == "new_user"
    listed = env.client.get("/admin/invites", headers=bearer(admin)).json()["invites"]
    assert created["id"] in {i["id"] for i in listed}
    assert all("code" not in i for i in listed)
    r = env.client.post(f"/admin/invites/{created['id']}/revoke", headers=bearer(admin))
    assert r.status_code == 200 and r.json()["state"] == "revoked"
    r = env.client.post(f"/admin/invites/{created['id']}/revoke", headers=bearer(admin))
    assert r.status_code == 409 and status(r) == P.INVALID_STATE
    assert env.register(created["code"], 9).json()["status"] == P.INVALID_INVITE
    expiring = env.invite(admin, ttl_s=60)
    clock.advance(61)
    assert env.register(expiring, 9).json()["status"] == P.INVALID_INVITE


@pytest.mark.parametrize("body, code", [
    ({"project": "demo", "kind": "bootstrap"}, 403),
    ({"project": "nada"}, 422),
    ({"project": "demo", "role": "root"}, 422),
    ({"project": "demo", "ttl_s": 10 ** 9}, 422),
    ({"project": "demo", "kind": 3}, 422),
    ({"project": "demo", "kind": "new_device"}, 422),
    ({}, 422),
    ([], 422),
])
def test_invite_create_refusals(env, body, code):
    admin, _ = env.bootstrap_admin()
    r = env.client.post("/admin/invites", json=body, headers=bearer(admin))
    assert r.status_code == code


def test_bootstrap_invite_is_only_revoked_by_the_operator(env):
    admin, _ = env.bootstrap_admin()
    listed = env.client.get("/admin/invites", headers=bearer(admin)).json()["invites"]
    boot = next(i for i in listed if i["kind"] == "bootstrap")
    assert boot["state"] == "used"
    r = env.client.post(f"/admin/invites/{boot['id']}/revoke", headers=bearer(admin))
    assert r.status_code == 403


# ---------------------------------------------------------------- solicitações e aprovação


def test_approval_flow(env):
    admin, _ = env.bootstrap_admin()
    device = env.pending_device(admin, 2)
    reqs = env.client.get("/admin/requests", headers=bearer(admin)).json()["requests"]
    assert [r["device"]["id"] for r in reqs] == [device]  # sem a de bootstrap
    assert reqs[0]["device"]["fingerprint"] == fingerprint(2)
    assert reqs[0]["user"]["display_name"] == "Dev 2"
    r = env.client.post(f"/admin/requests/{device}/approve",
                        json={"fingerprint": fingerprint(3)}, headers=bearer(admin))
    assert r.status_code == 409 and status(r) == P.FINGERPRINT_MISMATCH
    r = env.client.post(f"/admin/requests/{device}/approve", json={},
                        headers=bearer(admin))
    assert r.status_code == 422
    r = env.client.post(f"/admin/requests/{device}/approve",
                        json={"fingerprint": fingerprint(2)}, headers=bearer(admin))
    assert r.status_code == 200
    out = r.json()
    assert out["device"]["status"] == "active"
    assert out["binding"]["workspace"] == out["device"]["ssh_account"]
    layout = env.manager.projects["demo"].layout
    assert layout.sync_root(out["device"]["ssh_account"]).is_dir()
    r = env.client.post(f"/admin/requests/{device}/approve",
                        json={"fingerprint": fingerprint(2)}, headers=bearer(admin))
    assert r.status_code == 409 and status(r) == P.INVALID_STATE
    r = env.client.post("/admin/requests/nada/approve", json={"fingerprint": fingerprint(2)},
                        headers=bearer(admin))
    assert r.status_code == 404


def test_reject(env):
    admin, _ = env.bootstrap_admin()
    device = env.pending_device(admin, 2)
    r = env.client.post(f"/admin/requests/{device}/reject", headers=bearer(admin))
    assert r.status_code == 200 and r.json()["device"]["status"] == "rejected"
    r = env.client.post(f"/admin/requests/{device}/reject", headers=bearer(admin))
    assert r.status_code == 409
    ch = env.challenge("login", 2)
    r = env.client.post("/auth/verify", json={"challenge_id": ch["challenge_id"],
                                               "signature": env.sign(ch, 2)})
    assert r.status_code == 401


def test_approval_with_failing_provisioner_is_502(tmp_path, clock, rng):
    prov = FlakyProvisioner(tmp_path / "srv")
    env = ApiEnv(tmp_path, clock, rng, provisioner=prov)
    try:
        admin, _ = env.bootstrap_admin()
        device = env.pending_device(admin, 2)
        prov.fail.add("create")
        r = env.client.post(f"/admin/requests/{device}/approve",
                            json={"fingerprint": fingerprint(2)}, headers=bearer(admin))
        assert r.status_code == 502 and status(r) == P.PROVISIONING_FAILED
        reqs = env.client.get("/admin/requests", headers=bearer(admin)).json()["requests"]
        assert reqs[0]["device"]["status"] == "pending"
        assert "useradd" in reqs[0]["device"]["last_error"]
        prov.fail.clear()
        r = env.client.post(f"/admin/requests/{device}/approve",
                            json={"fingerprint": fingerprint(2)}, headers=bearer(admin))
        assert r.status_code == 200
    finally:
        env.close()


def test_new_device_for_existing_user(env):
    admin, _ = env.bootstrap_admin()
    token, first = env.developer(admin, 2)
    user = env.client.get("/me", headers=bearer(token)).json()["user"]["id"]
    second = env.pending_device(admin, 3, kind="new_device", user_id=user)
    me = env.client.get("/me", headers=bearer(env.login(3))).json()
    assert me["user"]["id"] == user and me["device"]["status"] == "pending"
    assert env.client.get("/me", headers=bearer(token)).json()["device"]["status"] == "active"
    r = env.client.post(f"/admin/requests/{second}/approve",
                        json={"fingerprint": fingerprint(3)}, headers=bearer(admin))
    assert r.status_code == 200 and r.json()["device"]["user_id"] == user
    assert first != second and env.binding_of(first) != env.binding_of(second)
    assert env.client.get("/me", headers=bearer(token)).json()["device"]["status"] == "active"


# ---------------------------------------------------------------- dispositivos e usuários


def test_revoke_device(env):
    admin, admin_device = env.bootstrap_admin()
    token, device = env.developer(admin, 2)
    r = env.client.post(f"/admin/devices/{device}/revoke", headers=bearer(admin))
    assert r.status_code == 200
    assert r.json()["status"] == "revoked" and r.json()["ssh"] == "done"
    assert env.client.get("/me", headers=bearer(token)).status_code == 401
    r = env.client.post(f"/admin/devices/{device}/revoke", headers=bearer(admin))
    assert r.status_code == 409
    r = env.client.post(f"/admin/devices/{admin_device}/revoke", headers=bearer(admin))
    assert r.status_code == 409 and status(r) == P.LAST_ADMIN
    devices = env.client.get("/admin/devices", headers=bearer(admin)).json()["devices"]
    assert {d["id"]: d["status"] for d in devices} == {admin_device: "active",
                                                       device: "revoked"}


def test_revoke_with_failing_helper_reports_pending(tmp_path, clock, rng):
    prov = FlakyProvisioner(tmp_path / "srv")
    env = ApiEnv(tmp_path, clock, rng, provisioner=prov)
    try:
        admin, _ = env.bootstrap_admin()
        token, device = env.developer(admin, 2)
        prov.fail.add("disable")
        r = env.client.post(f"/admin/devices/{device}/revoke", headers=bearer(admin))
        assert r.status_code == 200
        assert r.json()["ssh"] == "pending" and "pkill" in r.json()["error"]
        assert env.client.get("/me", headers=bearer(token)).status_code == 401
        listed = env.client.get("/admin/devices", headers=bearer(admin)).json()["devices"]
        mine = next(d for d in listed if d["id"] == device)
        assert mine["ssh_revocation_pending"] is True
        assert mine["pending_ops"][0]["action"] == "disable"
    finally:
        env.close()


def test_block_and_unblock(env):
    admin, _ = env.bootstrap_admin()
    token, _ = env.developer(admin, 2)
    user = env.client.get("/me", headers=bearer(token)).json()["user"]["id"]
    r = env.client.post(f"/admin/users/{user}/block", headers=bearer(admin))
    assert r.status_code == 200 and r.json()["devices"][0]["ssh"] == "done"
    assert env.client.get("/me", headers=bearer(token)).status_code == 401
    users = env.client.get("/admin/users", headers=bearer(admin)).json()["users"]
    assert {u["id"]: u["status"] for u in users}[user] == "blocked"
    r = env.client.post(f"/admin/users/{user}/unblock", headers=bearer(admin))
    assert r.status_code == 200 and r.json()["devices"][0]["action"] == "enable"
    assert env.client.get("/me", headers=bearer(env.login(2))).status_code == 200
    me = env.client.get("/me", headers=bearer(admin)).json()["user"]["id"]
    r = env.client.post(f"/admin/users/{me}/block", headers=bearer(admin))
    assert r.status_code == 409 and status(r) == P.LAST_ADMIN
    assert env.client.post("/admin/users/nada/unblock", headers=bearer(admin)).status_code \
        == 404


# ---------------------------------------------------------------- /connection/config


def test_connection_config(env):
    admin, _ = env.bootstrap_admin()
    token, device = env.developer(admin, 2)
    r = env.client.get("/connection/config", params={"project": "demo"},
                       headers=bearer(token))
    assert r.status_code == 200
    cfg = r.json()
    with env.ids.repo.read() as tx:
        account = tx.get_device(device).ssh_account
    layout = env.manager.projects["demo"].layout
    assert cfg["transport"] == "local" and cfg["ssh"] is None
    assert cfg["binding_id"] == env.binding_of(device) and cfg["device_id"] == device
    assert cfg["paths"]["workspace"] == str(layout.sync_root(account))
    assert cfg["rules_digest"] == rules_digest(env.manager.cfg.projects["demo"].rules)
    assert cfg["workspace_group"] == "tsm-ws" and cfg["server_id"] == SERVER_ID
    assert env.client.get("/connection/config", headers=bearer(token)).status_code == 422
    assert env.client.get("/connection/config", params={"project": "nada"},
                          headers=bearer(token)).status_code == 404
    assert env.client.get("/connection/config", params={"project": "outro"},
                          headers=bearer(token)).status_code == 404


def test_connection_config_over_ssh(tmp_path, clock, rng):
    host_key = tmp_path / "host.pub"
    host_key.write_text(HOST_KEY + "\n", encoding="utf-8")
    helper = str((tmp_path / "helper").resolve())
    env = ApiEnv(tmp_path, clock, rng, provisioner=LocalProvisioner(tmp_path / "srv"),
                 config={"provisioner": {"mode": "sudo", "helper": helper},
                         "ssh": {"host": "ts.example.net", "port": 2222,
                                 "host_key_files": [str(host_key.resolve())]}})
    try:
        admin, device = env.bootstrap_admin()
        cfg = env.client.get("/connection/config", params={"project": "demo"},
                             headers=bearer(admin)).json()
        with env.ids.repo.read() as tx:
            account = tx.get_device(device).ssh_account
        assert cfg["transport"] == "ssh"
        assert cfg["ssh"] == {"host": "ts.example.net", "port": 2222, "user": account,
                              "host_keys": [HOST_KEY]}
    finally:
        env.close()


def test_pending_is_refused_everywhere_but_me(env):
    admin, _ = env.bootstrap_admin()
    env.pending_device(admin, 2)
    token = env.login(2)
    for method, path in (("get", "/connection/config?project=demo"),
                         ("get", "/projects/demo"), ("get", "/projects/demo/revisions"),
                         ("post", "/projects/demo/bindings/b-x/publish"),
                         ("get", "/admin/devices")):
        r = getattr(env.client, method)(path, headers=bearer(token))
        assert r.status_code == 403 and status(r) == P.PENDING_APPROVAL, path
    assert env.client.get("/me", headers=bearer(token)).status_code == 200


# ---------------------------------------------------------------- rotas de projeto com sessão


def test_publish_with_session_reads_the_tree(env):
    admin, admin_device = env.bootstrap_admin()
    token, device = env.developer(admin, 2)
    svc = env.manager.projects["demo"]
    with env.ids.repo.read() as tx:
        account = tx.get_device(device).ssh_account
    data = b"mana = 42\n"
    target = svc.layout.sync_root(account) / SPELLS
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    body = {"idempotency_key": "k" * 16, "base": {"commit": svc.head()["commit"]},
            "rules_digest": rules_digest(svc.project.rules),
            "changes": [{"path": SPELLS, "op": "put",
                         "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}]}
    binding = env.binding_of(device)
    r = env.client.post(f"/projects/demo/bindings/{binding}/publish", json=body,
                        headers=bearer(token))
    assert r.status_code == 200 and r.json()["status"] == "published", r.text
    rev = env.client.get("/projects/demo/revisions", headers=bearer(admin)).json()
    assert rev["revisions"][0]["user"] == "Dev 2"
    assert rev["revisions"][0]["device"] == device
    events = env.client.get("/projects/demo/audit", headers=bearer(admin)).json()["events"]
    assert any(e.get("device") == device for e in events)
    other = env.binding_of(admin_device)
    r = env.client.post(f"/projects/demo/bindings/{other}/publish", json=body,
                        headers=bearer(token))
    assert r.status_code == 403 and status(r) == P.FORBIDDEN


def test_unknown_session_token_never_matches_a_test_token(env):
    """Na version 2 não existe caminho que aceite token fixo da config."""
    r = env.client.get("/projects/demo", headers=bearer("tok-admin"))
    assert r.status_code == 401


def test_expired_session_row_is_session_expired(env, clock):
    _, device = env.bootstrap_admin()
    token = "tsm-s-" + "E" * 43
    with env.ids.repo.write() as tx:
        tx.insert_session(Session("s-exp", token_hash(token), device, "full",
                                  ts(clock()), ts(clock())))
    r = env.client.get("/me", headers=bearer(token))
    assert r.status_code == 401 and status(r) == P.SESSION_EXPIRED


def test_host_key_fixture_is_ed25519():
    assert HOST_KEY.startswith("ssh-ed25519 ") and key_line(1) == fake_key(1)
