"""Bordas do enroll, whoami, bind e logout com Manager falso de roteiro."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.unit.client_fakes import (
    DEVICE_ID,
    SERVER_ID,
    USER_ID,
    FakeKeygen,
    RecordingAcl,
    ScriptedTransport,
    challenge_body,
    fake_key,
    fingerprint,
)
from tests.unit.test_client_sshconfig import data as conn_data
from tsm_client.adapters.manager import ManagerProtocolError, ManagerUnavailable
from tsm_client.config import ConfigError, HomeConfig, read_home_config, write_home_config
from tsm_client.enroll import Identity, Toolkit, device_name_default
from tsm_client.errors import RefusedError
from tsm_client.home import Home
from tsm_client.login import IdentityPending, IdentityRefused, ManagerRefused
from tsm_client.sshconfig import ConnectionConfigError

URL = "http://127.0.0.1:8740"
CODE = "tsm-inv-" + "b" * 26


def make(tmp_path: Path, t: ScriptedTransport, n: int = 1) -> Identity:
    tk = Toolkit(acl=RecordingAcl(), keygen=lambda p, h: FakeKeygen(n), transport=t,
                 sleep=lambda s: None, monotonic=lambda: 0.0, hostname=lambda: "pc\x07-a")
    return Identity(Home(tmp_path / "home"), tk)


def registered(t: ScriptedTransport, status: int = 201, body=None) -> ScriptedTransport:
    t.on("POST", "/auth/challenge", 200, challenge_body("register"))
    return t.on("POST", "/auth/register", status, body if body is not None else {
        "user_id": USER_ID, "device_id": DEVICE_ID, "fingerprint": fingerprint(1),
        "status": "pending", "project_id": "demo"})


def enrolled(tmp_path: Path, t: ScriptedTransport) -> Identity:
    ident = make(tmp_path, registered(t))
    ident.enroll(manager_url=URL, invite=CODE, name="Dev")
    t.routes.clear()
    t.requests.clear()
    return ident


def test_enroll_sends_expected_body(tmp_path):
    t = registered(ScriptedTransport())
    res = make(tmp_path, t).enroll(manager_url=URL, invite=CODE, name="Dev")
    assert res.status == "pending" and res.key_created and not res.recovered
    reg = t.requests[1]["body"]
    assert reg["invite"] == CODE and reg["display_name"] == "Dev"
    assert reg["device_name"] == "pc-a"  # caractere de controle removido
    assert t.requests[0]["body"] == {"purpose": "register", "public_key": fake_key(1)}
    hc = read_home_config(Home(tmp_path / "home"))
    assert (hc.server_id, hc.device_id, hc.fingerprint) == (SERVER_ID, DEVICE_ID,
                                                            fingerprint(1))


def test_enroll_without_name_omits_display_name(tmp_path):
    t = registered(ScriptedTransport())
    make(tmp_path, t).enroll(manager_url=URL, invite=CODE, device_name="meu pc")
    assert "display_name" not in t.requests[1]["body"]
    assert t.requests[1]["body"]["device_name"] == "meu pc"


@pytest.mark.parametrize("url", ["http://10.0.0.5:8740", "ftp://x"])
def test_enroll_refuses_insecure_url_before_anything(tmp_path, url):
    from tsm_client.adapters.manager import ManagerUrlError

    t = ScriptedTransport()
    with pytest.raises(ManagerUrlError):
        make(tmp_path, t).enroll(manager_url=url, invite=CODE)
    assert t.requests == [] and not (tmp_path / "home").exists()


def test_enroll_ca_file_checks(tmp_path):
    with pytest.raises(ConfigError, match="ca-file"):
        make(tmp_path, ScriptedTransport()).enroll(manager_url="https://h", invite=CODE,
                                                   ca_file="relativo.pem")
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    t = registered(ScriptedTransport())
    make(tmp_path, t).enroll(manager_url="https://ts.example.net", invite=CODE, name="D",
                             ca_file=str(ca))
    assert read_home_config(Home(tmp_path / "home")).ca_file == str(ca)


def test_enroll_register_refusals(tmp_path):
    t = registered(ScriptedTransport(), 401, {"status": "unauthorized"})
    with pytest.raises(ManagerRefused, match="prova de posse"):
        make(tmp_path / "a", t).enroll(manager_url=URL, invite=CODE, name="D")
    t = registered(ScriptedTransport(), 422, {"status": "invalid_invite", "message": "convite"})
    with pytest.raises(ManagerRefused) as info:
        make(tmp_path / "b", t).enroll(manager_url=URL, invite=CODE, name="D")
    assert info.value.status == "invalid_invite" and CODE not in str(info.value)
    t = ScriptedTransport().on("POST", "/auth/challenge", 422, {"status": "invalid_request"})
    with pytest.raises(ManagerRefused):
        make(tmp_path / "c", t).enroll(manager_url=URL, invite=CODE, name="D")


def test_enroll_refuses_other_fingerprint(tmp_path):
    t = registered(ScriptedTransport(), body={"device_id": DEVICE_ID,
                                              "fingerprint": fingerprint(2)})
    with pytest.raises(ManagerProtocolError, match="fingerprint"):
        make(tmp_path, t).enroll(manager_url=URL, invite=CODE, name="D")


def test_enroll_recovers_key_in_use(tmp_path):
    t = registered(ScriptedTransport(), 409, {"status": "key_in_use"})
    t.on("POST", "/auth/verify", 200, {"token": "tsm-s-" + "x" * 43, "scope": "pending",
                                       "device_id": DEVICE_ID})
    t.on("GET", "/me", 200, {"server_id": SERVER_ID, "user": {"id": USER_ID},
                             "device": {"id": DEVICE_ID, "fingerprint": fingerprint(1),
                                        "status": "pending"}})
    res = make(tmp_path, t).enroll(manager_url=URL, invite=CODE, name="D")
    assert res.recovered and res.device_id == DEVICE_ID and res.user_id == USER_ID


def test_enroll_recovery_with_other_device_refused(tmp_path):
    t = registered(ScriptedTransport(), 409, {"status": "key_in_use"})
    t.on("POST", "/auth/verify", 200, {"token": "tsm-s-" + "x" * 43, "scope": "pending",
                                       "device_id": DEVICE_ID})
    t.on("GET", "/me", 200, {"device": {"id": DEVICE_ID, "fingerprint": fingerprint(5)}})
    with pytest.raises(ManagerProtocolError):
        make(tmp_path, t).enroll(manager_url=URL, invite=CODE, name="D")


def test_enroll_refuses_foreign_home(tmp_path):
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "notas.txt").write_text("x")
    from tsm_client.home import HomeError

    with pytest.raises(HomeError):
        make(tmp_path, registered(ScriptedTransport())).enroll(manager_url=URL, invite=CODE)


def test_wait_outcomes(tmp_path):
    t = ScriptedTransport()
    ident = enrolled(tmp_path, t)
    hc = read_home_config(ident.home)
    t.login_ok(scope="pending").on("GET", "/me", 200, {"device": {"status": "rejected"}})
    with pytest.raises(IdentityRefused, match="rejected"):
        ident.wait_approval(hc, 30)
    t.routes.clear()
    t.on("GET", "/me", 403, {"status": "forbidden"})
    with pytest.raises(ManagerRefused):
        ident.wait_approval(hc, 30)
    t.routes.clear()
    t.on("GET", "/me", 200, {"device": {"status": "pending"}})
    with pytest.raises(IdentityPending):
        ident.wait_approval(hc, 0)


def test_whoami_checks_server_and_refusals(tmp_path):
    t = ScriptedTransport()
    ident = enrolled(tmp_path, t)
    t.login_ok().on("GET", "/me", 200, {"server_id": "outro", "device": {}})
    with pytest.raises(RefusedError, match="server_id"):
        ident.whoami()
    t.routes.clear()
    t.on("GET", "/me", 403, {"status": "forbidden"})
    with pytest.raises(ManagerRefused):
        ident.whoami()


def test_session_requires_matching_key(tmp_path):
    t = ScriptedTransport()
    ident = enrolled(tmp_path, t)
    hc = read_home_config(ident.home)
    hc.fingerprint = fingerprint(9)
    with pytest.raises(RefusedError, match="não confere"):
        ident.session(hc)
    ident.home.key_path.unlink()
    ident.home.pub_path.unlink()
    with pytest.raises(ConfigError, match="ausente"):
        ident.session(hc)


def connection(tmp_path: Path, **kw) -> dict:
    ws, sh = tmp_path / "srv" / "ws" / "tree", tmp_path / "srv" / "shared"
    return conn_data(transport="local", workspace=str(ws), shared=str(sh), **kw)


def test_bind_validations(tmp_path):
    t = ScriptedTransport()
    ident = enrolled(tmp_path, t)
    t.login_ok().on("GET", "/connection/config", 200, connection(tmp_path))
    with pytest.raises(ConfigError, match="--local"):
        ident.bind("demo")
    with pytest.raises(Exception, match="sobrepor"):
        ident.bind("demo", str(ident.home.root / "dentro"))
    res = ident.bind("demo", str(tmp_path / "work"), str(tmp_path / "x" / "cache"))
    assert res.created and res.binding.cache == str(tmp_path / "x" / "cache")
    assert (tmp_path / "x").is_dir() and not (tmp_path / "x" / "cache").exists()
    t.routes[("GET", "/connection/config")].clear()
    t.on("GET", "/connection/config", 200, connection(tmp_path, binding_id="b-outro"))
    with pytest.raises(RefusedError, match="outro vínculo"):
        ident.bind("demo")


def test_bind_refuses_bad_connection_and_overlap(tmp_path):
    t = ScriptedTransport()
    ident = enrolled(tmp_path, t)
    t.login_ok().on("GET", "/connection/config", 200, {**connection(tmp_path),
                                                       "server_id": "outro"})
    with pytest.raises(ConnectionConfigError):
        ident.bind("demo", str(tmp_path / "work"))
    t.routes[("GET", "/connection/config")].clear()
    t.on("GET", "/connection/config", 200, connection(tmp_path))
    with pytest.raises(ConfigError):  # cache dentro da pasta local
        ident.bind("demo", str(tmp_path / "work"), str(tmp_path / "work" / "cache"))
    assert read_home_config(ident.home).bindings == []
    with pytest.raises(ConfigError):
        ident.bind("demo", "relativo")


def test_bind_detects_host_key_change(tmp_path):
    t = ScriptedTransport()
    ident = enrolled(tmp_path, t)
    t.login_ok().on("GET", "/connection/config", 200, conn_data())
    first = ident.bind("demo", str(tmp_path / "work"))
    assert not first.host_keys_changed
    assert f"Host tsm-{first.binding.id}" in ident.home.ssh_config.read_text("utf-8")
    t.routes[("GET", "/connection/config")].clear()
    t.on("GET", "/connection/config", 200, conn_data(keys=[fake_key(950)]))
    second = ident.bind("demo")
    assert second.host_keys_changed and not second.created
    assert fake_key(950) in ident.home.known_hosts.read_text()


def test_bind_refusal_from_manager(tmp_path):
    t = ScriptedTransport()
    ident = enrolled(tmp_path, t)
    t.login_ok().on("GET", "/connection/config", 404, {"status": "not_found"})
    with pytest.raises(ManagerRefused, match="not_found"):
        ident.bind("outro", str(tmp_path / "w"))


def test_logout_paths(tmp_path):
    t = ScriptedTransport()
    ident = enrolled(tmp_path, t)
    assert ident.logout() is False
    ident.store().save({"token": "tsm-s-" + "x" * 43, "scope": "full"})
    t.on("POST", "/auth/logout", 200, {"ok": True})
    assert ident.logout() is True
    assert t.requests[-1]["headers"]["Authorization"].startswith("Bearer tsm-s-")
    ident.store().save({"token": "tsm-s-" + "x" * 43, "scope": "full"})
    t.fail = ConnectionRefusedError("x")
    with pytest.raises(ManagerUnavailable):
        ident.logout()
    assert ident.store().load() is None


def test_home_config_roundtrip_and_errors(tmp_path):
    home = Home(tmp_path)
    hc = HomeConfig(URL, SERVER_ID, DEVICE_ID, fingerprint(1), ssh_path="C:\\ssh",
                    git="C:\\git\\git.exe")
    write_home_config(home, hc)
    again = read_home_config(home)
    assert again.to_dict() == hc.to_dict() and again.ssh_dir == Path("C:\\ssh")
    raw = json.loads(home.config_path.read_text("utf-8"))
    for bad in ({**raw, "version": 2}, {**raw, "extra": 1},
                {**raw, "manager": {**raw["manager"], "url": "http://10.1.1.1"}},
                {**raw, "device": {**raw["device"], "fingerprint": "md5:x"}},
                {**raw, "device": {**raw["device"], "id": "a b"}},
                {**raw, "bindings": "x"},
                {**raw, "bindings": [{"id": "B", "project_id": "demo", "local": "C:\\a",
                                      "cache": "C:\\b"}]},
                {**raw, "bindings": [{"id": "b-1", "project_id": "demo", "local": "rel",
                                      "cache": "C:\\b"}]},
                {**raw, "bindings": [{"id": "b-1", "project_id": "demo", "local": "C:\\a",
                                      "cache": "C:\\b"}] * 2},
                {**raw, "git": "relativo"}):
        home.config_path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ConfigError):
            read_home_config(home)
    home.config_path.write_text("{", encoding="utf-8")
    with pytest.raises(ConfigError, match="JSON"):
        read_home_config(home)
    home.config_path.unlink()
    with pytest.raises(ConfigError, match="tsm enroll"):
        read_home_config(home)


def test_device_name_default():
    assert device_name_default("") == "dispositivo"
    assert device_name_default("x" * 100) == "x" * 64
