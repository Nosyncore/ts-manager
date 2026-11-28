"""CLI ``tsm`` com o diretório do tsm: saídas, ``--json`` e códigos de saída."""

from __future__ import annotations

import io
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
    fingerprint,
)
from tests.unit.test_client_sshconfig import data as conn_data
from tsm_client.adapters.acl import AclError
from tsm_client.adapters.sshkeygen import KeygenError
from tsm_client.cli import (
    EXIT_CONFIG,
    EXIT_IDENTITY,
    EXIT_MUTAGEN,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_UNAVAILABLE,
    default_collab,
    manager_client,
    run,
)
from tsm_client.config import load_home_config
from tsm_client.enroll import Toolkit
from tsm_client.home import Home
from tsm_client.login import SessionAuth
from tsm_client.state import BindingState, StateStore

URL = "http://127.0.0.1:8740"
CODE = "tsm-inv-" + "c" * 26


class Cli:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.home = tmp_path / "home"
        self.t = ScriptedTransport()
        self.keygen = FakeKeygen(1)
        self.acl = RecordingAcl()
        self.inits: list[str] = []

    def toolkit(self) -> Toolkit:
        return Toolkit(acl=self.acl, keygen=lambda p, h: self.keygen, transport=self.t,
                       sleep=lambda s: None, monotonic=lambda: 0.0, hostname=lambda: "pc")

    def collab(self, cfg, service):
        cli = self

        class C:
            def init(self, binding_id, wait=60.0):
                cli.inits.append(binding_id)
                StateStore(cfg.state_directory).save(BindingState(binding_id, "c" * 40, 2))
                return {"revision": 2, "commit": "c" * 40, "files": 1, "sessions": []}

            def status_info(self):
                return {"binding": "x", "initialized": False}

        return C()

    def __call__(self, *args: str, home: bool = True, environ=None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        argv = (["--home", str(self.home)] if home else []) + list(args)
        code = run(argv, toolkit=self.toolkit(), service_factory=lambda cfg: _Svc(),
                   collab_factory=self.collab, environ=environ or {}, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def enroll(self, status: int = 201, body=None) -> tuple[int, str, str]:
        self.t.on("POST", "/auth/challenge", 200, challenge_body("register"))
        self.t.on("POST", "/auth/register", status, body or {
            "user_id": USER_ID, "device_id": DEVICE_ID, "fingerprint": fingerprint(1),
            "status": "pending", "project_id": "demo"})
        r = self("enroll", "--manager", URL, "--invite", CODE, "--name", "Dev")
        self.t.routes.clear()
        return r

    def logged(self, scope: str = "full") -> Cli:
        self.enroll()
        self.t.login_ok(scope=scope)
        return self


class _Svc:
    class adapter:
        @staticmethod
        def daemon_running():
            return False

    def up(self):
        return []


@pytest.fixture
def cli(tmp_path) -> Cli:
    return Cli(tmp_path)


def test_enroll_text_output(cli):
    code, out, _ = cli.enroll()
    assert code == EXIT_OK
    assert f"dispositivo {DEVICE_ID} (pending)" in out and fingerprint(1) in out
    assert f"tsm admin requests approve {DEVICE_ID} --fingerprint {fingerprint(1)}" in out
    assert cli.acl.dirs[0] == cli.home  # ACL no <home> criado


def test_enroll_recovered_text(cli):
    cli.t.on("POST", "/auth/verify", 200, {"token": "tsm-s-" + "x" * 43, "scope": "full",
                                           "device_id": DEVICE_ID})
    cli.t.on("GET", "/me", 200, {"user": {"id": USER_ID},
                                 "device": {"id": DEVICE_ID, "fingerprint": fingerprint(1),
                                            "status": "active"}})
    code, out, _ = cli.enroll(409, {"status": "key_in_use"})
    assert code == EXIT_OK and "cadastro recuperado" in out and "(aprovado)" in out


def test_whoami_text(cli):
    cli.logged().t.on("GET", "/me", 200, {
        "server_id": SERVER_ID, "user": {"id": USER_ID, "display_name": "Dev",
                                         "role": "developer", "status": "active"},
        "device": {"id": DEVICE_ID, "name": "pc", "status": "pending"},
        "session": {"scope": "pending", "expires_at": "x"},
        "bindings": [{"id": "b-1", "project_id": "demo"}]})
    code, out, _ = cli("whoami")
    assert code == EXIT_OK and "aguardando aprovação" in out
    assert "vínculo b-1 (demo): (sem pasta local" in out


def test_config_file_option_no_longer_exists(cli, tmp_path):
    cfg = tmp_path / "x.json"
    cfg.write_text("{}")
    with pytest.raises(SystemExit) as exc:
        cli("--config", str(cfg), "whoami", home=False)
    assert exc.value.code == EXIT_CONFIG


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("command", [["whoami"], ["status"], ["history"]])
def test_old_config_in_home_is_refused(cli, version, command):
    cli.home.mkdir()
    (cli.home / "config.json").write_text(json.dumps({"version": version}), encoding="utf-8")
    code, _, err = cli(*command)
    assert code == EXIT_CONFIG and "não é mais aceita" in err and "tsm enroll" in err


def test_home_from_environment(cli):
    code, _, err = cli("whoami", home=False, environ={"TSM_HOME": str(cli.home)})
    assert code == EXIT_CONFIG and "tsm enroll" in err


def test_transport_commands_with_home(cli):
    cli.enroll()
    code, out, _ = cli("status")
    assert code == EXIT_OK and "daemon: parado" in out
    assert cli("up")[0] == EXIT_OK


def test_bind_text_and_already_initialized(cli):
    cli.logged()
    ws, sh = cli.tmp / "srv" / "tree", cli.tmp / "srv" / "shared"
    cli.t.on("GET", "/connection/config", 200,
             conn_data(transport="local", workspace=str(ws), shared=str(sh)))
    code, out, _ = cli("bind", "--project", "demo", "--local", str(cli.tmp / "w"))
    assert code == EXIT_OK and "vinculado:" in out and "inicializado em r2" in out
    code, out, _ = cli("bind", "--project", "demo")
    assert code == EXIT_OK and "conexão atualizada" in out and len(cli.inits) == 1
    cfg = load_home_config(Home(cli.home))
    assert cfg.bindings[0].workspace.path == str(ws) and cfg.home is not None


def test_bind_host_key_warning(cli):
    cli.logged()
    cli.t.on("GET", "/connection/config", 200, conn_data())
    assert cli("bind", "--project", "demo", "--local", str(cli.tmp / "w"))[0] == EXIT_OK
    cli.t.routes[("GET", "/connection/config")].clear()
    from tests.unit.client_fakes import fake_key

    cli.t.on("GET", "/connection/config", 200, conn_data(keys=[fake_key(951)]))
    code, _, err = cli("bind", "--project", "demo", "--json")
    assert code == EXIT_OK and "chave de host do servidor mudou" in err


def test_admin_text_outputs(cli):
    cli.logged()
    t = cli.t
    t.on("POST", "/admin/invites", 201, {"id": "i-1", "kind": "new_user",
                                         "role": "developer", "project_id": "demo",
                                         "expires_at": "x", "code": CODE})
    code, out, _ = cli("admin", "invite", "create", "--project", "demo", "--ttl", "30m")
    assert code == EXIT_OK and CODE in out
    assert t.requests[-1]["body"]["ttl_s"] == 1800
    t.on("GET", "/admin/invites", 200, {"invites": []})
    assert "nenhum convite" in cli("admin", "invite", "list")[1]
    t.on("POST", "/admin/invites/i-1/revoke", 200, {"id": "i-1", "state": "revoked"})
    assert "revoked" in cli("admin", "invite", "revoke", "i-1")[1]
    t.on("GET", "/admin/requests", 200, {"requests": [{
        "device": {"id": "d-2", "status": "pending", "fingerprint": fingerprint(2),
                   "name": "pc2", "created_at": "x"},
        "user": {"display_name": "Dev2"}, "invite": {"kind": "new_user",
                                                     "project_id": "demo"}}]})
    assert fingerprint(2) in cli("admin", "requests", "list")[1]
    t.on("POST", "/admin/requests/d-2/approve", 200,
         {"binding": {"id": "b-2", "project_id": "demo"}})
    assert "vínculo b-2" in cli("admin", "requests", "approve", "d-2", "--fingerprint",
                               fingerprint(2))[1]
    t.on("POST", "/admin/requests/d-2/reject", 200, {"device": {}})
    assert "rejeitado" in cli("admin", "requests", "reject", "d-2")[1]
    t.on("GET", "/admin/devices", 200, {"devices": [{
        "id": "d-2", "status": "revoked", "fingerprint": fingerprint(2), "name": "pc2",
        "user": {"display_name": "Dev2"}, "ssh_revocation_pending": True}]})
    assert "revogação SSH pendente" in cli("admin", "devices", "list")[1]
    t.on("GET", "/admin/users", 200, {"users": [{"id": "u-2", "status": "active",
                                                 "role": "developer",
                                                 "display_name": "Dev2"}]})
    assert "Dev2" in cli("admin", "users", "list")[1]
    assert json.loads(cli("admin", "users", "list", "--json")[1])[0]["id"] == "u-2"


def test_admin_ssh_pending_is_a_warning(cli):
    cli.logged()
    cli.t.on("POST", "/admin/devices/d-2/revoke", 200,
             {"device_id": "d-2", "status": "revoked", "ssh": "pending", "error": "helper"})
    code, out, err = cli("admin", "devices", "revoke", "d-2")
    assert code == EXIT_OK and "SSH: pending" in out and "recover" in err
    cli.t.on("POST", "/admin/users/u-2/block", 200, {
        "status": "blocked", "devices": [{"device_id": "d-2", "ssh": "pending"}]})
    code, _, err = cli("admin", "users", "block", "u-2")
    assert code == EXIT_OK and "d-2" in err


@pytest.mark.parametrize(("status", "http", "expected"), [
    ("provisioning_failed", 502, EXIT_MUTAGEN),
    ("invalid_request", 422, EXIT_CONFIG),
    ("last_admin", 409, EXIT_REFUSED),
])
def test_manager_refusal_codes(cli, status, http, expected):
    cli.logged()
    cli.t.on("POST", "/admin/requests/d/approve", http, {"status": status, "message": "m"})
    assert cli("admin", "requests", "approve", "d", "--fingerprint", "x")[0] == expected


def test_invalid_duration(cli):
    cli.logged()
    for bad in ("0", "1w", "abc"):
        assert cli("admin", "invite", "create", "--project", "demo", "--ttl", bad)[0] == \
            EXIT_CONFIG


def test_rate_limited_and_unavailable(cli):
    cli.enroll()
    cli.t.on("POST", "/auth/challenge", 429, {"status": "rate_limited"}, {"Retry-After": "7"})
    code, _, err = cli("whoami")
    assert code == EXIT_UNAVAILABLE and "7 s" in err
    cli.t.routes.clear()
    cli.t.fail = ConnectionRefusedError("x")
    assert cli("whoami")[0] == EXIT_UNAVAILABLE


def test_logout_unavailable(cli):
    cli.logged()
    cli.t.on("GET", "/me", 200, {"server_id": SERVER_ID, "device": {"status": "active"},
                                 "session": {"scope": "full"}})
    cli("whoami")
    cli.t.fail = ConnectionRefusedError("x")
    code, _, err = cli("logout")
    assert code == EXIT_UNAVAILABLE and "token local apagado" in err


def test_pending_and_refused_codes(cli):
    cli.logged(scope="pending")
    cli.t.on("GET", "/connection/config", 403, {"status": "pending_approval"})
    assert cli("bind", "--project", "demo", "--local", str(cli.tmp / "w"))[0] == EXIT_IDENTITY
    cli.t.routes.clear()
    cli.t.on("POST", "/auth/challenge", 200, challenge_body())
    cli.t.on("POST", "/auth/verify", 401, {"status": "unauthorized"})
    (cli.home / "state" / "session.json").unlink()
    assert cli("admin", "users", "list")[0] == EXIT_IDENTITY


@pytest.mark.parametrize("exc", [KeygenError("falhou"), AclError("icacls falhou")])
def test_tool_failures(cli, exc):
    def boom(p, h):
        raise exc

    out, err = io.StringIO(), io.StringIO()
    tk = cli.toolkit()
    tk.keygen = boom
    code = run(["--home", str(cli.home), "enroll", "--manager", URL, "--invite", CODE],
               toolkit=tk, out=out, err=err)
    assert code == EXIT_MUTAGEN and str(exc) in err.getvalue()


def test_manager_client_uses_the_session(cli, tmp_path):
    cli.enroll()
    cfg = load_home_config(Home(cli.home))
    client = manager_client(cfg, cli.toolkit())
    assert isinstance(client.auth, SessionAuth) and client.url == URL
    collab = default_collab(cfg, object(), toolkit=cli.toolkit())
    assert collab.manager.auth is not None
