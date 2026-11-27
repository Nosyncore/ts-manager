"""Contrato do ``tsm`` contra o Manager real em memória (rotas, banco, domínio).

O transporte HTTP do Client aponta para o ``TestClient`` do FastAPI e o ``ssh-keygen`` é
falso, assinando como o ``FakeVerifier`` do Manager espera: nada de rede nem subprocesso.
É o único teste do Client que importa o ``tsm_manager``.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.api_env import ApiEnv
from tests.unit.client_fakes import FakeKeygen, RecordingAcl, fingerprint
from tsm_client.cli import EXIT_CONFIG, EXIT_IDENTITY, EXIT_OK, EXIT_REFUSED, run
from tsm_client.enroll import Toolkit
from tsm_client.state import BindingState, StateStore
from tsm_manager.identity import invites
from tsm_manager.identity.base import Actor

URL = "http://127.0.0.1:8740"


class InProcessTransport:
    def __init__(self, client) -> None:
        self.client = client
        self.paths: list[str] = []

    def __call__(self, method, url, headers, data, timeout):
        path = "/" + url.split("://", 1)[1].split("/", 1)[1]
        self.paths.append(f"{method} {path.split('?')[0]}")
        r = self.client.request(method, path, content=data, headers=headers)
        return r.status_code, dict(r.headers), r.content


class FakeCollab:
    """``init`` falso: grava só o estado do vínculo, como o real faria ao concluir."""

    def __init__(self) -> None:
        self.inits: list[str] = []
        self.state: Path | None = None

    def init(self, binding_id, wait=60.0):
        self.inits.append(binding_id)
        assert self.state is not None
        StateStore(self.state).save(BindingState(binding_id, "c" * 40, 1))
        return {"revision": 1, "commit": "c" * 40, "files": 3, "sessions": []}


class Pc:
    def __init__(self, env: Env, name: str, n: int) -> None:
        self.env = env
        self.home = env.tmp / name
        self.keygen = FakeKeygen(n)
        self.transport = InProcessTransport(env.api.client)
        self.sleeps: list[float] = []
        self.on_sleep = None
        self.now = 0.0
        self.collab = FakeCollab()
        self.n = n

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.n)

    def _sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.now += s
        if self.on_sleep:
            self.on_sleep()

    def _collab(self, cfg, service) -> FakeCollab:
        self.collab.state = cfg.state_directory
        return self.collab

    def tsm(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        tk = Toolkit(acl=RecordingAcl(), keygen=lambda p, h: self.keygen,
                     transport=self.transport, sleep=self._sleep, monotonic=lambda: self.now,
                     hostname=lambda: "pc-teste")
        code = run(["--home", str(self.home), *args], toolkit=tk,
                   service_factory=lambda cfg: object(),
                   collab_factory=self._collab, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def ok(self, *args: str) -> str:
        code, out, err = self.tsm(*args)
        assert code == EXIT_OK, (args, code, out, err)
        return out

    def json(self, *args: str) -> Any:
        return json.loads(self.ok(*args, "--json"))


class Env:
    def __init__(self, tmp: Path, api: ApiEnv) -> None:
        self.tmp = tmp
        self.api = api

    def bootstrap_code(self) -> str:
        return invites.create_bootstrap(self.api.ctx, Actor.operator(), project_id="demo").code

    def operator_approve(self, device: str, fp: str) -> None:
        self.api.ids.provisioning.approve(Actor.operator(), device, fp)

    def admin(self) -> Pc:
        pc = Pc(self, "admin", 1)
        res = pc.json("enroll", "--manager", URL, "--invite", self.bootstrap_code(),
                      "--name", "Admin")
        self.operator_approve(res["device_id"], pc.fingerprint)
        return pc


@pytest.fixture
def env(tmp_path, clock, rng):
    (tmp_path / "mgr").mkdir()
    api = ApiEnv(tmp_path / "mgr", clock, rng)
    try:
        yield Env(tmp_path, api)
    finally:
        api.close()


def test_bootstrap_enroll_and_whoami(env):
    pc = Pc(env, "admin", 1)
    out = pc.ok("enroll", "--manager", URL, "--invite", env.bootstrap_code(), "--name", "Admin")
    assert pc.fingerprint in out and "tsm-manager requests approve" in out
    cfg = json.loads((pc.home / "config.json").read_text("utf-8"))
    assert cfg["version"] == 3 and cfg["device"]["fingerprint"] == pc.fingerprint
    assert cfg["manager"]["server_id"] == env.api.ctx.server_id

    who = pc.json("whoami")  # pendente: funciona e sai com 0
    assert who["device"]["status"] == "pending" and who["session"]["scope"] == "pending"
    env.operator_approve(cfg["device"]["id"], pc.fingerprint)
    who = pc.json("whoami")
    assert who["user"]["role"] == "admin" and who["device"]["status"] == "active"
    assert who["bindings"][0]["project_id"] == "demo"


def test_invite_enroll_approve_bind(env):
    admin = env.admin()
    inv = admin.json("admin", "invite", "create", "--project", "demo", "--ttl", "2h")
    assert inv["code"].startswith("tsm-inv-") and inv["kind"] == "new_user"
    dev = Pc(env, "dev", 2)
    res = dev.json("enroll", "--manager", URL, "--invite", inv["code"], "--name", "Dev")
    assert res["status"] == "pending" and res["project_id"] == "demo"

    listed = admin.json("admin", "invite", "list")
    assert [i["state"] for i in listed if i["id"] == inv["id"]] == ["used"]

    code, _, err = dev.tsm("bind", "--project", "demo", "--local", str(env.tmp / "w"))
    assert code == EXIT_IDENTITY and "aguardando aprovação" in err

    reqs = admin.json("admin", "requests", "list")
    assert [r["device"]["id"] for r in reqs] == [res["device_id"]]
    code, _, err = admin.tsm("admin", "requests", "approve", res["device_id"],
                             "--fingerprint", fingerprint(9))
    assert code == EXIT_REFUSED and "fingerprint_mismatch" in err
    admin.ok("admin", "requests", "approve", res["device_id"], "--fingerprint",
             dev.fingerprint)

    # a sessão pendente em cache é refeita (nunca ganha privilégio) e o bind passa
    info = dev.json("bind", "--project", "demo", "--local", str(env.tmp / "w"))
    assert info["created"] and info["transport"] == "local" and info["revision"] == 1
    assert dev.collab.inits == [info["binding"]]
    conn = json.loads((dev.home / "state" / "connections" / f"{info['binding']}.json")
                      .read_text("utf-8"))
    assert conn["paths"]["workspace"].endswith("tree")
    assert Path(conn["paths"]["workspace"]).is_dir()  # criado pelo LocalProvisioner
    assert (dev.home / "ssh" / ".ssh" / "known_hosts").read_text() == ""
    assert info["cache"] == str(dev.home / "cache" / "demo")

    out = dev.ok("bind", "--project", "demo")  # sem --local: só atualiza a conexão
    assert "conexão atualizada" in out and dev.collab.inits == [info["binding"]]
    code, _, err = dev.tsm("bind", "--project", "demo", "--local", str(env.tmp / "outra"))
    assert code == EXIT_REFUSED and "trocar a pasta" in err


def test_developer_cannot_administer(env):
    admin = env.admin()
    code = admin.json("admin", "invite", "create", "--project", "demo")["code"]
    dev = Pc(env, "dev", 2)
    did = dev.json("enroll", "--manager", URL, "--invite", code, "--name", "Dev")["device_id"]
    admin.ok("admin", "requests", "approve", did, "--fingerprint", dev.fingerprint)
    for args in (("admin", "invite", "create", "--project", "demo"),
                 ("admin", "requests", "approve", did, "--fingerprint", dev.fingerprint),
                 ("admin", "devices", "revoke", did), ("admin", "users", "list")):
        c, _, err = dev.tsm(*args)
        assert c == EXIT_REFUSED and "forbidden" in err, args


def test_revocation_exits_with_identity_code(env):
    admin = env.admin()
    code = admin.json("admin", "invite", "create", "--project", "demo")["code"]
    dev = Pc(env, "dev", 2)
    did = dev.json("enroll", "--manager", URL, "--invite", code, "--name", "Dev")["device_id"]
    admin.ok("admin", "requests", "approve", did, "--fingerprint", dev.fingerprint)
    dev.ok("whoami")
    out = admin.ok("admin", "devices", "revoke", did)
    assert "SSH: done" in out
    devices = admin.json("admin", "devices", "list")
    assert {d["id"]: d["status"] for d in devices}[did] == "revoked"

    code, _, err = dev.tsm("whoami")  # token em cache → 401 → sem novo login
    assert code == EXIT_IDENTITY and "identidade recusada" in err
    n = len(dev.transport.paths)
    code, _, _ = dev.tsm("bind", "--project", "demo", "--local", str(env.tmp / "w"))
    assert code == EXIT_IDENTITY  # tenta o login uma vez, recusado, e grava o marcador
    assert (dev.home / "state" / "refused").is_file()
    m = len(dev.transport.paths)
    assert m > n
    code, _, _ = dev.tsm("bind", "--project", "demo", "--local", str(env.tmp / "w"))
    assert code == EXIT_IDENTITY and len(dev.transport.paths) == m  # nada enviado


def test_block_and_unblock_user(env):
    admin = env.admin()
    code = admin.json("admin", "invite", "create", "--project", "demo")["code"]
    dev = Pc(env, "dev", 2)
    res = dev.json("enroll", "--manager", URL, "--invite", code, "--name", "Dev")
    admin.ok("admin", "requests", "approve", res["device_id"], "--fingerprint",
             dev.fingerprint)
    assert "blocked" in admin.ok("admin", "users", "block", res["user_id"])
    assert dev.tsm("whoami")[0] == EXIT_IDENTITY
    assert "active" in admin.ok("admin", "users", "unblock", res["user_id"])
    users = admin.json("admin", "users", "list")
    assert {u["id"]: u["status"] for u in users}[res["user_id"]] == "active"
    assert dev.json("whoami")["device"]["status"] == "active"  # whoami ignora o marcador
    c, _, err = admin.tsm("admin", "users", "block", admin.json("whoami")["user"]["id"])
    assert c == EXIT_REFUSED and "last_admin" in err


def test_new_device_for_existing_user(env):
    admin = env.admin()
    user_id = admin.json("whoami")["user"]["id"]
    inv = admin.json("admin", "invite", "create", "--project", "demo", "--for-user", user_id)
    assert inv["kind"] == "new_device"
    second = Pc(env, "admin2", 3)
    res = second.json("enroll", "--manager", URL, "--invite", inv["code"])  # sem --name
    assert res["status"] == "pending" and res["user_id"] == user_id
    assert admin.json("whoami")["device"]["status"] == "active"


def test_name_required_for_new_user(env):
    admin = env.admin()
    code = admin.json("admin", "invite", "create", "--project", "demo")["code"]
    c, _, err = Pc(env, "dev", 2).tsm("enroll", "--manager", URL, "--invite", code)
    assert c == EXIT_CONFIG and "invalid_request" in err


def test_invalid_invite_and_reject(env):
    admin = env.admin()
    c, _, err = Pc(env, "x", 5).tsm("enroll", "--manager", URL, "--invite",
                                    "tsm-inv-" + "a" * 26, "--name", "X")
    assert c == EXIT_REFUSED and "invalid_invite" in err and "tsm-inv-" not in err
    code = admin.json("admin", "invite", "create", "--project", "demo")["code"]
    dev = Pc(env, "dev", 2)
    did = dev.json("enroll", "--manager", URL, "--invite", code, "--name", "Dev")["device_id"]
    admin.ok("admin", "requests", "reject", did)
    assert dev.tsm("whoami")[0] == EXIT_IDENTITY
    inv = admin.json("admin", "invite", "create", "--project", "demo")
    assert "revoked" in admin.ok("admin", "invite", "revoke", inv["id"])


def test_enroll_wait_until_approved(env):
    admin = env.admin()
    code = admin.json("admin", "invite", "create", "--project", "demo")["code"]
    dev = Pc(env, "dev", 2)
    state = {}

    def approve_on_second_sleep() -> None:
        if len(dev.sleeps) == 2:
            reqs = admin.json("admin", "requests", "list")
            state["id"] = reqs[0]["device"]["id"]
            admin.ok("admin", "requests", "approve", state["id"], "--fingerprint",
                     dev.fingerprint)

    dev.on_sleep = approve_on_second_sleep
    res = dev.json("enroll", "--manager", URL, "--invite", code, "--name", "Dev",
                   "--wait", "60")
    assert res["approved"] and res["status"] == "active" and dev.sleeps == [5.0, 5.0]
    session = json.loads((dev.home / "state" / "session.json").read_text("utf-8"))
    assert session["scope"] == "full"


def test_enroll_wait_timeout(env):
    admin = env.admin()
    code = admin.json("admin", "invite", "create", "--project", "demo")["code"]
    dev = Pc(env, "dev", 2)
    c, _, err = dev.tsm("enroll", "--manager", URL, "--invite", code, "--name", "Dev",
                        "--wait", "12")
    assert c == EXIT_IDENTITY and "aguardando aprovação" in err and dev.sleeps == [5, 5, 2]


def test_expired_session_is_renewed_once(env, clock):
    admin = env.admin()
    admin.ok("whoami")
    clock.advance(1801)
    before = len(admin.transport.paths)
    admin.ok("whoami")
    assert admin.transport.paths[before:] == ["GET /me", "POST /auth/challenge",
                                              "POST /auth/verify", "GET /me"]


def test_logout_and_relogin(env):
    admin = env.admin()
    admin.ok("whoami")
    assert "sessão encerrada" in admin.ok("logout")
    assert not (admin.home / "state" / "session.json").exists()
    assert "nenhuma sessão" in admin.ok("logout")
    assert admin.json("whoami")["user"]["role"] == "admin"


def test_enroll_recovers_after_crash(env):
    pc = Pc(env, "admin", 1)
    pc.json("enroll", "--manager", URL, "--invite", env.bootstrap_code(), "--name", "Admin")
    (pc.home / "config.json").unlink()  # queda entre o cadastro e a gravação da config
    res = pc.json("enroll", "--manager", URL, "--invite", env.bootstrap_code(), "--name",
                  "Admin")
    assert res["recovered"] and res["status"] == "pending" and not res["key_created"]
    c, _, err = pc.tsm("enroll", "--manager", URL, "--invite", "x", "--name", "A")
    assert c == EXIT_REFUSED and "já há um dispositivo" in err
