"""CLI do Manager com a config ``version: 2``: identidade, ``recover``, ``verify`` e ``serve``.

Os cadastros (que exigem prova de posse) são feitos pelo domínio, sobre o mesmo banco, com o
verificador falso; o resto passa pela CLI, como o operador faria.
"""

from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient

from tests.unit.api_env import fingerprint, write_v2_config
from tests.unit.identity_fakes import FakeVerifier, fake_key
from tsm_manager import cli_identity
from tsm_manager.cli import EXIT_CONFIG, EXIT_FAIL, EXIT_OK, EXIT_PROBLEMS, run
from tsm_manager.config import load_manager_config
from tsm_manager.db import Database, Repository, server_id
from tsm_manager.identity import accounts, challenges
from tsm_manager.identity.base import IdentityContext, IdentityError
from tsm_manager.layout import ProjectLayout
from tsm_manager.provisioning.provisioner import LocalProvisioner, ProvisionError


def tsm_manager(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(list(args), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


class Cli:
    def __init__(self, tmp_path) -> None:
        self.path = write_v2_config(tmp_path)
        self.cfg = load_manager_config(self.path)
        assert self.run("migrate")[0] == EXIT_OK
        for pid in ("demo", "outro"):
            ProjectLayout(self.cfg.root, pid).workspaces.mkdir(parents=True)

    def run(self, *args: str) -> tuple[int, str, str]:
        return tsm_manager(*args, "--config", str(self.path))

    def ok(self, *args: str) -> str:
        code, out, err = self.run(*args)
        assert code == EXIT_OK, (args, out, err)
        return out

    def enroll(self, code: str, n: int, name: str = "Fulano") -> str:
        """Cadastro com prova de posse (verificador falso), direto no domínio."""
        db = Database(self.cfg.database)
        try:
            ctx = IdentityContext(repo=Repository(db), server_id=server_id(db),
                                  verifier=FakeVerifier(), projects=frozenset(self.cfg.projects))
            ch = challenges.issue_register(ctx, fake_key(n))
            sig = FakeVerifier.sign(fake_key(n), ch.message())
            return accounts.register(ctx, invite_code=code, display_name=name,
                                     device_name=f"pc{n}", challenge_id=ch.challenge_id,
                                     signature=sig).device_id
        finally:
            db.close()

    def bootstrap(self, n: int = 1) -> str:
        data = json.loads(self.ok("bootstrap-admin", "--project", "demo", "--json"))
        device = self.enroll(data["code"], n, "Admin")
        self.ok("requests", "approve", device, "--fingerprint", fingerprint(n))
        return device

    def invite(self, *, role: str = "developer", user: str | None = None,
               project: str = "demo") -> str:
        db = Database(self.cfg.database)
        try:
            from tsm_manager.identity import invites
            from tsm_manager.identity.base import Actor

            ctx = IdentityContext(repo=Repository(db), server_id=server_id(db),
                                  verifier=FakeVerifier(), projects=frozenset(self.cfg.projects))
            kind = "new_device" if user else "new_user"
            return invites.create(ctx, Actor.operator(), project_id=project, kind=kind,
                                  role=role, for_user=user).code
        finally:
            db.close()

    def json(self, *args: str):
        return json.loads(self.ok(*args, "--json"))


@pytest.fixture
def cli(tmp_path) -> Cli:
    return Cli(tmp_path)


def test_identity_commands_refuse_version_1(tmp_path):
    p = tmp_path / "v1.json"
    p.write_text(json.dumps({"version": 1, "root": "srv", "projects": [
        {"id": "demo", "bindings": []}], "identities": []}), encoding="utf-8")
    for args in (["bootstrap-admin", "--project", "demo"], ["users", "list"],
                 ["devices", "list"], ["requests", "list"], ["invites", "list"]):
        code, _, err = tsm_manager(*args, "--config", str(p))
        assert code == EXIT_CONFIG and "version 1" in err and "não é mais aceita" in err


def test_identity_commands_need_current_database(tmp_path):
    p = write_v2_config(tmp_path)
    code, _, err = tsm_manager("users", "list", "--config", str(p))
    assert code == EXIT_FAIL and "migrate" in err


def test_bootstrap_admin_flow(cli):
    out = cli.ok("bootstrap-admin", "--project", "demo", "--ttl", "2h")
    assert "convite: tsm-inv-" in out and "server_id:" in out
    first = out.split("convite: ")[1].split()[0]
    second = cli.json("bootstrap-admin", "--project", "demo")
    listed = cli.json("invites", "list")
    states = {i["id"]: i["state"] for i in listed}
    assert states[second["invite_id"]] == "open" and list(states.values()).count("revoked") == 1
    with pytest.raises(IdentityError, match="convite"):
        cli.enroll(first, 1)  # o primeiro código foi revogado pelo segundo bootstrap
    device = cli.enroll(second["code"], 1, "Admin")
    reqs = cli.json("requests", "list")
    assert reqs[0]["device"]["id"] == device and reqs[0]["invite"]["kind"] == "bootstrap"
    assert "Admin" in cli.ok("requests", "list")
    code, _, err = cli.run("requests", "approve", device, "--fingerprint", fingerprint(2))
    assert code == EXIT_FAIL and "fingerprint_mismatch" in err
    out = cli.ok("requests", "approve", device, "--fingerprint", fingerprint(1))
    assert f"dispositivo {device} ativo" in out
    code, _, err = cli.run("bootstrap-admin", "--project", "demo")
    assert code == EXIT_FAIL and "invalid_state" in err
    assert cli.ok("requests", "list") == "nenhuma solicitação pendente\n"


def test_invites_revoke_and_list(cli):
    out = cli.ok("invites", "list")
    assert out == "nenhum convite\n"
    inv = cli.json("bootstrap-admin", "--project", "demo")
    assert "revogado" in cli.ok("invites", "revoke", inv["invite_id"])
    code, _, err = cli.run("invites", "revoke", inv["invite_id"])
    assert code == EXIT_FAIL and "invalid_state" in err
    assert "bootstrap" in cli.ok("invites", "list")


def test_reject(cli):
    cli.bootstrap()
    device = cli.enroll(cli.invite(), 2)
    assert "rejeitada" in cli.ok("requests", "reject", device)
    assert cli.json("devices", "list")[1]["status"] == "rejected"


def test_users_promote_demote_block_unblock(cli):
    admin_device = cli.bootstrap()
    device = cli.enroll(cli.invite(), 2)
    cli.ok("requests", "approve", device, "--fingerprint", fingerprint(2))
    users = cli.json("users", "list")
    admin = next(u for u in users if u["role"] == "admin")["id"]
    dev = next(u for u in users if u["role"] == "developer")["id"]
    assert "Fulano" in cli.ok("users", "list")
    code, _, err = cli.run("users", "demote", admin)
    assert code == EXIT_FAIL and "last_admin" in err
    assert "role admin" in cli.ok("users", "promote", dev)
    assert "role developer" in cli.ok("users", "demote", admin)
    out = cli.ok("users", "block", admin)
    assert "bloqueado" in out and f"dispositivo {admin_device}: disable ssh done" in out
    out = cli.ok("users", "unblock", admin)
    assert f"dispositivo {admin_device}: enable ssh done" in out
    code, _, err = cli.run("users", "promote", "nada")
    assert code == EXIT_FAIL and "not_found" in err


def test_devices_revoke_last_admin_and_purge(cli):
    admin_device = cli.bootstrap()
    listed = cli.ok("devices", "list")
    assert admin_device in listed and "Admin" in listed
    code, _, err = cli.run("devices", "revoke", admin_device)
    assert code == EXIT_FAIL and "last_admin" in err
    out = cli.ok("devices", "revoke", admin_device, "--allow-last-admin")
    assert f"dispositivo {admin_device} revogado" in out and "disable ssh done" in out
    assert "convite:" in cli.ok("bootstrap-admin", "--project", "demo")  # volta a valer
    out = cli.ok("devices", "purge", admin_device)
    assert "expurgado" in out and "delete ssh done" in out
    code, out, _ = cli.run("verify")
    assert "dispositivo" not in out  # só os projetos não inicializados


def test_pending_ssh_operation_exits_3_until_recover(cli, monkeypatch):
    cli.bootstrap()
    device = cli.enroll(cli.invite(), 2)
    cli.ok("requests", "approve", device, "--fingerprint", fingerprint(2))
    real = LocalProvisioner.disable_device

    def broken(self, account):
        raise ProvisionError("system", "pkill falhou")

    monkeypatch.setattr(LocalProvisioner, "disable_device", broken)
    code, out, _ = cli.run("devices", "revoke", device)
    assert code == EXIT_PROBLEMS and "pkill falhou" in out and "recover" in out
    assert "revogação SSH pendente" in cli.ok("devices", "list")
    code, out, _ = cli.run("recover")
    assert code == EXIT_PROBLEMS and "pending" in out
    code, out, _ = cli.run("verify")
    assert code == EXIT_PROBLEMS and "operação pendente (disable)" in out
    monkeypatch.setattr(LocalProvisioner, "disable_device", real)
    code, out, _ = cli.run("recover")
    assert code == EXIT_OK and "done" in out and "recover: ok" in out


def test_verify_checks_accounts(cli):
    cli.bootstrap()
    device = cli.enroll(cli.invite(), 2)
    cli.ok("requests", "approve", device, "--fingerprint", fingerprint(2))
    code, out, _ = cli.run("verify")
    assert code == EXIT_PROBLEMS  # projetos não inicializados (sem Git nos unitários)
    assert "dispositivo" not in out
    account = cli.json("devices", "list")[1]["ssh_account"]
    (cli.cfg.root / "manager" / "local-accounts" / f"{account}.json").unlink()
    code, out, _ = cli.run("verify")
    assert f"dispositivo {device} ({account}): conta não existe" in out


@pytest.mark.parametrize("text, seconds", [("30m", 1800), ("24h", 86_400), ("7d", 604_800),
                                           ("90", 90), ("15S", 15)])
def test_parse_duration(text, seconds):
    assert cli_identity.parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["0", "1w", "-1h", "", "h", "1.5h"])
def test_parse_duration_rejects(text):
    with pytest.raises(Exception, match="duração"):
        cli_identity.parse_duration(text)


def test_bootstrap_ttl_is_validated(cli):
    with pytest.raises(SystemExit):
        cli.run("bootstrap-admin", "--project", "demo", "--ttl", "zero")
    code, _, err = cli.run("bootstrap-admin", "--project", "demo", "--ttl", "60d")
    assert code == EXIT_FAIL and "invalid_request" in err


# ---------------------------------------------------------------- serve


def test_serve_v2_prepares_and_stops_maintenance(cli, monkeypatch):
    calls = {}

    def fake_run(app, **kw):  # o Manager fecha o banco quando o serve termina
        with TestClient(app) as client:
            calls["status"] = client.post("/auth/challenge", json={
                "purpose": "login", "fingerprint": fingerprint(1)}).status_code
        calls.update(kw)

    monkeypatch.setattr("tsm_manager.adapters.sshsig.SshKeygenVerifier.self_check",
                        lambda self: None)
    monkeypatch.setattr("uvicorn.run", fake_run)
    code, out, _ = cli.run("serve", "--port", "18740")
    assert code == EXIT_OK and calls["port"] == 18740 and calls["host"] == "127.0.0.1"
    assert "provisionador local" in out and calls["status"] == 200


def test_serve_v2_refuses_unusable_verifier(cli):
    code, _, err = cli.run("serve")
    assert code == EXIT_FAIL and "verificador" in err


def test_serve_v2_refuses_missing_groups(cli, monkeypatch):
    from tsm_manager.startup import StartupError

    def refuse(_cfg):
        raise StartupError("o processo não está nos grupos tsm-ws")

    monkeypatch.setattr("tsm_manager.startup.check_process_groups", refuse)
    code, _, err = cli.run("serve")
    assert code == EXIT_FAIL and "tsm-ws" in err
