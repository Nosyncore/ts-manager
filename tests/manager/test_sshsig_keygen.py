"""Verificador SSHSIG com o ``ssh-keygen`` real do Windows (OpenSSH do Git for Windows).

Vetores gravados, chave nova assinada sem TTY, autoteste, nada gravado fora de ``<root>`` e
o fluxo do domínio (cadastro → aprovação → login) com o verificador real.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from tests.conftest import FIXTURES
from tests.sshsig_signer import (
    SigningDevice,
    generate_key,
    keygen_path,
    openssh_version,
    sign,
)
from tsm_common import protocol as P
from tsm_common.authmsg import NAMESPACE
from tsm_manager.adapters import sshsig
from tsm_manager.adapters.sshsig import SshKeygenVerifier, work_dir_for
from tsm_manager.db import Database, Repository, server_id, upgrade
from tsm_manager.identity import accounts, challenges, invites, sessions
from tsm_manager.identity.base import Actor, IdentityContext, IdentityError

pytestmark = pytest.mark.integration

VECTORS = json.loads((FIXTURES / "sshsig" / "vectors.json").read_text("utf-8"))
KEYGEN = keygen_path()


class CountingRunner:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args):
        self.calls += 1
        return sshsig.run_process(*args)


@pytest.fixture(scope="module", autouse=True)
def real_keygen() -> None:
    assert KEYGEN.is_file(), f"ssh-keygen ausente em {KEYGEN} (TSM_SSH_PATH)"


@pytest.fixture
def root(tmp_path) -> Path:
    return tmp_path / "root"


@pytest.fixture
def database(root):
    db = Database(root / "manager" / "manager.db")
    upgrade(db)
    yield db
    db.close()


@pytest.fixture
def verifier(database) -> SshKeygenVerifier:
    return SshKeygenVerifier(KEYGEN, work_dir_for(database.path))


def test_windows_openssh_version():
    assert openssh_version(KEYGEN).startswith("OpenSSH_10.")


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_recorded_vectors(root, case):
    runner = CountingRunner()
    verifier = SshKeygenVerifier(KEYGEN, root / "manager" / "tmp" / "sshsig", runner=runner)
    result = verifier.verify(case["public_key"], NAMESPACE,
                             case["message_text"].encode("ascii"), case["signature"])
    assert result is case["valid"]
    assert runner.calls == (0 if case["rejected_by"] == "validation" else 1)


def test_fresh_key_signed_without_tty_is_accepted(tmp_path, verifier):
    client = tmp_path / "client"
    private, public = generate_key(KEYGEN, client / "ssh" / ".ssh", "device")
    message = b"tsm-auth-v1\nmensagem qualquer\n"
    good = sign(KEYGEN, private, message, home=client / "ssh")
    other_ns = sign(KEYGEN, private, message, home=client / "ssh", namespace="git")
    assert verifier.verify(public, NAMESPACE, message, good) is True
    assert verifier.verify(public, NAMESPACE, message, other_ns) is False
    assert verifier.verify(public, NAMESPACE, message + b"x", good) is False


def test_self_check_with_real_ssh_keygen(verifier):
    verifier.self_check()


def test_missing_executable_fails_self_check(tmp_path):
    verifier = SshKeygenVerifier(tmp_path / "nao-existe" / "ssh-keygen.exe",
                                 tmp_path / "work")
    with pytest.raises(sshsig.SshsigUnavailable):
        verifier.self_check()


def _snapshot(directory: Path) -> tuple[int, list[str]]:
    return directory.stat().st_mtime_ns, sorted(
        str(p.relative_to(directory)) for p in directory.rglob("*"))


def test_nothing_written_outside_root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    work = work_dir_for(root / "manager" / "manager.db")
    sentinels = {name: tmp_path / "fora" / name for name in ("tmp", "home", "cwd")}
    for path in sentinels.values():
        path.mkdir(parents=True)
    for var in ("TMP", "TEMP", "TMPDIR"):
        monkeypatch.setenv(var, str(sentinels["tmp"]))
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(sentinels["home"]))
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.chdir(sentinels["cwd"])
    before = {name: _snapshot(path) for name, path in sentinels.items()}

    verifier = SshKeygenVerifier(KEYGEN, work)
    verifier.self_check()
    for case in VECTORS["cases"]:
        verifier.verify(case["public_key"], NAMESPACE, case["message_text"].encode("ascii"),
                        case["signature"])

    assert {name: _snapshot(path) for name, path in sentinels.items()} == before
    assert sorted(p.relative_to(root).as_posix() for p in root.rglob("*")) == [
        "manager", "manager/tmp", "manager/tmp/sshsig"]


# ------------------------------------------------------------------ fluxo do domínio


def test_domain_flow_with_real_verifier(tmp_path, database, verifier):
    ctx = IdentityContext(repo=Repository(database), server_id=server_id(database),
                          verifier=verifier, projects=frozenset({"demo"}))
    device = SigningDevice(KEYGEN, tmp_path / "client" / "ssh")
    invite = invites.create_bootstrap(ctx, Actor.operator(), project_id="demo")

    reg = challenges.issue_register(ctx, device.public).to_response()
    registration = accounts.register(ctx, invite_code=invite.code, display_name="Admin",
                                     device_name="pc-admin",
                                     challenge_id=reg["challenge_id"],
                                     signature=device.answer(reg))
    assert (registration.status, registration.fingerprint) == ("pending", device.fingerprint)

    pending = challenges.issue_login(ctx, device.fingerprint).to_response()
    assert sessions.login(ctx, pending["challenge_id"], device.answer(pending)).scope == \
        "pending"

    ticket = accounts.begin_approval(ctx, Actor.operator(), registration.device_id,
                                     fingerprint=device.fingerprint)
    accounts.complete_approval(ctx, registration.device_id, ticket.op_id)

    login = challenges.issue_login(ctx, device.fingerprint).to_response()
    signature = device.answer(login)
    issued = sessions.login(ctx, login["challenge_id"], signature)
    principal = sessions.authenticate(ctx, issued.token)
    assert (issued.scope, principal.is_admin, principal.device_id) == (
        "full", True, registration.device_id)

    with pytest.raises(IdentityError) as replay:
        sessions.login(ctx, login["challenge_id"], signature)
    assert replay.value.code == P.UNAUTHORIZED

    other = challenges.issue_login(ctx, device.fingerprint).to_response()
    as_register = device.sign(device.message(other, purpose="register"))
    with pytest.raises(IdentityError) as cross:
        sessions.login(ctx, other["challenge_id"], as_register)
    assert cross.value.code == P.UNAUTHORIZED

    assert list(work_dir_for(database.path).iterdir()) == []

