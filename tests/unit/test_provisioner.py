"""Provisionadores: ``SudoProvisioner`` com executor falso e ``LocalProvisioner`` em disco."""

from __future__ import annotations

import json
import subprocess

import pytest

from tests.conftest import FIXTURES
from tsm_manager.layout import ProjectLayout
from tsm_manager.provisioning.provisioner import (
    AccountPolicy,
    Completed,
    DirInfo,
    Inspection,
    LocalProvisioner,
    ProvisionError,
    SudoProvisioner,
    parse_inspection,
)

KEYS = json.loads((FIXTURES / "sshkeys" / "vectors.json").read_text("utf-8"))
KEY_A = KEYS["ed25519"][0]["line"]           # com comentário: o provisionador normaliza
KEY_A_LINE = " ".join(KEY_A.split()[:2])
FP_A = KEYS["ed25519"][0]["fingerprint"]
KEY_B = KEYS["ed25519"][1]["line"]
ACCOUNT = "tsm-d-0123456789ab"
HELPER = "/usr/local/libexec/tsm-provision"

INSPECTION = {
    "ok": True, "account": ACCOUNT, "exists": True, "expired": False,
    "groups": [ACCOUNT, "tsm-devices", "tsm-readers", "tsm-ws"], "key_fingerprint": FP_A,
    "processes": 0, "home": {"owner": ACCOUNT, "group": ACCOUNT, "mode": "0o700"},
    "gate": {"owner": ACCOUNT, "group": "tsm-manager", "mode": "0o750"},
    "tree": {"owner": ACCOUNT, "group": "tsm-ws", "mode": "0o750"},
}


class FakeRunner:
    def __init__(self, rc: int = 0, reply: dict | bytes | None = None, *, exc=None) -> None:
        self.rc = rc
        self.reply = {"ok": True} if reply is None else reply
        self.exc = exc
        self.calls: list[tuple[list[str], bytes, dict, float]] = []

    def __call__(self, argv, stdin, env, timeout) -> Completed:
        self.calls.append((list(argv), stdin, dict(env), timeout))
        if self.exc is not None:
            raise self.exc
        out = self.reply if isinstance(self.reply, bytes) else (
            json.dumps(self.reply) + "\n").encode()
        return Completed(self.rc, out)


def sudo(runner: FakeRunner, **kw) -> SudoProvisioner:
    return SudoProvisioner(HELPER, runner=runner, **kw)


# ------------------------------------------------------------------ sudo + helper


@pytest.mark.parametrize(("call", "argv", "stdin"), [
    (lambda p: p.create_device(ACCOUNT, "demo", KEY_A),
     ["create-device", ACCOUNT, "demo"], (KEY_A_LINE + "\n").encode()),
    (lambda p: p.disable_device(ACCOUNT), ["disable-device", ACCOUNT], b""),
    (lambda p: p.enable_device(ACCOUNT, KEY_A), ["enable-device", ACCOUNT],
     (KEY_A_LINE + "\n").encode()),
    (lambda p: p.delete_device(ACCOUNT, "demo"), ["delete-device", ACCOUNT, "demo"], b""),
])
def test_sudo_argv_stdin_env_and_timeout(call, argv, stdin):
    runner = FakeRunner()
    call(sudo(runner))
    [(got_argv, got_stdin, env, timeout)] = runner.calls
    assert got_argv == ["/usr/bin/sudo", "-n", HELPER, *argv]
    assert got_stdin == stdin
    assert env == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}
    assert timeout == 60.0


def test_sudo_inspection_is_parsed():
    runner = FakeRunner(reply=INSPECTION)
    got = sudo(runner, timeout_s=5).inspect_device(ACCOUNT, "demo")
    assert got == Inspection(True, False, frozenset(INSPECTION["groups"]), FP_A, 0,
                             DirInfo(ACCOUNT, ACCOUNT, 0o700),
                             DirInfo(ACCOUNT, "tsm-manager", 0o750),
                             DirInfo(ACCOUNT, "tsm-ws", 0o750))
    assert runner.calls[0][3] == 5.0


@pytest.mark.parametrize(("rc", "kind"), [(2, "invalid"), (3, "conflict"), (4, "system")])
def test_sudo_exit_codes(rc, kind):
    runner = FakeRunner(rc, {"ok": False, "error": kind, "detail": "conta\x1b[31m existente"})
    with pytest.raises(ProvisionError) as info:
        sudo(runner).disable_device(ACCOUNT)
    assert (info.value.kind, info.value.message) == (kind, "disable-device: conta[31m "
                                                     "existente")


@pytest.mark.parametrize(("runner", "kind"), [
    (FakeRunner(exc=subprocess.TimeoutExpired("sudo", 60)), "timeout"),
    (FakeRunner(exc=FileNotFoundError("sudo")), "unavailable"),
    (FakeRunner(1, b"sudo: a password is required\n"), "unavailable"),
    (FakeRunner(0, b"nada de json\n"), "system"),
    (FakeRunner(0, b""), "system"),
    (FakeRunner(0, b"\xff\xfe"), "system"),
    (FakeRunner(0, {"ok": False}), "system"),
    (FakeRunner(137, b""), "system"),
    (FakeRunner(4, b"lixo"), "system"),
])
def test_sudo_failures(runner, kind):
    with pytest.raises(ProvisionError) as info:
        sudo(runner).disable_device(ACCOUNT)
    assert info.value.kind == kind


@pytest.mark.parametrize("change", [
    {"exists": "sim"}, {"groups": "tsm-ws"}, {"groups": [1]}, {"processes": True},
    {"processes": "0"}, {"key_fingerprint": 3}, {"gate": "x"},
    {"tree": {"owner": 1, "group": "g", "mode": "0o750"}}, {"home": {"owner": "a"}},
    {"tree": {"owner": "a", "group": "g", "mode": "rwx"}},
])
def test_inspection_with_unexpected_shape_is_refused(change):
    with pytest.raises(ProvisionError) as info:
        parse_inspection({**INSPECTION, **change})
    assert info.value.kind == "system"
    raw = dict(INSPECTION)
    del raw["groups"]
    with pytest.raises(ProvisionError):
        parse_inspection(raw)


def test_sudo_refuses_invalid_key_before_running():
    runner = FakeRunner()
    with pytest.raises(ProvisionError) as info:
        sudo(runner).create_device(ACCOUNT, "demo", "restrict " + KEY_A_LINE)
    assert info.value.kind == "invalid"
    assert runner.calls == []


@pytest.mark.parametrize("kw", [dict(helper="tsm-provision"), dict(sudo="sudo"),
                                dict(timeout_s=0)])
def test_sudo_configuration_is_validated(kw):
    args = {"helper": HELPER, **kw}
    with pytest.raises(ValueError):
        SudoProvisioner(args.pop("helper"), **args)


# ------------------------------------------------------------------ local


@pytest.fixture
def local(tmp_path) -> LocalProvisioner:
    ProjectLayout(tmp_path, "demo").workspaces.mkdir(parents=True)
    return LocalProvisioner(tmp_path)


def test_local_create_and_inspect(local, tmp_path):
    local.create_device(ACCOUNT, "demo", KEY_A)
    layout = ProjectLayout(tmp_path, "demo")
    assert layout.sync_root(ACCOUNT).is_dir()
    assert layout.sync_root(ACCOUNT) == layout.account_gate(ACCOUNT) / "tree"
    got = local.inspect_device(ACCOUNT, "demo")
    assert got == Inspection(
        True, False, frozenset({ACCOUNT, "tsm-devices", "tsm-readers", "tsm-ws"}), FP_A, 0,
        DirInfo(ACCOUNT, ACCOUNT, 0o700), DirInfo(ACCOUNT, "tsm-manager", 0o750),
        DirInfo(ACCOUNT, "tsm-ws", 0o750))
    assert (tmp_path / "manager" / "local-accounts" / f"{ACCOUNT}.json").is_file()
    local.create_device(ACCOUNT, "demo", KEY_A)
    with pytest.raises(ProvisionError) as info:
        local.create_device(ACCOUNT, "demo", KEY_B)
    assert info.value.kind == "conflict"


def test_local_disable_enable_delete(local, tmp_path):
    local.create_device(ACCOUNT, "demo", KEY_A)
    local.disable_device(ACCOUNT)
    got = local.inspect_device(ACCOUNT, "demo")
    assert (got.exists, got.expired, got.key_fingerprint) == (True, True, None)
    local.enable_device(ACCOUNT, KEY_A)
    got = local.inspect_device(ACCOUNT, "demo")
    assert (got.expired, got.key_fingerprint) == (False, FP_A)
    local.delete_device(ACCOUNT, "demo")
    got = local.inspect_device(ACCOUNT, "demo")
    assert (got.exists, got.groups, got.gate, got.tree, got.home) == (
        False, frozenset(), None, None, None)
    local.delete_device(ACCOUNT, "demo")
    local.disable_device(ACCOUNT)
    with pytest.raises(ProvisionError) as info:
        local.enable_device(ACCOUNT, KEY_A)
    assert info.value.kind == "conflict"


def test_local_uses_the_policy_groups(tmp_path):
    ProjectLayout(tmp_path, "demo").workspaces.mkdir(parents=True)
    policy = AccountPolicy("dev", "ler", "ws", "mgr")
    local = LocalProvisioner(tmp_path, policy, state_dir=tmp_path / "estado")
    local.create_device(ACCOUNT, "demo", KEY_A)
    got = local.inspect_device(ACCOUNT, "demo")
    assert got.groups == frozenset({ACCOUNT, "dev", "ler", "ws"})
    assert (got.gate.group, got.tree.group) == ("mgr", "ws")
    assert (tmp_path / "estado" / f"{ACCOUNT}.json").is_file()


@pytest.mark.parametrize(("account", "project"), [
    ("root", "demo"), ("tsm-d-../../x", "demo"), (ACCOUNT, "../demo"), (ACCOUNT, "Demo"),
])
def test_local_validates_names(local, account, project):
    with pytest.raises(ProvisionError) as info:
        local.create_device(account, project, KEY_A)
    assert info.value.kind == "invalid"


def test_local_requires_an_initialized_project(local):
    with pytest.raises(ProvisionError) as info:
        local.create_device(ACCOUNT, "outro", KEY_A)
    assert info.value.kind == "system"
