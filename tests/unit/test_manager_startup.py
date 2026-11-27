"""Inicialização do ``serve`` (config ``version: 2``) e manutenção periódica."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from tests.unit.api_env import HOST_KEY, ApiEnv, fingerprint
from tests.unit.identity_fakes import FakeVerifier
from tsm_manager.adapters.sshsig import SshsigUnavailable
from tsm_manager.identity import accounts
from tsm_manager.identity.base import Actor
from tsm_manager.provisioning.provisioner import LocalProvisioner
from tsm_manager.startup import (
    Maintenance,
    StartupError,
    check_groups,
    check_process_groups,
    prepare_identity,
    run_maintenance,
)

GROUPS = {"tsm-readers": 1001, "tsm-ws": 1002, "tsm-manager": 1000}


def getgrnam(name):
    if name not in GROUPS:
        raise KeyError(name)
    return SimpleNamespace(gr_gid=GROUPS[name])


def groups(current, egid=1000):
    check_groups(["tsm-readers", "tsm-ws"], getgroups=lambda: current, getegid=lambda: egid,
                 getgrnam=getgrnam, user="tsm-manager")


def test_groups_present():
    groups([1001, 1002])
    groups([1001], egid=1002)  # grupo primário também conta


@pytest.mark.parametrize("current, missing", [([1001], "tsm-ws"), ([], "tsm-readers,tsm-ws")])
def test_groups_missing_are_refused_with_the_fix(current, missing):
    with pytest.raises(StartupError) as info:
        groups(current)
    assert f"sudo usermod -aG {missing} tsm-manager" in str(info.value)


def test_unknown_group_is_missing():
    with pytest.raises(StartupError, match="tsm-nada"):
        check_groups(["tsm-nada"], getgroups=lambda: [], getegid=lambda: 0,
                     getgrnam=getgrnam, user="x")


def test_process_groups_skipped_outside_posix(monkeypatch):
    monkeypatch.setattr("tsm_manager.startup.os.name", "nt")
    check_process_groups(SimpleNamespace(shared_group="nada", workspace_group="nada"))


class CheckingVerifier(FakeVerifier):
    def __init__(self, ok=True):
        super().__init__()
        self.ok = ok
        self.purged = 0

    def self_check(self):
        if not self.ok:
            raise SshsigUnavailable("ssh-keygen em /x não verifica")

    def purge_stale(self):
        self.purged += 1
        return 2


@pytest.fixture
def env(tmp_path, clock, rng):
    e = ApiEnv(tmp_path, clock, rng)
    yield e
    e.close()


def _lines():
    out: list[str] = []
    return out, out.append


def test_prepare_identity_runs_checks_recover_and_maintenance(env):
    env.ids.ctx.verifier = verifier = CheckingVerifier()
    out, log = _lines()
    maintenance = prepare_identity(env.manager, log=log)
    assert maintenance.rounds == 1 and verifier.purged == 2  # início + primeira rodada
    assert any("provisionador local" in line for line in out)
    assert any("temporário(s) do verificador" in line for line in out)


def test_prepare_identity_refuses_broken_verifier(env):
    env.ids.ctx.verifier = CheckingVerifier(ok=False)
    with pytest.raises(StartupError, match="verificador"):
        prepare_identity(env.manager, log=lambda _l: None)


def _ssh_env(tmp_path, clock, rng, host_key_text):
    key_file = tmp_path / "host.pub"
    key_file.write_text(host_key_text, encoding="utf-8")
    return ApiEnv(tmp_path, clock, rng, provisioner=LocalProvisioner(tmp_path / "srv"),
                  config={"provisioner": {"mode": "sudo",
                                          "helper": str((tmp_path / "h").resolve())},
                          "ssh": {"host": "ts.example.net",
                                  "host_key_files": [str(key_file.resolve())]}})


def test_prepare_identity_loads_host_keys(tmp_path, clock, rng):
    env = _ssh_env(tmp_path, clock, rng, HOST_KEY + " root@vm\n")
    try:
        env.ids.host_keys = ()
        prepare_identity(env.manager, log=lambda _l: None)
        assert env.ids.host_keys == (HOST_KEY,)
    finally:
        env.close()


def test_prepare_identity_refuses_bad_host_key(tmp_path, clock, rng):
    env = _ssh_env(tmp_path, clock, rng, "ssh-rsa AAAA x\n")
    try:
        with pytest.raises(StartupError, match="chave de host"):
            prepare_identity(env.manager, log=lambda _l: None)
    finally:
        env.close()


def test_prepare_identity_reports_provisioning_recover(env):
    admin, _ = env.bootstrap_admin()
    device = env.pending_device(admin, 2)
    accounts.begin_approval(env.ctx, Actor.operator(), device, fingerprint=fingerprint(2))
    out, log = _lines()
    prepare_identity(env.manager, log=log)  # a queda deixou a aprovação em andamento
    assert any(f"dispositivo {device}): done" in line for line in out)
    with env.ids.repo.read() as tx:
        assert tx.get_device(device).status == "active"


def test_maintenance_purges_and_expires(env, clock):
    admin, _ = env.bootstrap_admin()
    old = env.pending_device(admin, 2)
    env.challenge("login", 9)
    clock.advance(8 * 86_400)
    report = run_maintenance(env.ids)
    assert report.expired_requests == [old]
    assert report.challenges >= 1 and report.sessions >= 1
    assert report.stale_dirs == 0  # verificador falso não tem temporários
    notes = report.notes()
    assert any("expirada" in n for n in notes) and any("apagados" in n for n in notes)
    assert run_maintenance(env.ids).notes() == []


def test_maintenance_thread_runs_and_stops(env):
    lines: list[str] = []
    m = Maintenance(env.ids, interval_s=0.01, log=lines.append)
    m.start()
    deadline = time.monotonic() + 5
    while m.rounds < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    m.stop()
    assert m.rounds >= 2
    rounds = m.rounds
    time.sleep(0.05)
    assert m.rounds == rounds


def test_maintenance_thread_survives_errors(env, monkeypatch):
    lines: list[str] = []
    m = Maintenance(env.ids, interval_s=0.01, log=lines.append)
    monkeypatch.setattr("tsm_manager.startup.run_maintenance",
                        lambda _ids: (_ for _ in ()).throw(RuntimeError("x")))
    m.start()
    deadline = time.monotonic() + 5
    while not lines and time.monotonic() < deadline:
        time.sleep(0.01)
    m.stop()
    assert lines and lines[0] == "manutenção falhou: RuntimeError"
