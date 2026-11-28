"""Config ``version: 2`` do Manager: identidade real, provisionador, SSH e TTLs."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tsm_manager.adapters.sshsig import default_executable
from tsm_manager.config import (
    AuthConfig,
    ManagerConfigError,
    ProvisionerConfig,
    SshConfig,
    load_manager_config,
)

HOST_KEY = str(Path("/etc/ssh/ssh_host_ed25519_key.pub").resolve())
HELPER = str(Path("/usr/local/libexec/tsm-provision").resolve())


def base(**top) -> dict:
    data = {
        "version": 2, "root": "srv",
        "shared_group": "tsm-readers", "workspace_group": "tsm-ws",
        "provisioner": {"mode": "local"},
        "projects": [{"id": "demo"}],
    }
    data.update(top)
    return data


def full() -> dict:
    return base(
        database="manager/m.db",
        ssh={"host": "ts.example.net", "port": 2222, "host_key_files": [HOST_KEY],
             "devices_group": "tsm-dev"},
        provisioner={"mode": "sudo", "helper": HELPER, "sudo": HELPER, "timeout_s": 30,
                     "manager_group": "tsm-mgr"},
        auth={"challenge_ttl_s": 30, "session_ttl_s": 600, "invite_ttl_s": 3600,
              "invite_ttl_max_s": 7200, "pending_ttl_s": 7200, "ssh_keygen": HELPER,
              "sshsig_timeout_s": 2.5},
        projects=[{"id": "demo", "rules": {"allow": ["data/"]},
                   "limits": {"max_files": 10}}],
    )


def load(tmp_path, data):
    p = tmp_path / "manager.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return load_manager_config(p)


def test_minimal_local_config_has_defaults(tmp_path):
    cfg = load(tmp_path, base())
    assert cfg.root == (tmp_path / "srv").resolve()
    assert cfg.database == cfg.root / "manager" / "manager.db"
    assert cfg.shared_group == "tsm-readers" and cfg.workspace_group == "tsm-ws"
    assert cfg.provisioner == ProvisionerConfig("local")
    assert cfg.provisioner.manager_group == "tsm-manager"
    assert cfg.ssh is None
    assert cfg.auth == AuthConfig()
    assert cfg.auth.ssh_keygen == default_executable()
    assert cfg.auth.sshsig_timeout_s == 5
    assert cfg.backups == cfg.root / "manager" / "backups"
    assert not hasattr(cfg, "identities") and not hasattr(cfg.projects["demo"], "bindings")


def test_full_config(tmp_path):
    cfg = load(tmp_path, full())
    assert cfg.ssh == SshConfig("ts.example.net", 2222, (Path(HOST_KEY),), "tsm-dev")
    assert cfg.provisioner == ProvisionerConfig("sudo", HELPER, HELPER, 30, "tsm-mgr")
    assert cfg.auth == AuthConfig(30, 600, 3600, 7200, 7200, HELPER, 2.5)
    settings = cfg.auth.settings()
    assert (settings.challenge_ttl_s, settings.session_ttl_s, settings.invite_ttl_s,
            settings.invite_ttl_max_s, settings.pending_ttl_s) == (30, 600, 3600, 7200, 7200)
    assert cfg.projects["demo"].limits.max_files == 10
    assert cfg.database == cfg.root / "manager" / "m.db"


def test_ssh_port_defaults_to_22(tmp_path):
    data = base(ssh={"host": "10.0.0.5", "host_key_files": [HOST_KEY]})
    cfg = load(tmp_path, data)
    assert cfg.ssh.port == 22 and cfg.ssh.devices_group == "tsm-devices"


@pytest.mark.parametrize("host", ["::1", "127.0.0.1", "vm-01.local", "a"])
def test_ssh_host_accepted(tmp_path, host):
    assert load(tmp_path, base(ssh={"host": host, "host_key_files": [HOST_KEY]})).ssh.host \
        == host


def test_version_1_is_refused_with_migration_message(tmp_path):
    with pytest.raises(ManagerConfigError) as exc:
        load(tmp_path, {"version": 1, "root": "srv",
                        "projects": [{"id": "demo", "bindings": []}], "identities": []})
    msg = str(exc.value)
    assert "version 1" in msg and "não é mais aceita" in msg
    for hint in ("identities", "bindings", "bootstrap-admin", "workspace_group", "provisioner"):
        assert hint in msg


@pytest.mark.parametrize("version", [0, 3, "2", None])
def test_other_versions_refused(tmp_path, version):
    with pytest.raises(ManagerConfigError, match="suportada: 2"):
        load(tmp_path, base(version=version))


def test_database_under_root(tmp_path):
    root = (tmp_path / "srv").resolve()
    assert load(tmp_path, base(database="db/x.db")).database == root / "db" / "x.db"
    assert load(tmp_path, base(database=str(root / "y.db"))).database == root / "y.db"


@pytest.mark.parametrize("database", ["../fora.db", "", ".", "manager/../../fora.db", 7])
def test_database_outside_root_rejected(tmp_path, database):
    with pytest.raises(ManagerConfigError, match="database"):
        load(tmp_path, base(database=database))


def test_database_absolute_outside_root_rejected(tmp_path):
    with pytest.raises(ManagerConfigError, match="fora de root"):
        load(tmp_path, base(database=str((tmp_path / "outro" / "m.db").resolve())))


def _set(path: str, value):
    def mutate(d):
        *parents, leaf = path.split(".")
        node = d
        for k in parents:
            node = node[int(k)] if isinstance(node, list) else node.setdefault(k, {})
        if value is _DELETE:
            node.pop(leaf, None)
        else:
            node[leaf] = value
    return mutate


_DELETE = object()


@pytest.mark.parametrize("mutate, field", [
    (_set("version", 3), "version"),
    (_set("identities", []), "identities"),
    (_set("projects.0.bindings", []), "bindings"),
    (_set("shared_group", _DELETE), "shared_group"),
    (_set("workspace_group", _DELETE), "workspace_group"),
    (_set("workspace_group", "Tsm WS"), "workspace_group"),
    (_set("shared_group", ""), "shared_group"),
    (_set("provisioner", _DELETE), "provisioner"),
    (_set("provisioner.mode", "root"), "mode"),
    (_set("provisioner.extra", 1), "extra"),
    (_set("provisioner.helper", _DELETE), "helper"),
    (_set("provisioner.helper", "relativo/helper"), "helper"),
    (_set("provisioner.sudo", "sudo"), "sudo"),
    (_set("provisioner.timeout_s", 0), "timeout_s"),
    (_set("provisioner.timeout_s", True), "timeout_s"),
    (_set("provisioner.manager_group", "x y"), "manager_group"),
    (_set("ssh", "host"), "ssh"),
    (_set("ssh.host", "a b"), "host"),
    (_set("ssh.host", "-x"), "host"),
    (_set("ssh.host", "a" * 254), "host"),
    (_set("ssh.port", 0), "port"),
    (_set("ssh.port", 70000), "port"),
    (_set("ssh.port", "22"), "port"),
    (_set("ssh.host_key_files", []), "host_key_files"),
    (_set("ssh.host_key_files", ["rel.pub"]), "host_key_files"),
    (_set("ssh.host_key_files", "x"), "host_key_files"),
    (_set("ssh.account_prefix", "tsm-d-"), "account_prefix"),
    (_set("ssh.devices_group", "x;y"), "devices_group"),
    (_set("auth.challenge_ttl_s", 5), "challenge_ttl_s"),
    (_set("auth.challenge_ttl_s", 601), "challenge_ttl_s"),
    (_set("auth.session_ttl_s", 59), "session_ttl_s"),
    (_set("auth.session_ttl_s", 86_401), "session_ttl_s"),
    (_set("auth.invite_ttl_s", 0), "invite_ttl_s"),
    (_set("auth.invite_ttl_max_s", 30 * 86_400 + 1), "invite_ttl_max_s"),
    (_set("auth.pending_ttl_s", 3599), "pending_ttl_s"),
    (_set("auth.pending_ttl_s", "1d"), "pending_ttl_s"),
    (_set("auth.ssh_keygen", "ssh-keygen"), "ssh_keygen"),
    (_set("auth.sshsig_timeout_s", 0), "sshsig_timeout_s"),
    (_set("auth.sshsig_timeout_s", 61), "sshsig_timeout_s"),
    (_set("auth.unknown", 1), "unknown"),
    (_set("database", "../fora.db"), "database"),
    (_set("test_faults", "sim"), "test_faults"),
    (_set("projects", []), "projects"),
    (_set("projects.0.id", "Demo"), "id"),
    (_set("projects.0.limits", {"max_files": 0}), "max_files"),
    (_set("projects.0.rules", {"ignore": ["a,b"]}), "rules"),
    (_set("extra", 1), "extra"),
])
def test_invalid_v2(tmp_path, mutate, field):
    data = copy.deepcopy(full())
    mutate(data)
    with pytest.raises(ManagerConfigError, match=field):
        load(tmp_path, data)


def test_sudo_requires_ssh(tmp_path):
    data = full()
    del data["ssh"]
    with pytest.raises(ManagerConfigError, match="ssh"):
        load(tmp_path, data)


def test_invite_ttl_above_max_rejected(tmp_path):
    data = full()
    data["auth"]["invite_ttl_s"] = data["auth"]["invite_ttl_max_s"] + 1
    with pytest.raises(ManagerConfigError, match="invite_ttl_s"):
        load(tmp_path, data)


def test_duplicate_project_rejected(tmp_path):
    with pytest.raises(ManagerConfigError, match="duplicado"):
        load(tmp_path, base(projects=[{"id": "demo"}, {"id": "demo"}]))


def test_version_2_with_v1_fields_mentions_identity(tmp_path):
    data = base(identities=[{"name": "a", "role": "admin", "token_sha256": "0" * 64}])
    with pytest.raises(ManagerConfigError, match="identities"):
        load(tmp_path, data)
