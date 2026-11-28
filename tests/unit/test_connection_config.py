"""Configuração de conexão entregue ao dispositivo e chaves de host do servidor."""

from __future__ import annotations

import pytest

from tests.unit.identity_fakes import fake_key
from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager.config import Limits, ProjectConfig, SshConfig
from tsm_manager.connection import HostKeyError, connection_config, load_host_keys
from tsm_manager.db.repository import Binding, Device
from tsm_manager.layout import ProjectLayout

KEY_A = fake_key(1)
KEY_B = fake_key(2)


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_host_keys_are_normalized_and_deduplicated(tmp_path):
    a = write(tmp_path, "a.pub", f"{KEY_A} root@vm\n")
    b = write(tmp_path, "b.pub", f"\n{KEY_B}\n\n")
    again = write(tmp_path, "c.pub", f"{KEY_A} outro-comentario\n")
    assert load_host_keys([a, b, again]) == (KEY_A, KEY_B)


@pytest.mark.parametrize("text, reason", [
    ("", "vazio"),
    ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== x\n", "ssh-ed25519"),
    (f"{KEY_A}\n{KEY_B}\n", "uma linha"),
    ("lixo\n", "ssh-ed25519"),
    ("x" * 20_000, "grande"),
])
def test_invalid_host_key_files(tmp_path, text, reason):
    p = write(tmp_path, "k.pub", text)
    with pytest.raises(HostKeyError, match=reason):
        load_host_keys([p])


def test_missing_host_key_file(tmp_path):
    with pytest.raises(HostKeyError, match="ilegível"):
        load_host_keys([tmp_path / "nada.pub"])


def test_no_host_key_files():
    with pytest.raises(HostKeyError, match="nenhuma"):
        load_host_keys([])


def _device(account="tsm-d-0123456789ab"):
    return Device("d-1", "u-1", "pc", KEY_A, "SHA256:x", "active", account, "inv", "t")


def test_ssh_payload(tmp_path):
    layout = ProjectLayout(tmp_path / "srv", "demo")
    rules = ProjectRules.from_dict({"allow": ["data/"], "ignore": ["*.bak"]})
    project = ProjectConfig("demo", rules, Limits())
    binding = Binding("b-1", "demo", "d-1", "tsm-d-0123456789ab", "t")
    out = connection_config(server_id="srv-1", project=project, layout=layout,
                            binding=binding, device=_device(),
                            ssh=SshConfig("ts.example.net", 2222, (), "tsm-devices"),
                            host_keys=(KEY_A,), workspace_group="tsm-ws", transport="ssh")
    assert out == {
        "server_id": "srv-1", "project_id": "demo", "binding_id": "b-1", "device_id": "d-1",
        "transport": "ssh",
        "ssh": {"host": "ts.example.net", "port": 2222, "user": "tsm-d-0123456789ab",
                "host_keys": [KEY_A]},
        "paths": {"workspace": str(layout.sync_root("tsm-d-0123456789ab")),
                  "shared": str(layout.shared)},
        "workspace_group": "tsm-ws",
        "rules": {"allow": ["data/"], "ignore": ["*.bak"]},
        "rules_digest": rules_digest(rules),
    }


def test_local_payload_has_no_ssh(tmp_path):
    layout = ProjectLayout(tmp_path / "srv", "demo")
    project = ProjectConfig("demo", ProjectRules(), Limits())
    binding = Binding("b-1", "demo", "d-1", "tsm-d-0123456789ab", "t")
    out = connection_config(server_id="s", project=project, layout=layout, binding=binding,
                            device=_device(), ssh=SshConfig("h", 22, (), "g"),
                            host_keys=(KEY_A,), workspace_group="tsm-ws", transport="local")
    assert out["transport"] == "local" and out["ssh"] is None
    assert out["paths"]["workspace"].endswith("tree")


def test_unknown_transport_rejected(tmp_path):
    with pytest.raises(ValueError):
        connection_config(server_id="s", project=ProjectConfig("demo", ProjectRules(),
                                                                Limits()),
                          layout=ProjectLayout(tmp_path, "demo"),
                          binding=Binding("b", "demo", "d", "tsm-d-0123456789ab", "t"),
                          device=_device(), ssh=None, host_keys=(), workspace_group="g",
                          transport="ftp")


def test_ssh_transport_requires_ssh_settings(tmp_path):
    with pytest.raises(ValueError):
        connection_config(server_id="s", project=ProjectConfig("demo", ProjectRules(),
                                                                Limits()),
                          layout=ProjectLayout(tmp_path, "demo"),
                          binding=Binding("b", "demo", "d", "tsm-d-0123456789ab", "t"),
                          device=_device(), ssh=None, host_keys=(), workspace_group="g",
                          transport="ssh")
