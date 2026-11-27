"""Validação da /connection/config e golden da config SSH e do known_hosts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.conftest import FIXTURES
from tests.unit.client_fakes import DEVICE_ID, SERVER_ID, fake_key
from tsm_client.home import Home
from tsm_client.paths import Endpoint
from tsm_client.sshconfig import (
    HEADER,
    ConnectionConfigError,
    parse_connection,
    render_known_hosts,
    render_ssh_config,
    write_ssh_files,
)
from tsm_common.rules import ProjectRules, rules_digest

B1 = "b-0123456789abcdef0123"
B2 = "b-fedcba9876543210fedc"
GOLDEN = FIXTURES / "client"


def data(binding: str = B1, *, transport: str = "ssh", host: Any = "ts.example.net",
         port: Any = 22, user: Any = "tsm-d-0123456789ab", keys: Any = None,
         workspace: Any = None, shared: Any = "/srv/ts/projects/demo/shared",
         group: Any = "tsm-ws", rules: Any = None, **over: Any) -> dict[str, Any]:
    rules = rules if rules is not None else {"allow": ["data/"], "ignore": ["*.bak"]}
    d = {"server_id": SERVER_ID, "project_id": "demo", "binding_id": binding,
         "device_id": DEVICE_ID, "transport": transport,
         "ssh": {"host": host, "port": port, "user": user,
                 "host_keys": keys if keys is not None else [fake_key(900)]},
         "paths": {"workspace": workspace or f"/srv/ts/projects/demo/workspaces/{user}/tree",
                   "shared": shared},
         "workspace_group": group, "rules": rules,
         "rules_digest": rules_digest(ProjectRules.from_dict(rules))}
    if transport == "local":
        d["ssh"] = None
    d.update(over)
    return d


def parse(d: dict[str, Any]):
    return parse_connection(d, server_id=SERVER_ID, device_id=DEVICE_ID, project_id="demo")


def two():
    a = parse(data())
    b = parse(data(B2, host="192.0.2.10", port=2222, user="tsm-d-ba9876543210",
                   keys=[fake_key(901), fake_key(902), fake_key(901) + " comentário"]))
    return [b, a]  # ordem de entrada não importa


def test_golden_two_bindings():
    conns = two()
    assert render_ssh_config(conns) == (GOLDEN / "ssh_config_two_bindings").read_text("utf-8")
    assert render_known_hosts(conns) == (GOLDEN / "known_hosts_two_bindings").read_text(
        "utf-8")


def test_local_transport_has_no_ssh_entry(tmp_path):
    ws, sh = tmp_path / "ws" / "tree", tmp_path / "shared"
    c = parse(data(transport="local", workspace=str(ws), shared=str(sh)))
    assert render_ssh_config([c]) == HEADER
    assert render_known_hosts([c]) == ""
    workspace, shared = c.endpoints()
    assert workspace == Endpoint(None, str(ws)) and shared == Endpoint(None, str(sh))
    b = c.binding(str(tmp_path / "work"), str(tmp_path / "cache"))
    assert b.workspace_group is None


def test_ssh_binding_endpoints(tmp_path):
    c = parse(data())
    b = c.binding(str(tmp_path / "work"), str(tmp_path / "cache"))
    assert b.workspace == Endpoint(f"tsm-{B1}",
                                   "/srv/ts/projects/demo/workspaces/tsm-d-0123456789ab/tree")
    assert b.shared.host == f"tsm-{B1}" and b.workspace_group == "tsm-ws"
    assert b.rules.allow == ("data/",)


def test_write_files(tmp_path):
    home = Home(tmp_path)
    write_ssh_files(home, two())
    assert home.ssh_config.read_bytes() == (GOLDEN / "ssh_config_two_bindings").read_bytes()
    write_ssh_files(home, [])  # reescreve inteiro
    assert home.ssh_config.read_text("utf-8") == HEADER and home.known_hosts.read_text() == ""


@pytest.mark.parametrize("over", [
    {"server_id": "outro"},
    {"device_id": "outro"},
    {"project_id": "outro"},
    {"binding_id": "B-MAIUSC"},
    {"binding_id": "b x"},
    {"transport": "ftp"},
    {"workspace_group": "Grupo"},
    {"workspace_group": "g;rm"},
    {"rules_digest": "0" * 64},
    {"rules": {"allow": "tudo"}},
    {"ssh": None},
    {"paths": None},
])
def test_refused_fields(over):
    d = data()
    d.update(over)
    with pytest.raises(ConnectionConfigError):
        parse(d)


@pytest.mark.parametrize("kw", [
    {"host": "evil\n  ProxyCommand calc"},
    {"host": "a b"},
    {"host": "h%h"},
    {"host": '"h"'},
    {"host": ""},
    {"host": "-oProxyCommand=x"},
    {"host": "x" * 254},
    {"port": 0}, {"port": 65536}, {"port": "22"}, {"port": True},
    {"user": "root"}, {"user": "tsm-d-XYZ"}, {"user": "tsm-d-0123456789ab\n"},
    {"keys": []},
    {"keys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"]},
    {"keys": ["command=\"x\" " + fake_key(900)]},
    {"workspace": "relativo/tree"},
    {"workspace": "/srv/../etc"},
    {"shared": "C:\\x"},
])
def test_refused_ssh_values(kw):
    with pytest.raises(ConnectionConfigError):
        parse(data(**kw))


def test_accepts_ip_literals():
    assert parse(data(host="::1")).host == "::1"
    assert parse(data(host="10.0.0.7")).host == "10.0.0.7"


def test_local_transport_refuses_remote_paths_and_ssh_block(tmp_path):
    with pytest.raises(ConnectionConfigError):
        parse(data(transport="local", workspace="/srv/ts/x", shared=str(tmp_path)))
    d = data(transport="local", workspace=str(tmp_path / "w"), shared=str(tmp_path / "s"))
    d["ssh"] = {"host": "x"}
    with pytest.raises(ConnectionConfigError, match="local"):
        parse(d)


def test_not_an_object():
    with pytest.raises(ConnectionConfigError):
        parse_connection([], server_id=SERVER_ID, device_id=DEVICE_ID)


def test_golden_files_exist():
    assert Path(GOLDEN / "ssh_config_two_bindings").is_file()
