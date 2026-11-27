"""SU1, SU3, SU5 e parsing do merge-tree: unitários do Manager, sem Git."""

from __future__ import annotations

import json

import pytest

from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager.adapters.git import is_binary
from tsm_manager.auth import authenticate, can_read, owns_binding, token_sha256
from tsm_manager.cli import is_loopback
from tsm_manager.config import (
    BindingConfig,
    Identity,
    Limits,
    ManagerConfigError,
    ProjectConfig,
    load_manager_config,
)
from tsm_manager.validation import (
    RequestError,
    check_project_file,
    parse_publish_request,
    validate_changes,
)

H = "a" * 64


def _project(**kw) -> ProjectConfig:
    return ProjectConfig("demo", kw.get("rules", ProjectRules()), kw.get("limits", Limits()),
                         {"demo-pca": BindingConfig("demo-pca", "pca", "pca")})


def _req(changes, **kw):
    return {"idempotency_key": "k" * 16, "base": {"commit": "b" * 40},
            "rules_digest": rules_digest(ProjectRules()), "changes": changes, **kw}


# ---------------------------------------------------------------- SU1


def test_parse_request_normalizes_and_sorts():
    req = parse_publish_request(_req([
        {"path": "z.lua", "op": "delete"},
        {"path": "a.lua", "op": "put", "sha256": H, "size": 3},
    ]))
    assert [c.path for c in req.changes] == ["a.lua", "z.lua"]
    assert [c.path for c in req.puts] == ["a.lua"] and [c.path for c in req.deletes] == ["z.lua"]


@pytest.mark.parametrize("body", [
    None, [], {},
    _req([]),
    _req([{"path": "a", "op": "move"}]),
    _req([{"path": "a", "op": "put", "sha256": "x", "size": 1}]),
    _req([{"path": "a", "op": "put", "sha256": H, "size": -1}]),
    _req([{"path": "a", "op": "put", "sha256": H, "size": True}]),
    _req([{"path": "a", "op": "delete"}, {"path": "a", "op": "delete"}]),
    _req([{"path": "a", "op": "delete"}], base={"commit": "xyz"}),
    _req([{"path": "a", "op": "delete"}], rules_digest="0"),
    _req([{"path": "a", "op": "delete"}], message="x" * 2001),
])
def test_parse_request_rejects(body):
    with pytest.raises(RequestError):
        parse_publish_request(body)


def test_validate_changes():
    req = parse_publish_request(_req([
        {"path": "data/ok.lua", "op": "put", "sha256": H, "size": 3},
        {"path": "data/CON.lua", "op": "put", "sha256": H, "size": 3},
        {"path": "logs/x.log", "op": "put", "sha256": H, "size": 3},
        {"path": "gone.lua", "op": "delete"},
        {"path": "ts-project.json", "op": "delete"},
    ]))
    issues = {i.path: i.reason for i in validate_changes(req, _project(), {"ts-project.json": "x"})}
    assert "data/ok.lua" not in issues
    assert "reservado" in issues["data/CON.lua"]
    assert "regras" in issues["logs/x.log"]
    assert "não existe na base" in issues["gone.lua"]
    assert "não pode ser excluído" in issues["ts-project.json"]


def test_validate_limits():
    req = parse_publish_request(_req([
        {"path": f"f{i}.lua", "op": "put", "sha256": H, "size": 6} for i in range(3)]))
    issues = validate_changes(req, _project(limits=Limits(max_file_bytes=5, max_files=2,
                                                          max_total_bytes=10)), {})
    reasons = [i.reason for i in issues]
    assert sum("maior que 5" in r for r in reasons) == 3
    assert any("mais de 2" in r for r in reasons)
    assert any("maior que 10" in r for r in reasons)


def test_check_project_file():
    assert check_project_file(b'{"project_id": "demo", "version": 1}', "demo") is None
    assert check_project_file(b"{", "demo")
    assert check_project_file(b'{"project_id": "x"}', "demo")


# ---------------------------------------------------------------- SU3 auth


def _cfg(tmp_path, identities=None, **top):
    data = {
        "version": 1, "root": "srv",
        "projects": [{"id": "demo", "bindings": [
            {"id": "demo-pca", "device": "pca", "workspace": "pca"},
            {"id": "demo-pcb", "device": "pcb", "workspace": "pcb"}]}],
        "identities": identities if identities is not None else [
            {"name": "dev-a", "role": "developer", "device": "pca",
             "token_sha256": token_sha256("tok-a")},
            {"name": "admin", "role": "admin", "token_sha256": token_sha256("tok-admin")},
            {"name": "intruso", "role": "developer", "device": "pcx",
             "token_sha256": token_sha256("tok-x")},
        ],
        **top,
    }
    p = tmp_path / "manager.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return load_manager_config(p)


def test_authenticate(tmp_path):
    cfg = _cfg(tmp_path)
    assert authenticate(cfg, "Bearer tok-a").name == "dev-a"
    assert authenticate(cfg, "Bearer tok-admin").is_admin
    for bad in (None, "", "tok-a", "Bearer ", "Bearer errado", "Basic tok-a"):
        assert authenticate(cfg, bad) is None


def test_authorization(tmp_path):
    cfg = _cfg(tmp_path)
    project = cfg.projects["demo"]
    a = authenticate(cfg, "Bearer tok-a")
    x = authenticate(cfg, "Bearer tok-x")
    admin = authenticate(cfg, "Bearer tok-admin")
    assert can_read(a, project) and can_read(admin, project) and not can_read(x, project)
    assert owns_binding(a, project.bindings["demo-pca"])
    assert not owns_binding(a, project.bindings["demo-pcb"])
    assert not owns_binding(admin, project.bindings["demo-pca"])


def test_loopback_only():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.168.0.10")


# ---------------------------------------------------------------- SU5 config


def test_config_ok(tmp_path):
    cfg = _cfg(tmp_path)
    assert cfg.root == (tmp_path / "srv").resolve()
    assert cfg.projects["demo"].limits == Limits()
    assert set(cfg.projects["demo"].bindings) == {"demo-pca", "demo-pcb"}


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(version=2),
    lambda d: d.update(extra=1),
    lambda d: d["projects"][0].update(id="Demo"),
    lambda d: d["projects"][0]["bindings"].append(
        {"id": "demo-pcc", "device": "pca", "workspace": "pcc"}),
    lambda d: d["projects"][0]["bindings"].append(
        {"id": "demo-pcc", "device": "pcc", "workspace": "pca"}),
    lambda d: d["projects"][0].update(limits={"max_files": 0}),
    lambda d: d["projects"][0].update(rules={"ignore": ["a,b"]}),
    lambda d: d["identities"].append({"name": "x", "role": "root", "token_sha256": "0" * 64}),
    lambda d: d["identities"].append({"name": "x", "role": "admin", "token_sha256": "xyz"}),
    lambda d: d.update(test_faults="sim"),
])
def test_config_invalid(tmp_path, mutate):
    data = {
        "version": 1, "root": "srv",
        "projects": [{"id": "demo", "bindings": [
            {"id": "demo-pca", "device": "pca", "workspace": "pca"}]}],
        "identities": [{"name": "a", "role": "developer", "device": "pca",
                        "token_sha256": "1" * 64}],
    }
    mutate(data)
    p = tmp_path / "m.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ManagerConfigError):
        load_manager_config(p)


def test_is_binary_heuristic():
    assert is_binary(b"a\0b")
    assert not is_binary(b"texto\r\n")
    assert not is_binary(b"x" * 9000 + b"\0")


def test_identity_admin_flag():
    assert Identity("a", "admin", None, H).is_admin
    assert not Identity("a", "developer", "pca", H).is_admin
