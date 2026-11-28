"""SU1, SU3 e parsing do merge-tree: unitários do Manager, sem Git."""

from __future__ import annotations

import pytest

from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager.adapters.git import is_binary
from tsm_manager.cli import is_loopback
from tsm_manager.config import Limits, ProjectConfig
from tsm_manager.validation import (
    RequestError,
    check_project_file,
    parse_publish_request,
    validate_changes,
)

H = "a" * 64


def _project(**kw) -> ProjectConfig:
    return ProjectConfig("demo", kw.get("rules", ProjectRules()), kw.get("limits", Limits()))


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


# ---------------------------------------------------------------- SU3


def test_loopback_only():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.168.0.10")


def test_is_binary_heuristic():
    assert is_binary(b"a\0b")
    assert not is_binary(b"texto\r\n")
    assert not is_binary(b"x" * 9000 + b"\0")

