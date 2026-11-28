"""Comandos de colaboração da CLI com serviço falso (códigos de saída e saída)."""

from __future__ import annotations

import io

import pytest

from tests.transport_config import BindingSpec, transport_config
from tsm_client.adapters.manager import ManagerUnavailable, Response
from tsm_client.cli import (
    EXIT_CONFIG,
    EXIT_CONFLICT,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_UNAVAILABLE,
    run,
)
from tsm_client.collab import PublishReport, PullReport
from tsm_client.pulling import CONFLICT, WRITE, CacheNotReady, PullOp, PullPlan
from tsm_client.service import RefusedError


class FakeCollab:
    def __init__(self):
        self.calls = []
        self.publish_result = PublishReport("published", {"revision": 2}, [{"path": "a",
                                                                            "op": "put"}])
        self.pull_result = PullReport("updated", 3, PullPlan([PullOp("a", WRITE, "1", "1",
                                                                     "2")]))
        self.raise_on = {}

    def _maybe_raise(self, name):
        if name in self.raise_on:
            raise self.raise_on[name]

    def publish(self, paths, **kw):
        self.calls.append(("publish", paths, kw))
        self._maybe_raise("publish")
        return self.publish_result

    def pull(self, **kw):
        self.calls.append(("pull", kw))
        self._maybe_raise("pull")
        return self.pull_result

    def history(self, limit, binding):
        return [{"revision": 2, "date": "2026-11-26T10:00:00+00:00", "kind": "publish",
                 "user": "dev-a", "device": "pca", "message": "m", "rollback_to": None}]

    def rollback(self, number, message, binding):
        self.calls.append(("rollback", number))
        return Response(403, {"status": "forbidden", "message": "rollback exige admin"})


@pytest.fixture
def env(tmp_path):
    cfg = transport_config(tmp_path, device_id="pca", data_directory="m",
                           executable=tmp_path / "m.exe",
                           bindings=[BindingSpec("demo-pca", "w", "c", "srv/ws", "srv/sh")])
    fake = FakeCollab()

    def call(*args):
        out, err = io.StringIO(), io.StringIO()
        code = run(list(args), config=cfg, service_factory=lambda c: object(),
                   collab_factory=lambda c, s: fake, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    return fake, call


def test_publish_requires_paths_or_all(env):
    fake, call = env
    assert call("publish")[0] == EXIT_CONFIG
    assert call("publish", "a", "--all")[0] == EXIT_CONFIG
    code, out, _ = call("publish", "--all", "-m", "msg")
    assert code == EXIT_OK and "publicado: r2" in out
    assert fake.calls[-1] == ("publish", None, {"message": "msg", "dry_run": False,
                                                "confirm_deletions": False, "resume": False,
                                                "binding_id": None})
    call("publish", "data\\x.lua")
    assert fake.calls[-1][1] == ["data\\x.lua"]


@pytest.mark.parametrize(("status", "code"), [
    ("conflict", EXIT_CONFLICT), ("rejected", EXIT_REFUSED), ("stale_base", EXIT_REFUSED),
    ("busy", EXIT_UNAVAILABLE), ("no_change", EXIT_OK)])
def test_publish_status_codes(env, status, code):
    fake, call = env
    fake.publish_result = PublishReport(status, {"message": "x", "conflicts": [
        {"path": "a", "kind": "content"}], "errors": [{"path": "a", "reason": "r"}]}, [])
    assert call("publish", "--all")[0] == code


def test_publish_unavailable_mentions_resume(env):
    fake, call = env
    fake.raise_on["publish"] = ManagerUnavailable("caiu")
    code, _, err = call("publish", "--all")
    assert code == EXIT_UNAVAILABLE and "--resume" in err


def test_pull_resolve_parsing_and_codes(env):
    fake, call = env
    code, out, _ = call("pull", "--resolve", "data\\a.lua=ours", "--resolve", "b=c=theirs")
    assert code == EXIT_OK and "atualizado para r3" in out
    assert fake.calls[-1][1]["resolutions"] == {"data/a.lua": "ours", "b=c": "theirs"}
    assert call("pull", "--resolve", "semigual")[0] == EXIT_CONFIG
    fake.pull_result = PullReport("blocked", 3, PullPlan([PullOp("a", CONFLICT, "1", "2", "3",
                                                                 kind="content")]))
    code, _, err = call("pull")
    assert code == EXIT_CONFLICT and "conflito (content): a" in err
    fake.raise_on["pull"] = CacheNotReady("ainda não")
    assert call("pull")[0] == EXIT_UNAVAILABLE
    fake.raise_on["pull"] = RefusedError("pendente")
    assert call("pull")[0] == EXIT_REFUSED


def test_history_and_rollback(env):
    _fake, call = env
    code, out, _ = call("history")
    assert code == EXIT_OK and out.startswith("r2") and "dev-a@pca" in out
    code, _, err = call("rollback", "r1", "--confirm")
    assert code == EXIT_REFUSED and "admin" in err
    assert call("rollback", "xx", "--confirm")[0] == EXIT_CONFIG
