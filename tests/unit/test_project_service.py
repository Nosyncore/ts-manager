"""Orquestração do ``ProjectService`` com Git e Store em memória.

Confere a ordem das operações que mudam refs (diário → ``update-ref`` → shared com
``revision.json`` por último → registro idempotente → fim do diário), a recuperação a
partir do diário e os resultados que não passam pelo diário. Os merges reais e o
``update-ref`` atômico ficam com os testes de integração (Git real).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.unit.manager_fakes import FakeBindings, FakeGit, FakeStore
from tsm_common import protocol as P
from tsm_common.protocol import REVISION_FILE, RevisionInfo
from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager import project as project_mod
from tsm_manager.adapters.git import Author
from tsm_manager.config import BindingConfig, Limits, ProjectConfig
from tsm_manager.faults import Faults, SimulatedCrash
from tsm_manager.layout import ProjectLayout
from tsm_manager.project import (
    MAIN,
    ProjectError,
    ProjectService,
    RecoveryError,
    Requester,
    binding_ref,
)

DEMO = REPO_ROOT / "examples" / "demo-project"
SPELLS = "data/scripts/spells.lua"
DEV = Requester("dev-a", "u-dev-a", "pca", False)
ADMIN = Requester("admin", "u-admin", "pc-admin", True)


class Env:
    def __init__(self, tmp_path: Path, *, faults: Faults | None = None) -> None:
        self.events: list[tuple] = []
        self.layout = ProjectLayout(tmp_path / "srv", "demo")
        self.journal_at_update: list[list[dict]] = []
        self.git = FakeGit(self.events, on_update_refs=self._journal_snapshot)
        self.store = FakeStore(self.events)
        self.faults = faults or Faults()
        self.project = ProjectConfig("demo", ProjectRules(), Limits())
        self.bindings = FakeBindings([BindingConfig("demo-pca", "pca", "tsm-d-0123456789ab")])
        self.svc = self.service()

    def service(self) -> ProjectService:
        return ProjectService(self.project, self.layout, git=self.git, store=self.store,
                              bindings=self.bindings, faults=self.faults,
                              lock_timeout=5)

    def _journal_snapshot(self, _updates) -> None:
        self.journal_at_update.append([json.loads(p.read_text("utf-8"))
                                       for p in sorted(self.layout.journal.glob("*.json"))])

    @property
    def binding(self) -> BindingConfig:
        return self.svc.bindings.get("demo-pca")

    def write_workspace(self, rel: str, data: bytes) -> dict:
        p = self.layout.sync_root(self.binding.workspace) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return {"path": rel, "op": "put", "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data)}

    def request(self, changes: list[dict], *, base: str | None = None,
                key: str | None = None) -> dict:
        return {"idempotency_key": key or str(uuid.uuid4()),
                "base": {"commit": base or self.git.resolve(MAIN)},
                "rules_digest": rules_digest(self.project.rules), "changes": changes}

    def kinds(self) -> list[str]:
        return [e[0] for e in self.events]


@pytest.fixture
def env(tmp_path, monkeypatch) -> Env:
    e = Env(tmp_path)
    installs: list[str] = []
    real_install = project_mod.SharedWriter.install

    def spy(writer, tmp, rel):
        e.events.append(("install", rel))
        installs.append(rel)
        return real_install(writer, tmp, rel)

    monkeypatch.setattr(project_mod.SharedWriter, "install", spy)
    out = e.svc.init_project(DEMO)
    assert out.status == P.PUBLISHED and out.payload["revision"] == 1
    e.events.clear()
    return e


def _published_shared(env: Env) -> RevisionInfo:
    return RevisionInfo.from_json((env.layout.shared / REVISION_FILE).read_text("utf-8"))


# ---------------------------------------------------------------- ordem da publicação


def test_publish_order(env):
    change = env.write_workspace(SPELLS, b"mana = 99\n")
    req = env.request([change])
    out = env.svc.publish(DEV, env.binding, req)
    assert out.status == P.PUBLISHED and out.payload["revision"] == 2

    kinds = env.kinds()
    # o diário existia, com os refs da operação, no instante do update-ref
    [journal] = env.journal_at_update[-1]
    assert journal["key"] == req["idempotency_key"] and journal["kind"] == "publish"
    assert [r[0] for r in journal["refs"]] == [MAIN, binding_ref("demo-pca")]
    # update-ref → shared (revision.json por último) → registro → auditoria
    i_ref = kinds.index("update_refs")
    installs = [e[1] for e in env.events if e[0] == "install"]
    assert installs[-1] == REVISION_FILE and SPELLS in installs
    i_rev = env.events.index(("install", REVISION_FILE))
    i_put = kinds.index("put_result")
    assert i_ref < env.events.index(("install", SPELLS)) < i_rev < i_put
    assert kinds.index("set_shared_commit") < i_put < kinds.index("audit")
    assert "put_result" not in kinds[:i_ref]  # nada registrado antes da conclusão
    assert not list(env.layout.journal.glob("*.json"))  # diário encerrado
    assert not list(env.layout.staging.iterdir())
    info = _published_shared(env)
    assert info.revision == 2 and info.commit == env.git.resolve(MAIN)
    assert (env.layout.shared / SPELLS).read_bytes() == b"mana = 99\n"
    assert env.svc.verify() == []


def test_replay_and_mismatch_do_not_touch_git(env):
    req = env.request([env.write_workspace(SPELLS, b"mana = 1\n")])
    first = env.svc.publish(DEV, env.binding, req)
    env.events.clear()
    again = env.svc.publish(DEV, env.binding, req)
    assert again.status == P.PUBLISHED and again.payload["replayed"] is True
    assert again.payload["revision"] == first.payload["revision"]
    other = dict(req, message="outra")
    assert env.svc.publish(DEV, env.binding, other).status == P.IDEMPOTENCY_MISMATCH
    assert "update_refs" not in env.kinds() and "put_result" not in env.kinds()


@pytest.mark.parametrize("case", ["rules", "stale", "mismatch", "no_change", "bad_key",
                                  "bad_body"])
def test_outcomes_without_journal(env, case):
    change = env.write_workspace(SPELLS, b"mana = 5\n")
    req = env.request([change])
    expected = {"rules": P.RULES_MISMATCH, "stale": P.STALE_BASE,
                "mismatch": P.WORKSPACE_MISMATCH, "no_change": P.NO_CHANGE,
                "bad_key": P.REJECTED, "bad_body": P.REJECTED}[case]
    if case == "rules":
        req["rules_digest"] = "0" * 64
    elif case == "stale":
        req["base"]["commit"] = "f" * 40
    elif case == "mismatch":
        req["changes"][0]["sha256"] = "0" * 64
    elif case == "no_change":
        data = (DEMO / SPELLS).read_bytes()
        req = env.request([env.write_workspace(SPELLS, data)])
    elif case == "bad_key":
        req["idempotency_key"] = "x"
    else:
        req = {"changes": "não"}
    out = env.svc.publish(DEV, env.binding, req)
    assert out.status == expected, out.payload
    assert "update_refs" not in env.kinds()
    if case not in ("bad_key", "bad_body"):  # resultado registrado de imediato, sem diário
        assert env.store.get_result(req["idempotency_key"])["result"]["status"] == expected
        assert env.store.audits[-1]["result"] == expected
    assert not list(env.layout.journal.glob("*.json"))


def test_conflict_keeps_refs(env):
    base = env.git.resolve(MAIN)
    env.svc.publish(DEV, env.binding, env.request([env.write_workspace(SPELLS, b"a = 1\n")]))
    main = env.git.resolve(MAIN)
    refs_before = dict(env.git.refs)
    # a publicação seguinte parte da base antiga e muda o mesmo arquivo
    env.git.refs.pop(binding_ref("demo-pca"))  # vínculo sem ref: base antiga é aceita
    refs_before.pop(binding_ref("demo-pca"))
    out = env.svc.publish(DEV, env.binding, env.request(
        [env.write_workspace(SPELLS, b"a = 2\n")], base=base))
    assert out.status == P.CONFLICT and out.payload["conflicts"][0]["path"] == SPELLS
    assert env.git.refs == refs_before and env.git.resolve(MAIN) == main


# ---------------------------------------------------------------- falhas e recuperação


def _crash(env: Env, point: str) -> dict:
    req = env.request([env.write_workspace(SPELLS, b"mana = 7\n"),
                       env.write_workspace("data/extra/x.lua", b"return 1\n")])
    env.faults.crash = point
    with pytest.raises(SimulatedCrash):
        env.svc.publish(DEV, env.binding, req)
    env.faults.crash = None
    return req


def test_crash_before_update_ref_is_discarded(env):
    main = env.git.resolve(MAIN)
    req = _crash(env, "before_update_ref")
    assert env.git.resolve(MAIN) == main and env.store.get_result(req["idempotency_key"]) is None
    assert len(list(env.layout.journal.glob("*.json"))) == 1
    notes = env.service().recover()
    assert any("descartada" in n for n in notes)
    assert env.store.audits[-1]["event"] == "discarded"
    assert not list(env.layout.journal.glob("*.json"))
    out = env.svc.publish(DEV, env.binding, req)  # reenvio publica uma vez
    assert out.status == P.PUBLISHED and out.payload["revision"] == 2


@pytest.mark.parametrize("point", ["during_materialize", "before_record"])
def test_crash_after_update_ref_is_completed(env, point):
    req = _crash(env, point)
    assert env.svc.revision_of(env.git.resolve(MAIN)) == 2
    assert env.store.get_result(req["idempotency_key"]) is None
    restarted = env.service()
    notes = restarted.recover()
    assert any("concluída (r2)" in n for n in notes)
    assert env.store.get_result(req["idempotency_key"])["result"]["revision"] == 2
    assert env.store.audits[-1]["recovered"] is True
    assert _published_shared(env).revision == 2 and restarted.verify() == []
    out = restarted.publish(DEV, env.binding, req)
    assert out.payload["replayed"] is True and out.payload["revision"] == 2


def test_next_publish_recovers_first(env):
    _crash(env, "during_materialize")
    out = env.svc.publish(DEV, env.binding,
                          env.request([env.write_workspace("data/b.lua", b"return 'b'\n")]))
    assert out.status == P.PUBLISHED and out.payload["revision"] == 3
    assert env.svc.verify() == []


def test_journal_with_unexpected_refs_requires_operator(env):
    _crash(env, "before_update_ref")
    env.git.refs[MAIN] = env.git.commit_tree(env.git.tree_of(env.git.resolve(MAIN)),
                                             [env.git.resolve(MAIN)], "x", Author("x", "x@x"))
    with pytest.raises(RecoveryError, match="estado inesperado"):
        env.service().recover()


def test_recover_cleans_temporaries_and_reconciles_shared(env):
    (env.layout.staging / "lixo").mkdir(parents=True)
    (env.layout.tmp / "solto.tmp").write_bytes(b"x")
    (env.layout.shared / "intruso.lua").write_bytes(b"x")
    assert any("intruso" in p for p in env.svc.verify())
    notes = env.svc.recover()
    assert any("reconciliado" in n for n in notes)
    assert not list(env.layout.staging.iterdir()) and not list(env.layout.tmp.iterdir())
    assert env.svc.verify() == []


# ---------------------------------------------------------------- rollback e consultas


def test_rollback_order_and_permissions(env):
    env.svc.publish(DEV, env.binding, env.request([env.write_workspace(SPELLS, b"v2\n")]))
    assert env.svc.rollback(DEV, {}).status == P.FORBIDDEN
    assert env.svc.rollback(ADMIN, None).status == P.REJECTED
    assert env.svc.rollback(ADMIN, {"idempotency_key": "k" * 16, "target": 9}).status \
        == P.NOT_FOUND
    env.events.clear()
    key = "r" * 16
    out = env.svc.rollback(ADMIN, {"idempotency_key": key, "target": 1})
    assert out.status == P.PUBLISHED and out.payload["revision"] == 3
    kinds = env.kinds()
    assert env.journal_at_update[-1][0]["kind"] == "rollback"
    assert kinds.index("update_refs") < env.events.index(("install", REVISION_FILE)) \
        < kinds.index("put_result")
    assert (env.layout.shared / SPELLS).read_bytes() == (DEMO / SPELLS).read_bytes()
    again = env.svc.rollback(ADMIN, {"idempotency_key": key, "target": 1})
    assert again.payload["replayed"] is True
    same = env.svc.rollback(ADMIN, {"idempotency_key": "s" * 16, "target": 3})
    assert same.status == P.NO_CHANGE


def test_queries(env):
    env.svc.publish(DEV, env.binding, env.request([env.write_workspace(SPELLS, b"q\n")],
                                                  key="q" * 16))
    revs = env.svc.revisions()
    assert [r["revision"] for r in revs] == [2, 1]
    assert revs[0]["user"] == "dev-a" and revs[0]["binding"] == "demo-pca"
    detail = env.svc.revision_detail(2)
    assert {"status": "M", "path": SPELLS} in detail["changes"]
    assert env.svc.revision_detail(42) is None
    info = env.svc.info()
    assert info["head"]["revision"] == 2 and info["project_id"] == "demo"
    assert set(env.svc.binding_refs()) == {"demo-pca"}


def test_manifest_cache_uses_parent(env):
    env.svc.publish(DEV, env.binding, env.request([env.write_workspace(SPELLS, b"m\n")]))
    main = env.git.resolve(MAIN)
    env.store.manifests.pop(main)  # força o cálculo a partir do manifesto do pai
    files = env.svc.manifest_of(main)
    assert files[SPELLS] == hashlib.sha256(b"m\n").hexdigest()
    assert env.store.manifests[main] == files


def test_uninitialized_and_double_init(tmp_path):
    e = Env(tmp_path)
    assert not e.svc.initialized
    with pytest.raises(ProjectError, match="não inicializado"):
        e.svc.head()
    assert e.svc.init_project(DEMO).status == P.PUBLISHED
    with pytest.raises(ProjectError, match="já inicializado"):
        e.svc.init_project(DEMO)


def test_init_rejects_source_without_project_file(tmp_path):
    src = tmp_path / "src"
    (src / "data").mkdir(parents=True)
    (src / "data" / "a.lua").write_bytes(b"x")
    e = Env(tmp_path)
    out = e.svc.init_project(src)
    assert out.status == P.REJECTED and not e.git.refs


def test_publish_with_requester_reads_the_tree_workspace(env):
    svc = env.svc
    who = Requester("Fulano <x>", "u-123", "d-456", False)
    data = b"mana = 3\n"
    target = env.layout.sync_root("tsm-d-0123456789ab") / SPELLS
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    change = {"path": SPELLS, "op": "put", "sha256": hashlib.sha256(data).hexdigest(),
              "size": len(data)}
    out = svc.publish(who, svc.bindings.get("demo-pca"), env.request([change]))
    assert out.status == P.PUBLISHED, out.payload
    commit = env.git.commits[out.payload["commit"]]
    assert commit.author_name == "Fulano x"
    assert commit.author_email == "u-123@d-456.tsm"
    assert "TSM-User: Fulano <x>" in commit.message
    assert "TSM-User-Id: u-123" in commit.message and "TSM-Device: d-456" in commit.message
    rev = svc.revisions(1)[0]
    assert rev["user"] == "Fulano <x>" and rev["device"] == "d-456"
    assert svc.rollback(who, {}).status == P.FORBIDDEN

