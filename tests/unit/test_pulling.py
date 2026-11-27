"""Plano de três vias do pull e verificação do cache."""

from __future__ import annotations

import hashlib

import pytest

from tsm_client.adapters.git import MergeOutcome
from tsm_client.objects import ObjectStore
from tsm_client.pulling import (
    DELETE,
    KEEP,
    MARKERS,
    MERGE,
    WRITE,
    CacheNotReady,
    PlanError,
    has_markers,
    plan_pull,
    read_cache,
    wait_cache,
)
from tsm_common.protocol import RevisionInfo
from tsm_common.rules import IgnoreMatcher, ProjectRules, ignore_patterns


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class World:
    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.local: dict[str, bytes] = {}
        self.merges: list[tuple[bytes, bytes, bytes]] = []
        self.merge_result: MergeOutcome | None = None

    def m(self, files: dict[str, bytes]) -> dict[str, str]:
        out = {}
        for p, d in files.items():
            self.blobs[h(d)] = d
            out[p] = h(d)
        return out

    def merger(self, o, b, t):
        self.merges.append((o, b, t))
        return self.merge_result or MergeOutcome(0, o + t)

    def plan(self, base, ours, theirs, resolutions=None):
        self.local = dict(ours)
        return plan_pull(self.m(base), self.m(ours), self.m(theirs),
                         load_base=self.blobs.__getitem__,
                         load_ours=self.local.__getitem__,
                         load_theirs=self.blobs.__getitem__,
                         merger=self.merger, resolutions=resolutions)


def actions(plan):
    return {o.path: o.action for o in plan.ops}


def test_cases_table():
    w = World()
    plan = w.plan(
        base={"same": b"1", "theirs_mod": b"1", "ours_mod": b"1", "theirs_del": b"1",
              "both_same": b"1", "ours_del": b"1"},
        ours={"same": b"1", "theirs_mod": b"1", "ours_mod": b"2", "theirs_del": b"1",
              "both_same": b"9", "new_local": b"n"},
        theirs={"same": b"1", "theirs_mod": b"2", "ours_mod": b"1", "both_same": b"9",
                "new_remote": b"r", "ours_del": b"1"},
    )
    assert actions(plan) == {
        "theirs_mod": WRITE, "ours_mod": KEEP, "theirs_del": DELETE, "new_local": KEEP,
        "new_remote": WRITE, "ours_del": KEEP,
    }
    assert plan.conflicts == [] and not w.merges


def test_text_both_changed_clean_merge():
    w = World()
    w.merge_result = MergeOutcome(0, b"merged")
    plan = w.plan({"f": b"base\n"}, {"f": b"ours\n"}, {"f": b"theirs\n"})
    assert actions(plan) == {"f": MERGE}
    assert plan.ops[0].content == b"merged"
    assert w.merges == [(b"ours\n", b"base\n", b"theirs\n")]


def test_text_conflict_and_resolutions():
    w = World()
    w.merge_result = MergeOutcome(1, b"<<<<<<< local\nx\n=======\ny\n>>>>>>> rev\n")
    plan = w.plan({"f": b"b"}, {"f": b"o"}, {"f": b"t"})
    assert plan.conflicts[0].kind == "content"
    for choice, action in (("ours", KEEP), ("theirs", WRITE), ("markers", MARKERS)):
        p = w.plan({"f": b"b"}, {"f": b"o"}, {"f": b"t"}, {"f": choice})
        assert actions(p) == {"f": action} and not p.conflicts
    assert w.plan({"f": b"b"}, {"f": b"o"}, {"f": b"t"}, {"f": "markers"}).markers == ["f"]


def test_binary_delete_modify_add_add():
    w = World()
    w.merge_result = MergeOutcome(1, b"x")
    plan = w.plan(
        base={"bin": b"\0a", "dm": b"1", "md": b"1"},
        ours={"bin": b"\0b", "dm": b"2", "aa": b"one"},
        theirs={"bin": b"\0c", "md": b"2", "aa": b"two"},
    )
    kinds = {o.path: o.kind for o in plan.conflicts}
    assert kinds == {"bin": "binary", "dm": "delete_modify", "md": "delete_modify",
                     "aa": "add_add"}
    with pytest.raises(PlanError, match="markers"):
        w.plan({"bin": b"\0a"}, {"bin": b"\0b"}, {"bin": b"\0c"}, {"bin": "markers"})
    p = w.plan({"md": b"1"}, {}, {"md": b"2"}, {"md": "theirs"})
    assert actions(p) == {"md": WRITE}
    p = w.plan({"dm": b"1"}, {"dm": b"2"}, {}, {"dm": "theirs"})
    assert actions(p) == {"dm": DELETE}


def test_invalid_resolutions():
    w = World()
    with pytest.raises(PlanError, match="não há conflito"):
        w.plan({"f": b"1"}, {"f": b"1"}, {"f": b"2"}, {"f": "ours"})
    with pytest.raises(PlanError, match="inválida"):
        w.plan({"f": b"1"}, {"f": b"2"}, {"f": b"3"}, {"f": "mine"})


def test_has_markers():
    assert has_markers(b"a\n<<<<<<< local\nb\n=======\nc\n>>>>>>> rev\n")
    assert not has_markers(b"a <<<<<<< b\n")


# ---------------------------------------------------------------- cache


def _cache(tmp_path, files, revision=3, extra=None, info_files=None):
    cache = tmp_path / "cache"
    for rel, data in files.items():
        p = cache / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    info = RevisionInfo("demo", revision, "c" * 40,
                        info_files if info_files is not None else {p: h(d) for p, d in
                                                                   files.items()})
    (cache / ".tsm").mkdir(parents=True, exist_ok=True)
    (cache / ".tsm" / "revision.json").write_text(info.to_json(), encoding="utf-8")
    for rel, data in (extra or {}).items():
        (cache / rel).parent.mkdir(parents=True, exist_ok=True)
        (cache / rel).write_bytes(data)
    return cache


def _matcher():
    return IgnoreMatcher(ignore_patterns(ProjectRules()))


def test_read_cache_ok_and_stores_objects(tmp_path):
    cache = _cache(tmp_path, {"a.lua": b"1", "d/b.lua": b"2"})
    store = ObjectStore(tmp_path / "obj")
    info = read_cache(cache, _matcher(), store)
    assert info.revision == 3
    assert store.read(h(b"1")) == b"1" and store.read(h(b"2")) == b"2"


def test_read_cache_mismatches(tmp_path):
    store = ObjectStore(tmp_path / "obj")
    cache = _cache(tmp_path, {"a.lua": b"1"}, info_files={"a.lua": h(b"novo")})
    with pytest.raises(CacheNotReady, match="difere"):
        read_cache(cache, _matcher(), store)
    cache = _cache(tmp_path / "x", {"a.lua": b"1"}, info_files={"a.lua": h(b"1"),
                                                               "b.lua": h(b"2")})
    with pytest.raises(CacheNotReady, match="ausentes"):
        read_cache(cache, _matcher(), store)
    cache = _cache(tmp_path / "y", {"a.lua": b"1"}, extra={"extra.lua": b"z"})
    with pytest.raises(CacheNotReady, match="fora da revisão"):
        read_cache(cache, _matcher(), store)
    (tmp_path / "z").mkdir()
    with pytest.raises(CacheNotReady, match="ainda não chegou"):
        read_cache(tmp_path / "z", _matcher(), store)


def test_read_cache_ignores_ignored_content(tmp_path):
    cache = _cache(tmp_path, {"a.lua": b"1"}, extra={"logs/x.log": b"log", ".env": b"s"})
    assert read_cache(cache, _matcher(), ObjectStore(tmp_path / "obj")).revision == 3


def test_wait_cache_retries_until_accepted():
    calls = {"n": 0}

    def read():
        calls["n"] += 1
        if calls["n"] < 3:
            raise CacheNotReady("ainda não")
        return RevisionInfo("demo", calls["n"], "c" * 40, {})

    info = wait_cache(read, timeout=5, interval=0.01, accept=lambda i: i.revision >= 4)
    assert info.revision == 4
    with pytest.raises(CacheNotReady):
        wait_cache(lambda: (_ for _ in ()).throw(CacheNotReady("x")), timeout=0.05,
                   interval=0.01)
