"""Unitários de ``tsm_common``: protocolo, escrita atômica, lock e regras."""

from __future__ import annotations

import json
import threading
import time

import pytest

from tsm_client.rules import local_patterns, sync_flags
from tsm_common.fsutil import LockTimeout, atomic_write_json, file_lock, read_json
from tsm_common.protocol import RevisionFormatError, RevisionInfo
from tsm_common.rules import ProjectRules, rules_digest


def test_revision_roundtrip():
    info = RevisionInfo("demo", 3, "a" * 40, {"b.lua": "1" * 64, "a.lua": "2" * 64})
    back = RevisionInfo.from_json(info.to_json())
    assert back == info
    data = json.loads(info.to_json())
    assert list(data["files"]) == ["a.lua", "b.lua"]


@pytest.mark.parametrize("text", [
    "nada", "[]", '{"format": 2}',
    '{"format": 1, "project_id": "d", "revision": 1, "commit": "x", "files": {}, '
    '"tree_digest": "errado"}',
    '{"format": 1, "project_id": "d", "commit": "x", "files": {}}',
])
def test_revision_invalid(text):
    with pytest.raises(RevisionFormatError):
        RevisionInfo.from_json(text)


def test_atomic_write_json(tmp_path):
    p = tmp_path / "x" / "y.json"
    atomic_write_json(p, {"b": 1, "a": [1, 2]})
    assert read_json(p) == {"a": [1, 2], "b": 1}
    atomic_write_json(p, {"c": 3})
    assert read_json(p) == {"c": 3}
    assert [x.name for x in p.parent.iterdir()] == ["y.json"]


def test_file_lock_excludes_threads(tmp_path):
    lock = tmp_path / "lock"
    events = []

    def worker(n):
        with file_lock(lock, timeout=10):
            events.append(("in", n))
            time.sleep(0.05)
            events.append(("out", n))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for i in range(0, len(events), 2):
        assert events[i][0] == "in" and events[i + 1] == ("out", events[i][1])


def test_file_lock_timeout(tmp_path):
    lock = tmp_path / "lock"
    holding = threading.Event()
    release = threading.Event()

    def holder():
        with file_lock(lock):
            holding.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    holding.wait(5)
    with pytest.raises(LockTimeout), file_lock(lock, timeout=0.2):
        pass
    release.set()
    t.join()


def test_rules_digest_changes_with_rules():
    assert rules_digest(ProjectRules()) != rules_digest(ProjectRules(ignore=("*.bak",)))
    assert rules_digest(ProjectRules(allow=("data/",))) == rules_digest(
        ProjectRules(allow=("data/",)))


def test_tsm_reserved_flags_by_role():
    up = sync_flags(ProjectRules(), role="upload")
    assert up[-1] == "--ignore=/.tsm/"
    down = sync_flags(ProjectRules(), role="download")
    assert not any(".tsm" in f for f in down)  # sem lista de permitidos, .tsm já desce
    down_allow = sync_flags(ProjectRules(allow=("data/",)), role="download")
    assert down_allow[-1] == "--ignore=!/.tsm/"
    assert local_patterns(ProjectRules())[-1] == "/.tsm/"
