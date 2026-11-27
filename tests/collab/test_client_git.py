"""Adaptador git do Client com Git real: diff e merge de três vias sobre bytes."""

from __future__ import annotations

import pytest

from tsm_client.adapters.git import ClientGit, find_git

pytestmark = pytest.mark.integration


@pytest.fixture
def git(tmp_path) -> ClientGit:
    return ClientGit(find_git(), tmp_path / "git-global.cfg")


def test_merge_preserves_crlf_and_bom(git):
    base = "﻿-- título\r\na = 1\r\nb = 2\r\nc = 3\r\nd = 4\r\n".encode()
    ours = base.replace(b"a = 1", b"a = 10")
    theirs = base.replace(b"d = 4", b"d = 40")
    r = git.merge(ours, base, theirs)
    assert r.clean
    assert r.content == base.replace(b"a = 1", b"a = 10").replace(b"d = 4", b"d = 40")
    assert r.content.startswith("﻿".encode()) and b"\r\n" in r.content
    assert b"\n" not in r.content.replace(b"\r\n", b"")


def test_merge_conflict_markers(git):
    r = git.merge(b"x = 1\n", b"x = 0\n", b"x = 2\n")
    assert r.conflicts == 1
    assert r.content.startswith(b"<<<<<<< local\n") and b">>>>>>> " in r.content


def test_diff_keeps_removed_comment_lines(git, tmp_path):
    old = tmp_path / "old.lua"
    new = tmp_path / "new.lua"
    old.write_bytes(b"-- comentario antigo\nlocal a = 1\n")
    new.write_bytes(b"local a = 2\n")
    text = git.diff(old, new, "data/x.lua")
    assert text.splitlines()[:3] == ["diff --tsm data/x.lua", text.splitlines()[1],
                                     "--- base/data/x.lua"]
    assert "--- -- comentario antigo" not in text
    assert "--- comentario antigo" in text  # linha removida "-" + "-- comentario antigo"
    assert "+local a = 2" in text
    added = git.diff(None, new, "n.lua").splitlines()
    assert "--- /dev/null" in added and "+++ local/n.lua" in added
