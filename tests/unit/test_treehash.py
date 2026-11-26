import hashlib
import os
import subprocess
import sys

import pytest

from tsm_client.rules import IgnoreMatcher
from tsm_client.treehash import DIR, manifest, tree_digest


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    (root / "data" / "scripts").mkdir(parents=True)
    (root / "data" / "scripts" / "a.lua").write_bytes(b"print(1)\n")
    (root / "empty").mkdir()
    (root / "x.tmp").write_bytes(b"tmp")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_bytes(b"ref")
    return root


def test_manifest_contents(tree):
    m = manifest(tree)
    assert m["data"] == DIR and m["empty"] == DIR
    assert m["data/scripts/a.lua"] == hashlib.sha256(b"print(1)\n").hexdigest()
    assert ".git/HEAD" in m


def test_manifest_deterministic(tree):
    assert manifest(tree) == manifest(tree)
    assert tree_digest(manifest(tree)) == tree_digest(manifest(tree))
    assert list(manifest(tree)) == sorted(manifest(tree))


def test_manifest_with_matcher_excludes(tree):
    m = manifest(tree, IgnoreMatcher(["*.tmp"]))
    assert "x.tmp" not in m
    assert ".git" not in m and ".git/HEAD" not in m
    assert "data/scripts/a.lua" in m


def test_digest_changes_with_content(tree):
    before = tree_digest(manifest(tree))
    (tree / "data" / "scripts" / "a.lua").write_bytes(b"print(2)\n")
    assert tree_digest(manifest(tree)) != before


def test_missing_root_gives_empty_manifest(tmp_path):
    assert manifest(tmp_path / "nope") == {}


@pytest.mark.skipif(sys.platform != "win32", reason="junction só existe no Windows")
def test_links_skipped_by_default_and_recorded_on_request(tree, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"s")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(tree / "j"), str(outside)], check=True,
                   capture_output=True)
    assert not any(k.startswith("j") for k in manifest(tree))
    recorded = manifest(tree, include_links=True)
    assert recorded["j"].startswith("link:")
    assert "j/secret.txt" not in recorded


def test_file_symlink_skipped(tree):
    try:
        os.symlink(tree / "x.tmp", tree / "l.txt")
    except OSError as exc:
        pytest.skip(f"sem privilégio para symlink: {exc}")
    assert "l.txt" not in manifest(tree)
