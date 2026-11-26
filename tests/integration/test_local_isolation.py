"""Isolamento A/B, demo do shared por cópia manual, idempotência e sessões alheias."""

from __future__ import annotations

import shutil

import pytest

from tsm_client.adapters.mutagen import MutagenAdapter
from tsm_client.treehash import manifest

from .conftest import _outside_snapshot, filtered

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]


def write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def up_both(layout):
    for pc in (layout.a, layout.b):
        pc.tsm("up")
    for pc in (layout.a, layout.b):
        pc.wait_watching()


def test_same_path_different_content_stays_isolated(layout):
    up_both(layout)
    a, b = layout.a, layout.b
    shared_before = manifest(layout.shared)
    caches_before = (manifest(a.cache), manifest(b.cache))
    rel = ("data", "scripts", "spells.lua")
    a.work.joinpath(*rel).write_text("-- versão de A\n", encoding="utf-8")
    b.work.joinpath(*rel).write_text("-- versão de B\n", encoding="utf-8")
    write(a.work / "data" / "novo.lua", "return 'A'\n")
    write(b.work / "data" / "novo.lua", "return 'B'\n")
    a.tsm("flush")
    b.tsm("flush")

    ws_a, ws_b = layout.workspace("devA"), layout.workspace("devB")
    assert ws_a.joinpath(*rel).read_text(encoding="utf-8") == "-- versão de A\n"
    assert ws_b.joinpath(*rel).read_text(encoding="utf-8") == "-- versão de B\n"
    assert (ws_a / "data" / "novo.lua").read_text(encoding="utf-8") == "return 'A'\n"
    assert (ws_b / "data" / "novo.lua").read_text(encoding="utf-8") == "return 'B'\n"
    assert filtered(a, ws_a) == filtered(a, a.work)
    assert filtered(b, ws_b) == filtered(b, b.work)
    assert manifest(layout.shared) == shared_before
    assert (manifest(a.cache), manifest(b.cache)) == caches_before


def test_demo_manual_copy_to_shared_reaches_caches_not_work(layout):
    """Demonstração apenas: copiar o workspace A para o shared NÃO é publicação."""
    up_both(layout)
    a, b = layout.a, layout.b
    (a.work / "data" / "scripts" / "spells.lua").write_text("-- publicado (demo)\n",
                                                             encoding="utf-8")
    write(a.work / "data" / "scripts" / "items.lua", "return {}\n")
    a.tsm("flush", "--role", "upload")
    work_before = (manifest(a.work), manifest(b.work))

    shutil.copytree(layout.workspace("devA") / "data", layout.shared / "data",
                    dirs_exist_ok=True)
    a.tsm("flush", "--role", "download")
    b.tsm("flush", "--role", "download")

    assert manifest(a.cache) == manifest(layout.shared)
    assert manifest(b.cache) == manifest(layout.shared)
    assert (b.cache / "data" / "scripts" / "items.lua").is_file()
    assert (manifest(a.work), manifest(b.work)) == work_before


def test_guard_detects_outside_changes(layout):
    """Sanidade da restrição global: uma alteração em sentinela é detectada."""
    before = _outside_snapshot(layout.root, layout.mutable_roots())
    sentinel = layout.sentinel / "secret.txt"
    original = sentinel.read_bytes()
    sentinel.write_bytes(original + b"x")
    try:
        assert _outside_snapshot(layout.root, layout.mutable_roots()) != before
    finally:
        sentinel.write_bytes(original)
    assert _outside_snapshot(layout.root, layout.mutable_roots()) == before


def test_idempotent_up_and_foreign_session_survives_teardown(layout):
    a = layout.a
    alien_root = layout.root / "alien"
    layout.extra_roots.append(alien_root)
    write(alien_root / "src" / "f.txt", "alheio\n")
    (alien_root / "dst").mkdir()

    a.tsm("up")
    a.wait_watching()
    adapter: MutagenAdapter = a.adapter
    # sessão "alheia": mesmo daemon, sem labels, criada fora do Client (mesmo nome de uma nossa)
    res = adapter.runner(
        [str(adapter.executable), "sync", "create", "--no-global-configuration",
         "--name=tsm-demo-pca-up", str(alien_root / "src"), str(alien_root / "dst")],
        timeout=60,
    )
    assert res.returncode == 0, res.stderr

    _, out, _ = a.tsm("up")
    assert out.count("unchanged") == 2
    all_sessions = adapter.list_sessions(label_selector=None)
    assert len(all_sessions) == 3
    assert len(a.service.managed_sessions()) == 2

    a.tsm("pause")
    alien = [s for s in adapter.list_sessions(label_selector=None) if not s.labels]
    assert len(alien) == 1 and not alien[0].paused

    a.tsm("teardown")
    remaining = adapter.list_sessions(label_selector=None)
    assert [s.identifier for s in remaining] == [alien[0].identifier]
    assert a.service.managed_sessions() == []


def test_up_refuses_foreign_session_writing_into_local_folder(layout):
    a = layout.a
    alien_root = layout.root / "alien"
    layout.extra_roots.append(alien_root)
    write(alien_root / "src" / "f.txt", "alheio\n")
    a.adapter.daemon_start()
    adapter = a.adapter
    res = adapter.runner(
        [str(adapter.executable), "sync", "create", "--no-global-configuration", "--paused",
         "--name=alheia", str(alien_root / "src"), str(a.cache / "sub")],
        timeout=60,
    )
    assert res.returncode == 0, res.stderr
    code, _, err = a.tsm("up", expect=2)
    assert "sobreposição" in err and "alheia" in err
    assert a.service.managed_sessions() == []
