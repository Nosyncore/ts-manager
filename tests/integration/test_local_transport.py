"""Subida, upload + flush, exclusões e réplica (Mutagen real, local)."""

from __future__ import annotations

import shutil

import pytest

from tsm_client.treehash import manifest

from .conftest import Layout, filtered

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]


def write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def up_both(layout: Layout) -> None:
    for pc in (layout.a, layout.b):
        pc.tsm("up")
    for pc in (layout.a, layout.b):
        pc.wait_watching()
        pc.tsm("flush")


def test_up_two_pcs_initial_state(layout):
    up_both(layout)
    a, b = layout.a, layout.b
    assert set(a.sessions()) == {"upload", "download"}
    assert set(b.sessions()) == {"upload", "download"}
    assert a.sessions()["upload"].mode == "one-way-replica"
    assert a.sessions()["download"].mode == "one-way-replica"
    assert filtered(a, layout.workspace("devA")) == filtered(a, a.work)
    assert filtered(b, layout.workspace("devB")) == filtered(b, b.work)
    assert manifest(a.cache) == manifest(layout.shared)
    assert manifest(b.cache) == manifest(layout.shared)
    assert "ts-project.json" in manifest(layout.workspace("devA"))


def test_upload_flush_reaches_only_own_workspace(layout):
    up_both(layout)
    a = layout.a
    before = {
        "ws_b": manifest(layout.workspace("devB")),
        "shared": manifest(layout.shared),
        "cache_a": manifest(a.cache),
        "cache_b": manifest(layout.b.cache),
        "work_b": manifest(layout.b.work),
    }
    spells = a.work / "data" / "scripts" / "spells.lua"
    spells.write_text(spells.read_text(encoding="utf-8") + "-- editado em A\n", encoding="utf-8")
    write(a.work / "data" / "scripts" / "items.lua", "return { 'sword' }\n")
    a.tsm("flush", "--role", "upload")

    assert filtered(a, layout.workspace("devA")) == filtered(a, a.work)
    assert manifest(layout.workspace("devB")) == before["ws_b"]
    assert manifest(layout.shared) == before["shared"]
    assert manifest(a.cache) == before["cache_a"]
    assert manifest(layout.b.cache) == before["cache_b"]
    assert manifest(layout.b.work) == before["work_b"]


def test_flush_then_compare_20_iterations(layout):
    """Após ``flush`` (sem --skip-wait), o beta é igual ao alpha filtrado."""
    up_both(layout)
    a = layout.a
    target = a.work / "data" / "scripts" / "creatures.lua"
    mismatches = []
    for i in range(20):
        target.write_text(f"-- iteração {i}\nreturn {i}\n", encoding="utf-8")
        write(a.work / "data" / "gen" / f"f{i}.lua", f"return {i}\n")
        if i % 3 == 2:
            (a.work / "data" / "gen" / f"f{i - 1}.lua").unlink()
        a.tsm("flush", "--role", "upload")
        if filtered(a, layout.workspace("devA")) != filtered(a, a.work):
            mismatches.append(i)
    assert mismatches == []


def test_deletions_and_replica(layout):
    up_both(layout)
    a = layout.a
    ws = layout.workspace("devA")
    shared_before = manifest(layout.shared)

    # arquivo e diretório apagados em A somem só no workspace A
    write(a.work / "data" / "tmpdir" / "x.lua", "return 'x'\n")
    a.tsm("flush", "--role", "upload")
    assert (ws / "data" / "tmpdir" / "x.lua").is_file()
    (a.work / "data" / "scripts" / "creatures.lua").unlink()
    shutil.rmtree(a.work / "data" / "tmpdir")
    a.tsm("flush", "--role", "upload")
    assert not (ws / "data" / "scripts" / "creatures.lua").exists()
    assert not (ws / "data" / "tmpdir").exists()
    assert (layout.workspace("devB") / "data" / "scripts" / "creatures.lua").is_file()
    assert (a.cache / "data" / "scripts" / "creatures.lua").is_file()

    # arquivo criado direto no workspace é removido (réplica); alterado é revertido
    work_before = manifest(a.work)
    write(ws / "intruso.lua", "return 'não deveria ficar'\n")
    (ws / "data" / "scripts" / "spells.lua").write_text("-- adulterado\n", encoding="utf-8")
    a.tsm("flush", "--role", "upload")
    assert not (ws / "intruso.lua").exists()
    assert filtered(a, ws) == filtered(a, a.work)
    assert manifest(a.work) == work_before  # o alpha nunca muda por ação da sessão

    # cache editado ou com arquivo apagado é restaurado a partir do shared
    (a.cache / "data" / "scripts" / "spells.lua").write_text("-- lixo\n", encoding="utf-8")
    (a.cache / "README.md").unlink()
    write(a.cache / "extra.txt", "extra\n")
    a.tsm("flush", "--role", "download")
    assert manifest(a.cache) == manifest(layout.shared)
    assert manifest(layout.shared) == shared_before
    assert manifest(a.work) == work_before
