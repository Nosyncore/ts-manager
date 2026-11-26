"""Ignores (inclui .git real) e lista de permitidos."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from tsm_client.rules import ProjectRules
from tsm_client.treehash import manifest

from .conftest import filtered

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]

IGNORED = {
    ".env": "SECRET=1\n",
    "logs/a.log": "log\n",
    "build/x": "bin\n",
    "data/scripts/x.tmp": "tmp\n",
    "__pycache__/m.pyc": "pyc\n",
    "data/.env.local": "SECRET=2\n",
}


def write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=tsm-test", "-c", "user.email=tsm-test@example.invalid",
         "-c", "init.defaultBranch=main", "-c", "core.autocrlf=false", *args],
        cwd=cwd, check=True, capture_output=True,
    )


def test_ignored_never_reach_workspace_and_are_never_touched(layout):
    a = layout.a
    ws = layout.workspace("devA")
    git(a.work, "init")
    git(a.work, "add", "-A")
    git(a.work, "commit", "-m", "base")
    for rel, text in IGNORED.items():
        write(a.work / rel, text)
    # ignorados preexistentes no workspace
    write(ws / ".env", "SEGREDO-DO-SERVIDOR\n")
    write(ws / "logs" / "server.log", "log do servidor\n")
    local_ignored_before = manifest(a.work / ".git") | {
        rel: manifest(a.work)[rel] for rel in IGNORED
    }

    a.tsm("up")
    a.wait_watching()
    a.tsm("flush")
    # mais um commit real depois da subida
    write(a.work / "data" / "scripts" / "spells.lua", "-- v2\n")
    git(a.work, "commit", "-am", "v2")
    a.tsm("flush", "--role", "upload")

    ws_manifest = manifest(ws)
    assert not any(k == ".git" or k.startswith(".git/") for k in ws_manifest)
    for rel in IGNORED:
        if rel in (".env",):
            continue
        assert rel not in ws_manifest, rel
    assert "build" not in ws_manifest and "__pycache__" not in ws_manifest
    # ignorados preexistentes no beta não são apagados
    assert (ws / ".env").read_text(encoding="utf-8") == "SEGREDO-DO-SERVIDOR\n"
    assert (ws / "logs" / "server.log").is_file()
    # ignorados locais nunca são tocados
    after = manifest(a.work)
    for rel in IGNORED:
        assert after[rel] == local_ignored_before[rel]
    assert manifest(a.work / ".git") != {}
    # o restante converge
    assert filtered(a, ws) == filtered(a, a.work)


def test_deleting_dir_whose_beta_copy_holds_ignored_content(layout, record_property):
    """Registra o comportamento: diretório apagado localmente com ignorado só no beta."""
    a = layout.a
    ws = layout.workspace("devA")
    a.tsm("up")
    a.wait_watching()
    write(a.work / "data" / "tmpdir" / "x.lua", "return 1\n")
    a.tsm("flush", "--role", "upload")
    write(ws / "data" / "tmpdir" / "server.tmp", "ignorado, só no beta\n")
    shutil.rmtree(a.work / "data" / "tmpdir")
    a.tsm("flush", "--role", "upload")
    up = a.sessions()["upload"]

    remaining = sorted(p.relative_to(ws).as_posix() for p in (ws / "data").rglob("*"))
    problems = [(p.path, p.error) for p in up.problems]
    record_property("dir_with_ignored_remaining", remaining)
    record_property("dir_with_ignored_problems", problems)
    print(f"\nL4 (registro): restante={remaining} problemas={problems} status={up.raw_status}")

    record_property("dir_with_ignored_conflicts", up.conflicts)
    print(f"conflitos registrados: {up.conflicts}")
    # Comportamento observado (v0.18.1): o conteúdo não rastreado (ignorado) no beta
    # impede a remoção do diretório; o Mutagen reporta conflito e mantém o diretório
    # inteiro, inclusive o x.lua que já não existe no alpha. O ignorado não é apagado.
    assert (ws / "data" / "tmpdir" / "server.tmp").is_file()
    assert (ws / "data" / "tmpdir" / "x.lua").exists()
    assert up.conflicts >= 1
    assert up.status.value == "watching"
    _, out, _ = a.tsm("status")
    assert "conflito" in out


def test_allow_list(layout_factory):
    layout = layout_factory(ProjectRules(allow=("data/",)))
    a = layout.a
    write(a.work / "notes.txt", "fora da lista\n")
    write(a.work / "tools" / "gen.py", "print(1)\n")
    write(a.work / "data" / "scripts" / "new.lua", "return 2\n")
    write(a.work / "data" / "scripts" / "y.tmp", "tmp\n")
    a.tsm("up")
    a.wait_watching()
    a.tsm("flush")

    ws = manifest(layout.workspace("devA"))
    top = {k.split("/")[0] for k in ws}
    assert top == {"ts-project.json", "data"}
    assert "data/scripts/new.lua" in ws
    assert "data/scripts/y.tmp" not in ws
    assert ws == filtered(a, a.work)
    cache = manifest(a.cache)
    assert {k.split("/")[0] for k in cache} == {"ts-project.json", "data"}
    assert cache == filtered(a, layout.shared)
