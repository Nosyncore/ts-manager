"""Salvaguardas de raiz em one-way-replica e tratamento de links."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from tsm_client.adapters.mutagen import Status
from tsm_client.treehash import manifest

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]


def _empty_dir(path) -> None:
    for entry in path.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def _start(pc):
    pc.tsm("up")
    pc.wait_watching()
    pc.tsm("flush")


def test_emptied_work_halts_and_workspace_survives(layout):
    a = layout.a
    ws = layout.workspace("devA")
    _start(a)
    ws_before = manifest(ws)
    assert ws_before

    _empty_dir(a.work)
    s = a.wait_status("upload", lambda s: s.status.halted, what="halt por raiz esvaziada")
    assert s.status is Status.HALTED_ON_ROOT_EMPTIED
    assert manifest(ws) == ws_before

    code, _, err = a.tsm("resume", expect=3)
    assert "--confirm-halted" in err
    a.tsm("flush", "--role", "upload", expect=1)
    _, out, _ = a.tsm("status")
    assert "halted-on-root-emptied" in out and "salvaguarda" in out
    assert manifest(ws) == ws_before


def test_deleted_root_halts(layout):
    b = layout.b
    ws = layout.workspace("devB")
    _start(b)
    ws_before = manifest(ws)

    shutil.rmtree(b.work)
    s = b.wait_status("upload", lambda s: s.status.halted, what="halt por raiz apagada")
    assert s.status is Status.HALTED_ON_ROOT_DELETION
    assert manifest(ws) == ws_before
    b.tsm("resume", expect=3)
    # a pasta é recriada para a checagem global de temporários
    b.work.mkdir()


def test_emptied_cache_halts(layout):
    a = layout.a
    _start(a)
    shared_before = manifest(layout.shared)

    _empty_dir(a.cache)
    s = a.wait_status("download", lambda s: s.status.halted, what="halt por cache esvaziado")
    assert s.status.halted
    print(f"\nL8 (registro): cache esvaziado -> {s.raw_status}")
    assert manifest(layout.shared) == shared_before
    a.tsm("resume", expect=3)


def test_confirm_halted_resumes(layout):
    """Com --confirm-halted a retomada é tentada; com a raiz restaurada, volta a watching."""
    a = layout.a
    _start(a)
    backup = {p.relative_to(a.work): p.read_bytes() for p in a.work.rglob("*") if p.is_file()}
    _empty_dir(a.work)
    a.wait_status("upload", lambda s: s.status.halted)
    for rel, data in backup.items():
        (a.work / rel).parent.mkdir(parents=True, exist_ok=True)
        (a.work / rel).write_bytes(data)
    a.tsm("resume", "--confirm-halted")
    a.wait_watching()


@pytest.mark.skipif(sys.platform != "win32", reason="junction só existe no Windows")
def test_junction_to_sentinel_is_not_followed(layout):
    a = layout.a
    ws = layout.workspace("devA")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(a.work / "data" / "link"),
                    str(layout.sentinel)], check=True, capture_output=True)
    _start(a)
    write_marker = a.work / "data" / "scripts" / "after.lua"
    write_marker.write_text("return 1\n", encoding="utf-8")
    a.tsm("flush", "--role", "upload")
    assert (ws / "data" / "scripts" / "after.lua").is_file()
    assert not (ws / "data" / "link").exists()
    assert not any("secret" in k for k in manifest(ws))
    s = a.sessions()["upload"]
    print(f"\nL9 (registro): junction -> problemas={[(p.path, p.error) for p in s.problems]}")
    os.rmdir(a.work / "data" / "link")  # remove só a junction


def test_file_symlink(layout):
    a = layout.a
    ws = layout.workspace("devA")
    try:
        os.symlink(layout.sentinel / "secret.txt", a.work / "data" / "secret-link.txt")
    except OSError as exc:
        pytest.skip(f"symlink de arquivo exige privilégio no Windows: {exc}")
    _start(a)
    assert not (ws / "data" / "secret-link.txt").exists()
