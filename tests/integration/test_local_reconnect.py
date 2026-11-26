"""Pause/resume e reinício do daemon."""

from __future__ import annotations

import time

import pytest

from tsm_client.adapters.mutagen import Status

from .conftest import filtered

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]


def test_pause_blocks_and_resume_propagates(layout):
    a = layout.a
    ws = layout.workspace("devA")
    a.tsm("up")
    a.wait_watching()
    a.tsm("flush")

    _, out, _ = a.tsm("pause")
    assert out.count("pausada") == 2
    assert all(s.paused for s in a.sessions().values())
    target = a.work / "data" / "scripts" / "spells.lua"
    target.write_text("-- editado com sessão pausada\n", encoding="utf-8")
    time.sleep(3)  # com watch nativo, propagaria em < 1 s se não estivesse pausada
    assert (ws / "data" / "scripts" / "spells.lua").read_text(encoding="utf-8") != (
        "-- editado com sessão pausada\n"
    )
    code, _, err = a.tsm("flush", expect=1)
    assert "SessionCannotSync" in err or "synchronize" in err

    _, out, _ = a.tsm("resume")
    assert out.count("retomada") == 2
    a.wait_watching()
    a.tsm("flush")
    assert filtered(a, ws) == filtered(a, a.work)


def test_up_resumes_paused(layout):
    a = layout.a
    a.tsm("up")
    a.wait_watching()
    a.tsm("pause")
    _, out, _ = a.tsm("up")
    assert out.count("resumed") == 2
    a.wait_watching()


def test_sessions_survive_daemon_restart(layout):
    a, b = layout.a, layout.b
    ws = layout.workspace("devA")
    for pc in (a, b):
        pc.tsm("up")
        pc.wait_watching()
    ids_before = {r: s.identifier for r, s in a.sessions().items()}

    a.adapter.daemon_stop()
    assert not a.adapter.daemon_running()
    assert b.adapter.daemon_running()  # daemons isolados coexistem
    target = a.work / "data" / "scripts" / "spells.lua"
    target.write_text("-- editado com daemon parado\n", encoding="utf-8")

    a.adapter.daemon_start()  # sem 'tsm up': as sessões devem voltar sozinhas
    a.wait_watching(timeout=90)
    assert {r: s.identifier for r, s in a.sessions().items()} == ids_before
    a.tsm("flush")
    assert (ws / "data" / "scripts" / "spells.lua").read_text(encoding="utf-8") == (
        "-- editado com daemon parado\n"
    )
    _, out, _ = a.tsm("up")
    assert out.count("unchanged") == 2
    assert all(s.status is Status.WATCHING for s in b.sessions().values())
