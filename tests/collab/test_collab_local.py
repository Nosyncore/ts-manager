"""Colaboração local com Mutagen, Git, HTTP e identidade reais.

Os PCs se cadastram pelo ``tsm enroll`` e se vinculam pelo ``tsm bind``, que inicializa a
pasta (o ``init`` da colaboração); daí em diante os comandos são os mesmos de sempre.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time

import pytest

from tests.collab.conftest import CREATURES, DEMO, SPELLS, Collab, tree_hash
from tsm_client.objects import ObjectStore
from tsm_client.pulling import CacheNotReady, read_cache
from tsm_common.manifest import files_only, manifest
from tsm_common.rules import IgnoreMatcher, ProjectRules, ignore_patterns

pytestmark = [pytest.mark.integration, pytest.mark.timeout(300)]


def demo_tree() -> dict[str, bytes]:
    return {p.relative_to(DEMO).as_posix(): p.read_bytes() for p in DEMO.rglob("*")
            if p.is_file()}


def work_tree(pc) -> dict[str, bytes]:
    m = files_only(manifest(pc.work, IgnoreMatcher(ignore_patterns(ProjectRules()))))
    return {p: (pc.work / p).read_bytes() for p in m}


# ----------------------------------------------------------------


def test_init(collab: Collab):
    a = collab.a
    code, out, err = a.bind()
    assert "inicializado em r1" in out
    assert work_tree(a) == demo_tree()
    st = a.state()
    assert st["base_revision"] == 1 and st["pending_publish"] is None
    assert not (a.work / ".tsm").exists()
    _code, out, _ = a.tsm("status")
    assert "base r1" in out and "Manager em r1" in out
    assert f"tsm-{a.binding}-up" in out and "watching" in out
    # pasta não vazia é recusada; init repetido também
    collab.b.work.mkdir(parents=True)
    (collab.b.work / "x.txt").write_text("x")
    collab.b.bind(expect=3)
    a.tsm("init", expect=3)


# ----------------------------------------------------------------


def test_distinct_files(ready: Collab):
    a, b = ready.a, ready.b
    a.edit(SPELLS, b"mana = 20", b"mana = 21")
    b.edit(CREATURES, b"health = 20", b"health = 22")
    _, out, _ = a.tsm("changes")
    assert f"modified  {SPELLS}" in out
    _, out, _ = a.tsm("publish", "--all", "-m", "mana")
    assert "publicado: r2" in out
    _, out, _ = b.tsm("publish", CREATURES)
    assert "publicado: r3" in out
    a.tsm("pull")
    b.tsm("pull")
    for pc in (a, b):
        assert b"mana = 21" in pc.read(SPELLS) and b"health = 22" in pc.read(CREATURES)
        assert pc.state()["base_revision"] == 3
    assert work_tree(a) == work_tree(b) == ready.main_files()
    _, out, _ = a.tsm("history")
    assert out.splitlines()[0].startswith("r3") and f"dev-b@{b.device_id}" in out
    _, out, _ = a.tsm("show", "r2")
    assert f"M {SPELLS}" in out
    ready.verify()


def test_same_file_non_adjacent(ready: Collab):
    a, b = ready.a, ready.b
    a.edit(SPELLS, b'words = "utevo lux"', b'words = "utevo gran lux"')
    b.edit(SPELLS, b'words = "exori flam"', b'words = "exori vis"')
    a.tsm("publish", SPELLS)
    b.tsm("publish", SPELLS)
    a.tsm("pull")
    _, out, _ = b.tsm("pull")
    for pc in (a, b):
        data = pc.read(SPELLS)
        assert b"utevo gran lux" in data and b"exori vis" in data
        assert b"\r\n" in data  # bytes preservados (CRLF da demo)
    assert a.read(SPELLS) == ready.main_files()[SPELLS]


def test_same_line_conflict_and_markers(ready: Collab):
    a, b = ready.a, ready.b
    a.edit(SPELLS, b"level = 15", b"level = 16")
    b.edit(SPELLS, b"level = 15", b"level = 17")
    a.tsm("publish", SPELLS)
    before_b = b.read(SPELLS)
    code, _out, err = b.tsm("publish", SPELLS, expect=4)
    assert "conflito (content)" in err
    assert b.read(SPELLS) == before_b and b.state()["pending_publish"] is None
    # pull também bloqueia, sem mexer em nada
    code, _out, err = b.tsm("pull", expect=4)
    assert "conflito (content)" in err and b.read(SPELLS) == before_b
    # resolução com marcadores
    b.tsm("pull", "--resolve", f"{SPELLS}=markers")
    data = b.read(SPELLS)
    assert b"<<<<<<< local" in data and b">>>>>>> " in data
    assert b.state()["markers"] == [SPELLS]
    code, _, err = b.tsm("publish", SPELLS, expect=3)
    assert "marcadores" in err
    # edita, resolve e publica
    lines = [ln for ln in data.split(b"\r\n") if not ln.startswith((b"<<<<<<<", b"=======",
                                                                     b">>>>>>>"))]
    resolved = b"\r\n".join(ln for ln in lines if b"level = 16" not in ln)
    b.write(SPELLS, resolved)
    _, out, _ = b.tsm("publish", SPELLS)
    assert "publicado: r3" in out
    assert b.state()["markers"] == []
    a.tsm("pull")
    assert b"level = 17" in a.read(SPELLS) and b"level = 16" not in a.read(SPELLS)
    ready.verify()


def test_resolve_theirs_keeps_preimage(ready: Collab):
    a, b = ready.a, ready.b
    a.edit(SPELLS, b"level = 15", b"level = 16")
    b.edit(SPELLS, b"level = 15", b"level = 17")
    mine = b.read(SPELLS)
    a.tsm("publish", SPELLS)
    b.tsm("pull", "--resolve", f"{SPELLS}=theirs")
    assert b.read(SPELLS) == a.read(SPELLS)
    rec = json.loads(sorted((b.state_dir / "bindings" / b.binding / "pulls")
                            .glob("*.json"))[-1].read_text("utf-8"))
    pre = next(o["preimage"] for o in rec["ops"] if o["path"] == SPELLS)
    assert ObjectStore(b.state_dir / "objects").read(pre) == mine


def test_pull_preserves_unpublished_change(ready: Collab):
    a, b = ready.a, ready.b
    a.edit(SPELLS, b"mana = 25", b"mana = 26")  # não publicado
    a.write("data/notes.lua", "-- rascunho local\n")  # novo, não publicado
    b.edit(SPELLS, b"mana = 40", b"mana = 41")
    b.write("data/new.lua", "return 'b'\n")
    b.tsm("publish", "--all")
    _, out, _ = a.tsm("pull")
    assert "merge" in out
    data = a.read(SPELLS)
    assert b"mana = 26" in data and b"mana = 41" in data
    assert a.read("data/notes.lua") == b"-- rascunho local\n"
    assert a.read("data/new.lua") == b"return 'b'\n"
    _, out, _ = a.tsm("changes")
    assert "added     data/notes.lua" in out and SPELLS in out
    a.tsm("publish", "--all")
    b.tsm("pull")
    assert b"mana = 26" in b.read(SPELLS) and b.read("data/notes.lua")


# ----------------------------------------------------------------


def test_offline_manager_and_paused_upload(ready: Collab):
    a = ready.a
    a.edit(SPELLS, b"mana = 20", b"mana = 60")
    ready.manager.stop()
    code, _out, err = a.tsm("publish", SPELLS, expect=5)
    assert "pendente" in err
    assert a.state()["pending_publish"] is not None
    a.tsm("changes")  # offline continua funcionando
    a.tsm("publish", SPELLS, expect=3)  # nova publicação recusada enquanto há pendência
    a.tsm("pull", expect=3)
    ready.manager.start()
    _, out, _ = a.tsm("publish", "--resume")
    assert "publicado: r2" in out
    assert a.state()["pending_publish"] is None
    # upload pausado: recusa antes de enviar, sem pendência
    a.edit(SPELLS, b"mana = 25", b"mana = 27")
    a.tsm("pause")
    a.tsm("publish", SPELLS, expect=3)
    assert a.state()["pending_publish"] is None
    a.tsm("resume")
    _, out, _ = a.tsm("publish", SPELLS)
    assert "publicado: r3" in out


def test_pull_during_materialization(collab: Collab):
    collab.manager.restart({"delay_per_file": 0.6})
    for pc in collab.pcs.values():
        pc.bind("--wait", "90")
    a, b = collab.a, collab.b
    for i in range(8):
        b.write(f"data/many/f{i}.lua", f"return {i}\n")
    observed = {"ok": [], "not_ready": 0}
    stop = threading.Event()
    matcher = IgnoreMatcher(ignore_patterns(ProjectRules()))
    store = ObjectStore(collab.root / "probe-objects")

    def probe():
        while not stop.is_set():
            try:
                observed["ok"].append(read_cache(a.cache, matcher, store).revision)
            except CacheNotReady:
                observed["not_ready"] += 1
            time.sleep(0.05)

    t = threading.Thread(target=probe)
    t.start()
    pub = threading.Thread(target=lambda: b.tsm("publish", "--all"))
    pub.start()
    time.sleep(2.0)  # main já avançou; a materialização está em curso
    _, out, _ = a.tsm("pull", "--wait", "90")
    pub.join()
    stop.set()
    t.join()
    assert "atualizado para r2" in out
    assert all(a.read(f"data/many/f{i}.lua") == f"return {i}\n".encode() for i in range(8))
    assert set(observed["ok"]) <= {1, 2}  # só revisões completas são aceitas
    assert observed["not_ready"] > 0  # o cache passou por estados mistos
    collab.manager.restart()


def test_interrupted_pull_converges(ready: Collab):
    a, b = ready.a, ready.b
    for i in range(4):
        b.write(f"data/p/f{i}.lua", f"return {i}\n")
    b.edit(SPELLS, b"mana = 20", b"mana = 88")
    b.tsm("publish", "--all")
    svc = a.collab()
    svc.faults = {"crash": "mid_pull"}
    with pytest.raises(KeyboardInterrupt):
        svc.pull(wait=60)
    assert a.state()["base_revision"] == 1  # base não avançou
    applied = [i for i in range(4) if (a.work / f"data/p/f{i}.lua").exists()]
    assert 0 < len(applied) + (b"mana = 88" in a.read(SPELLS)) < 5
    _, out, _ = a.tsm("pull")
    assert "atualizado para r2" in out
    assert work_tree(a) == ready.main_files()


def test_interrupted_after_send(ready: Collab):
    a = ready.a
    a.edit(SPELLS, b"mana = 20", b"mana = 70")
    svc = a.collab()
    svc.faults = {"crash": "after_send"}
    with pytest.raises(KeyboardInterrupt):
        svc.publish([SPELLS])
    assert a.state()["pending_publish"] is not None
    _, out, _ = a.tsm("publish", "--resume")
    assert "publicado: r2" in out
    _, out, _ = a.tsm("history")
    assert len(out.strip().splitlines()) == 2  # uma única revisão nova


# ----------------------------------------------------------------


def test_rollback(ready: Collab):
    a, b = ready.a, ready.b
    a.edit(SPELLS, b"mana = 20", b"mana = 99")
    a.tsm("publish", SPELLS)
    b.tsm("pull")
    b.edit(CREATURES, b"health = 20", b"health = 23")  # local, não publicado
    _, _, err = a.tsm("rollback", "r1", "--confirm", expect=3)  # dev não é admin
    assert "forbidden" in err
    _, _, err = a.tsm("audit", "--limit", "5", expect=3)  # auditoria também é só do admin
    assert "HTTP 403" in err
    _, out, _ = ready.admin("rollback", "r1", "--confirm", "-m", "volta")
    assert "rollback: r3" in out
    _, out, _ = b.tsm("pull")
    assert b"mana = 20" in b.read(SPELLS)
    assert b"health = 23" in b.read(CREATURES)  # mudança local preservada
    _, out, _ = ready.admin("audit", "--limit", "5")
    assert "rollback" in out
    _, out, _ = a.tsm("history")
    assert "→ r1" in out.splitlines()[0]
    ready.verify()


def test_ignored_in_workspace(ready: Collab):
    a = ready.a
    a.write("data/extra/x.lua", "return 1\n")
    a.tsm("publish", "data/extra/x.lua")
    # conteúdo ignorado no workspace impede o Mutagen de remover o diretório
    ws_extra = ready.a.workspace / "data" / "extra"
    (ws_extra / "debug.log").write_text("log no workspace\n")
    (a.work / "data" / "extra" / "x.lua").unlink()
    (a.work / "data" / "extra").rmdir()
    a.tsm("flush", "--role", "upload")
    assert (ws_extra / "x.lua").exists()  # o arquivo apagado continua no workspace
    _, out, _ = a.tsm("publish", "data/extra")
    assert "publicado" in out
    assert "data/extra/x.lua" not in ready.main_files()


def test_mass_deletions_need_confirmation(ready: Collab):
    a = ready.a
    for i in range(12):
        a.write(f"data/bulk/f{i}.lua", "x")
    a.tsm("publish", "data/bulk")
    for i in range(12):
        (a.work / f"data/bulk/f{i}.lua").unlink()
    _code, _, err = a.tsm("publish", "data/bulk", expect=3)
    assert "--confirm-deletions" in err
    a.tsm("publish", "data/bulk", "--confirm-deletions")
    # o pull que apagaria muitos arquivos locais também pede confirmação
    b = ready.b
    for i in range(12):
        b.write(f"data/bulk2/f{i}.lua", "y")
    b.tsm("publish", "data/bulk2")
    a.tsm("pull")
    for i in range(12):
        (b.work / f"data/bulk2/f{i}.lua").unlink()
    b.tsm("publish", "data/bulk2", "--confirm-deletions")
    a.tsm("pull", expect=3)
    a.tsm("pull", "--confirm-deletions")
    assert not (a.work / "data" / "bulk2").exists()


def test_local_git_untouched(ready: Collab):
    a, b = ready.a, ready.b
    git = ["git", "-C", str(a.work)]
    env_cfg = ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "core.autocrlf=false"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, *env_cfg, "add", "-A"], check=True)
    subprocess.run([*git, *env_cfg, "commit", "-qm", "local"], check=True)
    before = tree_hash(a.work / ".git")
    a.edit(SPELLS, b"mana = 20", b"mana = 1")
    a.tsm("publish", SPELLS)
    b.edit(CREATURES, b"health = 20", b"health = 2")
    b.tsm("publish", CREATURES)
    a.tsm("pull")
    assert tree_hash(a.work / ".git") == before
    assert not (ready.a.workspace / ".git").exists()
    assert ".git/HEAD" not in ready.main_files()


def test_same_content_is_no_change(ready: Collab):
    a, b = ready.a, ready.b
    a.edit(SPELLS, b"mana = 20", b"mana = 33")
    b.edit(SPELLS, b"mana = 20", b"mana = 33")
    a.tsm("publish", SPELLS)
    _, out, _ = b.tsm("publish", SPELLS)
    assert "sem mudança" in out
    _, out, _ = b.tsm("pull")
    assert b.state()["base_revision"] == 2
    _, out, _ = a.tsm("history")
    assert len(out.strip().splitlines()) == 2
