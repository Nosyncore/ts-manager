"""Publicação no Manager com Git real."""

from __future__ import annotations

import multiprocessing
import uuid
from pathlib import Path

import pytest

from tests.manager.conftest import (
    DEV_A,
    Dev,
    assert_shared_is_main,
    demo_files,
    dev,
    main_files,
    make_project,
    refs,
    sha,
)
from tsm_common.rules import ProjectRules
from tsm_manager.config import Limits

pytestmark = pytest.mark.integration

SPELLS = "data/scripts/spells.lua"
CREATURES = "data/scripts/creatures.lua"


def edit(d: Dev, rel: str, old: bytes, new: bytes) -> None:
    data = d.files[rel]
    assert old in data, (rel, old)
    d.write(rel, data.replace(old, new, 1))


# ----------------------------------------------------------------


def test_distinct_files_merge_cleanly(svc, a, b):
    edit(a, SPELLS, b"mana = 20", b"mana = 21")
    edit(b, CREATURES, b"health = 20", b"health = 22")
    ra = a.publish([SPELLS])
    rb = b.publish([CREATURES])
    assert (ra.status, rb.status) == ("published", "published")
    assert (ra.payload["revision"], rb.payload["revision"]) == (2, 3)
    files = main_files(svc)
    assert b"mana = 21" in files[SPELLS] and b"health = 22" in files[CREATURES]
    info = assert_shared_is_main(svc)
    assert info.revision == 3
    # vínculos: cada um aponta para o próprio commit, ancestral de main
    bindings = svc.binding_refs()
    assert bindings == {"demo-pca": ra.payload["commit"], "demo-pcb": rb.payload["commit"]}


def test_same_file_non_adjacent_lines(svc, a, b):
    edit(a, SPELLS, b'words = "utevo lux"', b'words = "utevo gran lux"')
    edit(b, SPELLS, b'words = "exori flam"', b'words = "exori vis"')
    assert a.publish([SPELLS]).status == "published"
    assert b.publish([SPELLS]).status == "published"
    merged = main_files(svc)[SPELLS]
    assert b"utevo gran lux" in merged and b"exori vis" in merged
    assert_shared_is_main(svc)


def test_same_line_conflict_changes_nothing(svc, a, b):
    edit(a, SPELLS, b"level = 15", b"level = 16")
    edit(b, SPELLS, b"level = 15", b"level = 17")
    assert a.publish([SPELLS]).status == "published"
    before_refs, before_main = refs(svc), main_files(svc)
    before_ws_b = dict(b.files)
    out = b.publish([SPELLS])
    assert out.status == "conflict"
    assert out.http_status == 409
    assert out.payload["conflicts"] == [{"path": SPELLS, "kind": "content"}]
    assert refs(svc) == before_refs  # nenhum ref muda
    assert main_files(svc) == before_main
    assert b.files == before_ws_b
    assert_shared_is_main(svc)
    events = [e for e in svc.store.read_audit() if e["event"] == "publish"]
    assert events[0]["result"] == "conflict"


def test_repeated_self_publication_has_no_self_conflict(svc, a):
    for value in (b"30", b"31", b"32"):
        edit(a, SPELLS, b"mana = " + (a.files[SPELLS].split(b"mana = ")[1][:2]),
             b"mana = " + value)
        out = a.publish([SPELLS])
        assert out.status == "published", out.payload
    assert b"mana = 32" in main_files(svc)[SPELLS]
    assert assert_shared_is_main(svc).revision == 4


def test_selective_publication(svc, a, b):
    edit(a, SPELLS, b"mana = 20", b"mana = 99")
    edit(a, CREATURES, b"health = 70", b"health = 71")
    assert a.publish([SPELLS]).status == "published"
    files = main_files(svc)
    assert b"mana = 99" in files[SPELLS]
    assert b"health = 70" in files[CREATURES]  # não selecionado: fica pendente
    # o restante publica depois, a partir da nova base, sem conflito
    assert a.publish([CREATURES]).status == "published"
    assert b"health = 71" in main_files(svc)[CREATURES]


# ----------------------------------------------------------------


def test_binary_delete_modify_add_add(svc, a, b):
    a.write("data/map.bin", b"\0\1\2base")
    assert a.publish(["data/map.bin"]).status == "published"
    b.pull()
    a.pull()
    a.write("data/map.bin", b"\0\1\2AAAA")
    b.write("data/map.bin", b"\0\1\2BBBB")
    assert a.publish(["data/map.bin"]).status == "published"
    assert b.publish(["data/map.bin"]).payload["conflicts"] == [
        {"path": "data/map.bin", "kind": "binary"}]

    # exclusão × modificação
    a.pull()
    b.pull()
    edit(a, CREATURES, b"health = 25", b"health = 26")
    b.delete(CREATURES)
    assert a.publish([CREATURES]).status == "published"
    assert b.publish(deletes=[CREATURES]).payload["conflicts"] == [
        {"path": CREATURES, "kind": "delete_modify"}]

    # criação × criação com conteúdos diferentes
    a.pull()
    b.pull()
    a.write("data/new.lua", b"return 1\n")
    b.write("data/new.lua", b"return 2\n")
    assert a.publish(["data/new.lua"]).status == "published"
    assert b.publish(["data/new.lua"]).payload["conflicts"] == [
        {"path": "data/new.lua", "kind": "add_add"}]
    assert_shared_is_main(svc)


def test_rename_is_delete_plus_add(svc, a, b):
    # A renomeia; B altera o original: sem inferência de renomeação → conflito
    a.write("data/scripts/magic.lua", a.files[SPELLS])
    a.delete(SPELLS)
    edit(b, SPELLS, b"mana = 20", b"mana = 23")
    assert a.publish(["data/scripts/magic.lua"], [SPELLS]).status == "published"
    out = b.publish([SPELLS])
    assert out.status == "conflict"
    assert out.payload["conflicts"] == [{"path": SPELLS, "kind": "delete_modify"}]
    files = main_files(svc)
    assert SPELLS not in files and "data/scripts/magic.lua" in files


# ----------------------------------------------------------------


def test_workspace_changed_after_manifest(svc, a):
    edit(a, SPELLS, b"mana = 20", b"mana = 50")
    req = a.request([SPELLS])
    # o arquivo muda no workspace depois do manifesto (flush não é snapshot)
    (a.workspace / SPELLS).write_bytes(a.files[SPELLS] + b"-- extra\n")
    before = refs(svc)
    out = svc.publish(a.identity, a.binding, req)
    assert out.status == "workspace_mismatch"
    assert out.payload["paths"][0]["path"] == SPELLS
    assert refs(svc) == before
    assert not any(svc.layout.staging.iterdir())
    # ausente no workspace também diverge
    req2 = a.request([SPELLS])
    (a.workspace / SPELLS).unlink()
    assert svc.publish(a.identity, a.binding, req2).status == "workspace_mismatch"


@pytest.mark.parametrize(("path", "fragment"), [
    ("data/CON.lua", "reservado"),
    ("data/aux", "reservado"),
    ("data/a:b.lua", "inválido"),
    ("data/x. ", "ponto ou espaço"),
    ("../x.lua", "'..'"),
    (".tsm/revision.json", "reservado"),
    ("logs/a.log", "regras do projeto"),
    (".env", "regras do projeto"),
])
def test_path_policy(svc, a, path, fragment):
    a.files[path] = b"x"
    req = a.request([path])
    out = svc.publish(a.identity, a.binding, req)
    assert out.status == "rejected", out.payload
    assert out.http_status == 422
    assert fragment in out.payload["errors"][0]["reason"]
    assert assert_shared_is_main(svc).revision == 1


def test_case_collision_with_shared(svc, a):
    a.write("data/scripts/Spells.lua", b"-- outra\n")
    out = a.publish(["data/scripts/Spells.lua"])
    assert out.status == "rejected"
    assert "colide" in out.payload["errors"][0]["reason"]


def test_project_file_rules(svc, a):
    out = a.publish(deletes=["ts-project.json"])
    assert out.status == "rejected"
    a.write("ts-project.json", b'{"project_id": "outro", "version": 1}')
    assert a.publish(["ts-project.json"]).status == "rejected"


def test_limits(tmp_path):
    svc = make_project(tmp_path, limits=Limits(max_file_bytes=10, max_files=2,
                                               max_total_bytes=15))
    d = dev(svc, "a")
    d.write("data/big.lua", b"x" * 11)
    assert "maior que 10" in d.publish(["data/big.lua"]).payload["errors"][0]["reason"]
    d.write("data/a.lua", b"x" * 8)
    d.write("data/b.lua", b"x" * 8)
    reasons = [e["reason"] for e in d.publish(["data/a.lua", "data/b.lua"]).payload["errors"]]
    assert any("maior que 15" in r for r in reasons)
    d.write("data/c.lua", b"x")
    reasons = [e["reason"] for e in d.publish(["data/a.lua", "data/c.lua", SPELLS]).payload[
        "errors"]]
    assert any("mais de 2" in r for r in reasons)


def test_allow_list_enforced(tmp_path):
    svc = make_project(tmp_path, rules=ProjectRules(allow=("data/",)))
    d = dev(svc, "a")
    d.write("notes.txt", b"fora da lista")
    assert d.publish(["notes.txt"]).status == "rejected"
    # README.md da demo não entrou na r1 por estar fora da lista de permitidos
    assert "README.md" not in main_files(svc)


def test_rules_digest_mismatch(svc, a):
    edit(a, SPELLS, b"mana = 20", b"mana = 1")
    req = a.request([SPELLS])
    req["rules_digest"] = "0" * 64
    assert svc.publish(a.identity, a.binding, req).status == "rules_mismatch"


def test_idempotency(svc, a):
    edit(a, SPELLS, b"mana = 20", b"mana = 77")
    key = str(uuid.uuid4())
    req = a.request([SPELLS], key=key)
    first = svc.publish(a.identity, a.binding, req)
    assert first.status == "published"
    again = svc.publish(a.identity, a.binding, req)
    assert again.status == "published" and again.payload["replayed"] is True
    assert again.payload["revision"] == first.payload["revision"]
    # mesma chave, conteúdo diferente
    other = dict(req, message="outra")
    assert svc.publish(a.identity, a.binding, other).status == "idempotency_mismatch"
    # depois de "reiniciar" o Manager (novo serviço sobre o mesmo diretório)
    from tsm_manager.project import ProjectService

    svc2 = ProjectService(svc.layout.root, svc.project)
    assert svc2.publish(a.identity, a.binding, req).payload["revision"] == 2
    assert len(svc.revisions()) == 2
    # sem mudança
    a.base = first.payload["commit"]
    assert a.publish([SPELLS]).status == "no_change"
    assert len(svc.revisions()) == 2


def test_content_already_in_main_is_no_change(svc, a, b):
    edit(a, SPELLS, b"mana = 20", b"mana = 44")
    edit(b, SPELLS, b"mana = 20", b"mana = 44")
    assert a.publish([SPELLS]).status == "published"
    out = b.publish([SPELLS])
    assert out.status == "no_change"
    assert "demo-pcb" not in svc.binding_refs()


# ----------------------------------------------------------------


def _concurrent_publish(root: str, which: str, idx: int) -> str:
    from tsm_manager.config import BindingConfig, Limits, ProjectConfig
    from tsm_manager.project import ProjectService

    project = ProjectConfig("demo", ProjectRules(), Limits(), {
        f"demo-{which}": BindingConfig(f"demo-{which}", which, which)})
    svc = ProjectService(Path(root), project, lock_timeout=120)
    from tsm_manager.config import Identity

    ident = Identity(which, "developer", which, "d" * 64)
    d = Dev(svc, ident, project.bindings[f"demo-{which}"], svc.git.resolve("refs/heads/main"),
            demo_files())
    rel = f"data/conc/{which}.lua"
    d.write(rel, f"return {idx}\n")
    return d.publish([rel]).status


def test_concurrent_publications_are_serialized(tmp_path):
    names = [f"p{i}" for i in range(8)]
    from tsm_manager.config import BindingConfig, Limits, ProjectConfig
    from tsm_manager.project import ProjectService

    project = ProjectConfig("demo", ProjectRules(), Limits(), {
        f"demo-{n}": BindingConfig(f"demo-{n}", n, n) for n in names})
    svc = ProjectService(tmp_path / "srv", project)
    svc.init_project(Path(__file__).resolve().parents[2] / "examples" / "demo-project")
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(8) as pool:
        results = pool.starmap(_concurrent_publish,
                               [(str(tmp_path / "srv"), n, i) for i, n in enumerate(names)])
    assert results == ["published"] * 8
    revs = svc.revisions(100)
    assert [r["revision"] for r in revs] == list(range(9, 0, -1))
    files = main_files(svc)
    assert {f"data/conc/{n}.lua" for n in names} <= set(files)
    assert_shared_is_main(svc)


# ----------------------------------------------------------------


def test_base_validation_and_fast_forward(svc, a, b):
    edit(a, SPELLS, b"mana = 20", b"mana = 60")
    first = a.publish([SPELLS])
    assert first.status == "published"
    # base desconhecida
    out = svc.publish(a.identity, a.binding, a.request([SPELLS], base="f" * 40))
    assert out.status == "stale_base"
    # base anterior à ponta do vínculo (vínculo não volta)
    r1 = svc.revisions()[-1]["commit"]
    out = svc.publish(a.identity, a.binding, a.request([SPELLS], base=r1))
    assert out.status == "stale_base"
    # B publica; A faz pull (base = main) e publica: vínculo avança por fast-forward
    edit(b, CREATURES, b"health = 20", b"health = 21")
    assert b.publish([CREATURES]).status == "published"
    a.pull()
    edit(a, SPELLS, b"level = 8", b"level = 10")
    out = a.publish([SPELLS])
    assert out.status == "published"
    assert svc.git.commit_info(out.payload["commit"]).parents == (
        svc.revisions()[1]["commit"],)


def test_links_and_non_regular_files_rejected(svc, a, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.lua").write_bytes(b"segredo")
    ws = a.workspace
    # diretório no lugar de arquivo
    (ws / "data" / "dir.lua").mkdir()
    a.files["data/dir.lua"] = b""
    out = svc.publish(a.identity, a.binding, a.request(["data/dir.lua"]))
    assert out.status == "rejected"
    # junction/symlink de diretório apontando para fora do workspace
    import subprocess
    import sys

    link = ws / "data" / "lnk"
    if sys.platform == "win32":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], check=True,
                       capture_output=True)
    else:
        link.symlink_to(outside, target_is_directory=True)
    a.files["data/lnk/secret.lua"] = b"segredo"
    out = svc.publish(a.identity, a.binding, a.request(["data/lnk/secret.lua"]))
    assert out.status == "rejected"
    assert "link" in out.payload["errors"][0]["reason"]
    assert assert_shared_is_main(svc).revision == 1


def test_materialization_order_and_shape(svc, a):
    order: list[str] = []
    real_install = None

    from tsm_manager.adapters import fs as fsmod

    real_install = fsmod.SharedWriter.install

    def spy(self, tmp, rel):
        order.append(rel)
        assert not any(p.name.startswith("shared-") for p in self.shared.rglob("*"))
        return real_install(self, tmp, rel)

    edit(a, SPELLS, b"mana = 20", b"mana = 5")
    a.write("data/n1/x.lua", b"1")
    a.write("data/n2/y.lua", b"2")
    fsmod.SharedWriter.install = spy
    try:
        assert a.publish([SPELLS, "data/n1/x.lua", "data/n2/y.lua"]).status == "published"
    finally:
        fsmod.SharedWriter.install = real_install
    assert order[-1] == ".tsm/revision.json"
    assert set(order[:-1]) == {SPELLS, "data/n1/x.lua", "data/n2/y.lua"}
    # exclusão remove diretórios vazios; a raiz nunca é trocada
    root_id = svc.layout.shared.stat().st_ino if hasattr(svc.layout.shared.stat(),
                                                         "st_ino") else None
    a.delete("data/n1/x.lua")
    assert a.publish(deletes=["data/n1/x.lua"]).status == "published"
    assert not (svc.layout.shared / "data" / "n1").exists()
    assert svc.layout.shared.stat().st_ino == root_id
    assert not any(svc.layout.tmp.iterdir())
    info = assert_shared_is_main(svc)
    assert info.files[SPELLS] == sha(main_files(svc)[SPELLS])


def test_identity_mismatch_is_caller_concern(svc, a):
    # o serviço confia no par identidade/vínculo validado pela API; aqui só a auditoria
    edit(a, SPELLS, b"mana = 20", b"mana = 2")
    out = a.publish([SPELLS], message="teste")
    assert out.status == "published"
    ev = svc.store.read_audit(1)[0]
    assert ev["user"] == DEV_A.name and ev["binding"] == "demo-pca"
