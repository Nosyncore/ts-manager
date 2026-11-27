"""Recuperação e rollback do Manager com Git real."""

from __future__ import annotations

import uuid

import pytest

from tests.manager.conftest import (
    ADMIN,
    DEV_A,
    assert_shared_is_main,
    dev,
    main_files,
    make_project,
    refs,
    reopen,
    shared_files,
)
from tsm_manager.faults import Faults, SimulatedCrash

pytestmark = pytest.mark.integration

SPELLS = "data/scripts/spells.lua"


def _setup(tmp_path, crash: str):
    faults = Faults()
    svc = make_project(tmp_path, faults=faults)
    a = dev(svc, "a")
    a.write(SPELLS, a.files[SPELLS].replace(b"mana = 20", b"mana = 33"))
    for i in range(5):
        a.write(f"data/extra/f{i}.lua", f"return {i}\n")
    req = a.request([SPELLS] + [f"data/extra/f{i}.lua" for i in range(5)])
    faults.crash = crash
    return svc, a, req, faults


def test_crash_before_update_ref_is_discarded(tmp_path):
    svc, a, req, faults = _setup(tmp_path, "before_update_ref")
    before = refs(svc)
    with pytest.raises(SimulatedCrash):
        svc.publish(a.identity, a.binding, req)
    assert refs(svc) == before
    assert list(svc.layout.journal.glob("*.json"))  # diário ficou
    faults.crash = None
    notes = reopen(svc).recover()
    assert any("descartada" in n for n in notes)
    assert_shared_is_main(svc)
    # o Client reenvia com a mesma chave: o Manager reexecuta e publica uma vez só
    out = svc.publish(a.identity, a.binding, req)
    assert out.status == "published" and out.payload["revision"] == 2
    assert len(svc.revisions()) == 2


@pytest.mark.parametrize("crash", ["during_materialize", "before_record"])
def test_crash_after_update_ref_is_completed(tmp_path, crash):
    svc, a, req, faults = _setup(tmp_path, crash)
    with pytest.raises(SimulatedCrash):
        svc.publish(a.identity, a.binding, req)
    # main avançou; shared parcial ou revision.json antigo; nenhum registro
    assert svc.revision_of(svc.git.resolve("refs/heads/main")) == 2
    assert svc.store.get_result(req["idempotency_key"]) is None
    if crash == "during_materialize":
        assert shared_files(svc) != main_files(svc)
    faults.crash = None
    restarted = reopen(svc)
    notes = restarted.recover()
    assert any("concluída (r2)" in n for n in notes)
    assert_shared_is_main(restarted)
    # reenvio devolve o resultado registrado pela recuperação, sem nova revisão
    out = restarted.publish(a.identity, a.binding, req)
    assert out.status == "published" and out.payload.get("replayed") is True
    assert out.payload["revision"] == 2
    assert len(restarted.revisions()) == 2
    assert [e for e in restarted.store.read_audit() if e.get("recovered")]


def test_next_publish_recovers_pending_journal(tmp_path):
    svc, a, req, faults = _setup(tmp_path, "during_materialize")
    with pytest.raises(SimulatedCrash):
        svc.publish(a.identity, a.binding, req)
    faults.crash = None
    b = dev(svc, "b")
    b.base = svc.git.resolve("refs/heads/main")
    b.files = main_files(svc)
    b.write("data/b.lua", b"return 'b'\n")
    assert b.publish(["data/b.lua"]).status == "published"  # recupera antes, sob o lock
    assert_shared_is_main(svc)
    assert svc.revisions()[0]["revision"] == 3


def test_recover_repairs_tampered_shared(tmp_path):
    svc = make_project(tmp_path)
    (svc.layout.shared / SPELLS).write_bytes(b"adulterado")
    (svc.layout.shared / "intruso.lua").write_bytes(b"x")
    assert svc.verify()
    svc.recover()
    assert_shared_is_main(svc)


def test_rollback_creates_new_revision(svc, a, b):
    a.write(SPELLS, a.files[SPELLS].replace(b"mana = 20", b"mana = 90"))
    assert a.publish([SPELLS]).status == "published"
    b.write("data/b.lua", b"return 1\n")
    assert b.publish(["data/b.lua"]).status == "published"
    history_before = [r["commit"] for r in svc.revisions()]
    key = str(uuid.uuid4())
    # não admin
    assert svc.rollback(DEV_A, {"idempotency_key": key, "target": 1}).status == "forbidden"
    out = svc.rollback(ADMIN, {"idempotency_key": key, "target": 1, "message": "volta"})
    assert out.status == "published" and out.payload["revision"] == 4
    assert out.payload["rollback_to"] == 1
    revs = svc.revisions()
    assert [r["commit"] for r in revs[1:]] == history_before  # histórico intacto
    assert revs[0]["kind"] == "rollback" and revs[0]["rollback_to"] == 1
    r1 = svc.revisions()[-1]["commit"]
    assert main_files(svc) == {p: svc.git.cat_blob(o) for p, o in svc.git.ls_tree(r1).items()}
    assert_shared_is_main(svc)
    # idempotente; rollback para a revisão já igual → no_change; revisão inexistente
    again = svc.rollback(ADMIN, {"idempotency_key": key, "target": 1, "message": "volta"})
    assert again.payload["revision"] == 4
    assert svc.rollback(ADMIN, {"idempotency_key": str(uuid.uuid4()), "target": 1}
                        ).status == "no_change"
    assert svc.rollback(ADMIN, {"idempotency_key": str(uuid.uuid4()), "target": 99}
                        ).status == "not_found"
    # vínculos continuam ancestrais de main; o dev publica de novo a partir da base antiga
    assert svc.verify() == []
    a.write("data/a2.lua", b"return 2\n")
    assert a.publish(["data/a2.lua"]).status == "published"
    assert SPELLS in main_files(svc) and b"mana = 20" in main_files(svc)[SPELLS]


def test_revision_detail(svc, a):
    a.write(SPELLS, a.files[SPELLS] + b"-- fim\n")
    a.delete("README.md")
    assert a.publish([SPELLS], ["README.md"], message="ajuste").status == "published"
    d = svc.revision_detail(2)
    assert d["message"] == "ajuste" and d["user"] == "dev-a" and d["kind"] == "publish"
    assert sorted((c["status"], c["path"]) for c in d["changes"]) == [
        ("D", "README.md"), ("M", SPELLS)]
    assert svc.revision_detail(1)["kind"] == "init"
    assert svc.revision_detail(7) is None
