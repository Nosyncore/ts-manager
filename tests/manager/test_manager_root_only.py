"""O Manager só grava sob ``<root>``.

Todas as operações rodam como processos ``tsm-manager`` com o diretório temporário, o
HOME, os diretórios de config/cache e o diretório atual apontando para sentinelas fora de
``<root>``. O estado de tudo o que está fora de ``<root>`` é comparado antes e depois:
conteúdo de cada arquivo e o horário de modificação de cada diretório. O segundo pega
também temporários criados e apagados durante a operação (do Git, do SQLite ou do
Python), que não deixam arquivo para trás.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.request
import uuid
from pathlib import Path

import pytest

from tests.integration.conftest import _outside_snapshot, wait_until
from tests.manager.conftest import DEMO, sha
from tests.manager.identity_http import KEYGEN, Device
from tests.manager.server import free_port
from tests.sshsig_signer import generate_key
from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager.db import Database, upgrade
from tsm_manager.db.migrate import packaged_migrations

pytestmark = pytest.mark.integration

SPELLS = "data/scripts/spells.lua"


def _outside_state(tmp_path: Path, root: Path, *also_mutable: Path
                   ) -> tuple[dict[str, str], dict[str, int]]:
    """Arquivos fora de ``root`` e o ``mtime`` de cada diretório fora de ``root``."""
    files = _outside_snapshot(tmp_path, [root, *also_mutable])
    dirs = {"": tmp_path.stat().st_mtime_ns}
    dirs.update({rel: (tmp_path / rel).stat().st_mtime_ns
                 for rel, kind in files.items() if kind == "dir"})
    return files, dirs


def _env(tmp_path: Path) -> dict[str, str]:
    home, systmp = tmp_path / "home", tmp_path / "systmp"
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_", "XDG_", "TSM_", "PYTHONPYCACHEPREFIX"))}
    env.update({
        "TMP": str(systmp), "TEMP": str(systmp), "TMPDIR": str(systmp),
        "HOME": str(home), "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "XDG_CONFIG_HOME": str(home / ".config"), "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return env


class Mgr:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "srv"
        self.cfg = tmp_path / "cfg" / "manager.json"
        self.cwd = tmp_path / "cwd"
        self.env = _env(tmp_path)
        self.port = free_port()
        self.proc: subprocess.Popen | None = None

    def run(self, *args: str, ok: tuple[int, ...] = (0,)) -> str:
        r = subprocess.run([sys.executable, "-m", "tsm_manager", *args, "--config",
                            str(self.cfg)], cwd=self.cwd, env=self.env, capture_output=True,
                           text=True, encoding="utf-8", timeout=300)
        assert r.returncode in ok, f"{args}: {r.returncode}\n{r.stdout}{r.stderr}"
        return r.stdout

    def start(self, faults: dict | None = None) -> None:
        env = dict(self.env)
        if faults:
            env["TSM_MANAGER_FAULTS"] = json.dumps(faults)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "tsm_manager", "serve", "--config", str(self.cfg),
             "--port", str(self.port)], cwd=self.cwd, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def up() -> bool:
            assert self.proc.poll() is None, "Manager saiu"
            return self.get("/health")["ok"] is True

        wait_until(up, 30, 0.2, "Manager no ar")

    def wait_exit(self) -> int:
        return self.proc.wait(30)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(10)

    def get(self, path: str) -> dict:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=60) as r:
            return json.loads(r.read())


@pytest.fixture
def mgr(tmp_path: Path):
    """Manager com a config ``version: 2`` (identidade real, provisionador local)."""
    m = Mgr(tmp_path)
    m.cfg.parent.mkdir()
    generate_key(KEYGEN, tmp_path / "hostkey", "ssh_host_ed25519_key")
    m.cfg.write_text(json.dumps({
        "version": 2, "root": str(m.root), "shared_group": "tsm-readers",
        "workspace_group": "tsm-ws", "provisioner": {"mode": "local"},
        "ssh": {"host": "127.0.0.1",
                "host_key_files": [str(tmp_path / "hostkey" / "ssh_host_ed25519_key.pub")]},
        "auth": {"ssh_keygen": str(KEYGEN)}, "test_faults": True,
        "projects": [{"id": "demo"}],
    }), encoding="utf-8")
    shutil.copytree(DEMO, tmp_path / "src")
    for d in (m.cwd, tmp_path / "home", tmp_path / "systmp"):
        d.mkdir()
        (d / "sentinela.txt").write_text("intocado\n", encoding="utf-8")
    yield m
    m.stop()


def _enroll(mgr: Mgr, admin: Device, dev: Device) -> None:
    """Admin pelo bootstrap (aprovado na CLI) e um dev convidado pelo admin, ambos ativos."""
    boot = json.loads(mgr.run("bootstrap-admin", "--project", "demo", "--json"))
    assert admin.register(boot["code"], display_name="Admin").status == 201
    mgr.run("requests", "approve", admin.device_id, "--fingerprint", admin.fingerprint)
    assert admin.login().status == 200
    code = admin.post("/admin/invites", {"project": "demo"}).body["code"]
    assert dev.register(code, display_name="Dev").status == 201
    assert admin.post(f"/admin/requests/{dev.device_id}/approve",
                      {"fingerprint": dev.fingerprint}).status == 200
    assert dev.login().status == 200


def _publish_body(tree: Path, files: dict[str, bytes], head: str) -> dict:
    changes = []
    for rel, data in files.items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_bytes(data)
        changes.append({"path": rel, "op": "put", "sha256": sha(data), "size": len(data)})
    return {"idempotency_key": str(uuid.uuid4()), "base": {"commit": head},
            "rules_digest": rules_digest(ProjectRules()), "changes": changes}


def test_manager_writes_only_under_root(mgr: Mgr, tmp_path: Path):
    client = tmp_path / "client"  # chaves dos dispositivos: lado do Client, fora do servidor
    admin = Device.create(mgr.port, client / "admin", 1, "Admin")
    dev = Device.create(mgr.port, client / "dev", 2, "Dev")
    # banco numa versão anterior: o migrate atualiza e faz o backup (sob <root>)
    db = Database(mgr.root / "manager" / "manager.db")
    upgrade(db, migrations=packaged_migrations()[:1])
    db.close()
    before = _outside_state(tmp_path, mgr.root, client)

    assert "aplicada: 0002" in mgr.run("migrate")
    mgr.run("init-project", "--project", "demo", "--from", str(tmp_path / "src"))

    mgr.start()
    _enroll(mgr, admin, dev)
    cfg = dev.get("/connection/config?project=demo").body
    tree = Path(cfg["paths"]["workspace"])
    publish = f"/projects/demo/bindings/{cfg['binding_id']}/publish"
    head = dev.get("/projects/demo").body["head"]
    out = dev.post(publish, _publish_body(tree, {SPELLS: b"mana = 1\n",
                                                 "data/novo.lua": b"x\n"}, head["commit"]))
    assert out.body["status"] == "published" and out.body["revision"] == 2, out
    out = admin.post("/projects/demo/rollback",
                     {"idempotency_key": str(uuid.uuid4()), "target": 1})
    assert out.body["status"] == "published" and out.body["revision"] == 3, out
    assert admin.get("/projects/demo/audit").body["events"]
    mgr.stop()

    # queda do processo durante a materialização; o recover conclui
    mgr.start({"crash": "during_materialize"})
    head = dev.get("/projects/demo").body["head"]  # a sessão sobrevive ao reinício
    body = _publish_body(tree, {SPELLS: b"mana = 2\n"}, head["commit"])
    with pytest.raises(OSError):
        dev.post(publish, body)
    assert mgr.wait_exit() == 70
    assert "concluída (r4)" in mgr.run("recover")
    assert "verify: ok" in mgr.run("verify")
    assert "versão 2 de 2" in mgr.run("migrate", "--status")

    after = _outside_state(tmp_path, mgr.root, client)
    assert after[0] == before[0], "arquivos fora de <root> mudaram"
    changed = sorted(d for d in before[1] if after[1].get(d) != before[1][d])
    assert not changed, f"diretórios fora de <root> modificados: {changed}"
    manager_dir = mgr.root / "manager"
    assert (manager_dir / "manager.db").is_file()
    assert len(list((manager_dir / "backups").glob("manager-v0001-*.db"))) == 1
    history = mgr.root / "projects" / "demo" / "history"
    assert not (history / "state").exists()
    assert not list((history / "tmp").iterdir())


# ---------------------------------------------------------------- identidade real


def test_identity_flow_writes_only_under_root(mgr: Mgr, tmp_path: Path):
    client = tmp_path / "client"  # chaves dos dispositivos: lado do Client, fora do servidor
    admin = Device.create(mgr.port, client / "admin", 1, "Admin")
    dev = Device.create(mgr.port, client / "dev", 2, "Dev")
    mgr.root.mkdir()  # a raiz em si é do operador; o teste confere o que vem depois
    before = _outside_state(tmp_path, mgr.root, client)

    mgr.run("migrate")
    mgr.run("init-project", "--project", "demo", "--from", str(tmp_path / "src"))
    boot = json.loads(mgr.run("bootstrap-admin", "--project", "demo", "--json"))
    mgr.start()
    assert admin.register(boot["code"], display_name="Admin").status == 201
    mgr.run("requests", "approve", admin.device_id, "--fingerprint", admin.fingerprint)
    assert admin.login().status == 200
    code = admin.post("/admin/invites", {"project": "demo"}).body["code"]
    assert dev.register(code, display_name="Dev").status == 201
    assert admin.post(f"/admin/requests/{dev.device_id}/approve",
                      {"fingerprint": dev.fingerprint}).status == 200
    assert dev.login().status == 200
    cfg = dev.get("/connection/config?project=demo").body
    tree = Path(cfg["paths"]["workspace"])
    data = b"mana = 3\n"
    (tree / SPELLS).parent.mkdir(parents=True, exist_ok=True)
    (tree / SPELLS).write_bytes(data)
    head = dev.get("/projects/demo").body["head"]["commit"]
    out = dev.post(f"/projects/demo/bindings/{cfg['binding_id']}/publish", {
        "idempotency_key": str(uuid.uuid4()), "base": {"commit": head},
        "rules_digest": rules_digest(ProjectRules()),
        "changes": [{"path": SPELLS, "op": "put", "sha256": sha(data), "size": len(data)}]})
    assert out.body["status"] == "published", out
    assert admin.post(f"/admin/devices/{dev.device_id}/revoke").body["ssh"] == "done"
    assert dev.get("/me").status == 401
    mgr.stop()
    assert "recover: ok" in mgr.run("recover")
    assert "verify: ok" in mgr.run("verify")

    after = _outside_state(tmp_path, mgr.root, client)
    assert after[0] == before[0], "arquivos fora de <root> mudaram"
    changed = sorted(d for d in before[1] if after[1].get(d) != before[1][d])
    assert not changed, f"diretórios fora de <root> modificados: {changed}"
    manager_dir = mgr.root / "manager"
    assert (manager_dir / "local-accounts").is_dir()
    assert not list((manager_dir / "tmp" / "sshsig").iterdir())
