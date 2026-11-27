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
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

from tests.collab.conftest import free_port
from tests.integration.conftest import _outside_snapshot, wait_until
from tests.manager.conftest import DEMO, sha
from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager.auth import token_sha256
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

    def _req(self, method: str, path: str, token: str | None, body: dict | None) -> dict:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {token}"} if token else {})})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return json.loads(exc.read())

    def get(self, path: str, token: str | None = None) -> dict:
        return self._req("GET", path, token, None)

    def post(self, path: str, token: str, body: dict) -> dict:
        return self._req("POST", path, token, body)

    def publish_body(self, files: dict[str, bytes], head: str) -> dict:
        ws = self.root / "projects" / "demo" / "workspaces" / "pca"
        changes = []
        for rel, data in files.items():
            (ws / rel).parent.mkdir(parents=True, exist_ok=True)
            (ws / rel).write_bytes(data)
            changes.append({"path": rel, "op": "put", "sha256": sha(data), "size": len(data)})
        return {"idempotency_key": str(uuid.uuid4()), "base": {"commit": head},
                "rules_digest": rules_digest(ProjectRules()), "changes": changes}


@pytest.fixture
def mgr(tmp_path: Path):
    m = Mgr(tmp_path)
    m.cfg.parent.mkdir()
    m.cfg.write_text(json.dumps({
        "version": 1, "root": str(m.root), "test_faults": True,
        "projects": [{"id": "demo", "bindings": [
            {"id": "demo-pca", "device": "pca", "workspace": "pca"}]}],
        "identities": [
            {"name": "dev-a", "role": "developer", "device": "pca",
             "token_sha256": token_sha256("tok-a")},
            {"name": "admin", "role": "admin", "token_sha256": token_sha256("tok-admin")}],
    }), encoding="utf-8")
    shutil.copytree(DEMO, tmp_path / "src")
    for d in (m.cwd, tmp_path / "home", tmp_path / "systmp"):
        d.mkdir()
        (d / "sentinela.txt").write_text("intocado\n", encoding="utf-8")
    yield m
    m.stop()


def test_manager_writes_only_under_root(mgr: Mgr, tmp_path: Path):
    # banco numa versão anterior: o migrate atualiza e faz o backup (sob <root>)
    db = Database(mgr.root / "manager" / "manager.db")
    upgrade(db, migrations=packaged_migrations()[:1])
    db.close()
    before = _outside_state(tmp_path, mgr.root)

    assert "aplicada: 0002" in mgr.run("migrate")
    mgr.run("init-project", "--project", "demo", "--from", str(tmp_path / "src"))

    mgr.start()
    head = mgr.get("/projects/demo", "tok-a")["head"]
    out = mgr.post("/projects/demo/bindings/demo-pca/publish", "tok-a",
                   mgr.publish_body({SPELLS: b"mana = 1\n", "data/novo.lua": b"x\n"},
                                    head["commit"]))
    assert out["status"] == "published" and out["revision"] == 2, out
    out = mgr.post("/projects/demo/rollback", "tok-admin",
                   {"idempotency_key": str(uuid.uuid4()), "target": 1})
    assert out["status"] == "published" and out["revision"] == 3, out
    assert mgr.get("/projects/demo/audit", "tok-admin")["events"]
    mgr.stop()

    # queda do processo durante a materialização; o recover conclui
    mgr.start({"crash": "during_materialize"})
    head = mgr.get("/projects/demo", "tok-a")["head"]
    body = mgr.publish_body({SPELLS: b"mana = 2\n"}, head["commit"])
    with pytest.raises((urllib.error.URLError, ConnectionError)):
        mgr.post("/projects/demo/bindings/demo-pca/publish", "tok-a", body)
    assert mgr.wait_exit() == 70
    assert "concluída (r4)" in mgr.run("recover")
    assert "verify: ok" in mgr.run("verify")
    assert "versão 2 de 2" in mgr.run("migrate", "--status")

    after = _outside_state(tmp_path, mgr.root)
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


@pytest.fixture
def mgr2(tmp_path: Path):
    """Manager com a config ``version: 2`` (identidade real, provisionador local)."""
    from tests.manager.identity_http import KEYGEN
    from tests.sshsig_signer import generate_key

    m = Mgr(tmp_path)
    m.cfg.parent.mkdir()
    generate_key(KEYGEN, tmp_path / "hostkey", "ssh_host_ed25519_key")
    m.cfg.write_text(json.dumps({
        "version": 2, "root": str(m.root), "shared_group": "tsm-readers",
        "workspace_group": "tsm-ws", "provisioner": {"mode": "local"},
        "ssh": {"host": "127.0.0.1",
                "host_key_files": [str(tmp_path / "hostkey" / "ssh_host_ed25519_key.pub")]},
        "auth": {"ssh_keygen": str(KEYGEN)},
        "projects": [{"id": "demo"}],
    }), encoding="utf-8")
    shutil.copytree(DEMO, tmp_path / "src")
    for d in (m.cwd, tmp_path / "home", tmp_path / "systmp"):
        d.mkdir()
        (d / "sentinela.txt").write_text("intocado\n", encoding="utf-8")
    yield m
    m.stop()


def test_identity_flow_writes_only_under_root(mgr2: Mgr, tmp_path: Path):
    from tests.manager.identity_http import Device

    client = tmp_path / "client"  # chaves dos dispositivos: lado do Client, fora do servidor
    admin = Device.create(mgr2.port, client / "admin", 1, "Admin")
    dev = Device.create(mgr2.port, client / "dev", 2, "Dev")
    mgr2.root.mkdir()  # a raiz em si é do operador; o teste confere o que vem depois
    before = _outside_state(tmp_path, mgr2.root, client)

    mgr2.run("migrate")
    mgr2.run("init-project", "--project", "demo", "--from", str(tmp_path / "src"))
    boot = json.loads(mgr2.run("bootstrap-admin", "--project", "demo", "--json"))
    mgr2.start()
    assert admin.register(boot["code"], display_name="Admin").status == 201
    mgr2.run("requests", "approve", admin.device_id, "--fingerprint", admin.fingerprint)
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
    mgr2.stop()
    assert "recover: ok" in mgr2.run("recover")
    assert "verify: ok" in mgr2.run("verify")

    after = _outside_state(tmp_path, mgr2.root, client)
    assert after[0] == before[0], "arquivos fora de <root> mudaram"
    changed = sorted(d for d in before[1] if after[1].get(d) != before[1][d])
    assert not changed, f"diretórios fora de <root> modificados: {changed}"
    manager_dir = mgr2.root / "manager"
    assert (manager_dir / "local-accounts").is_dir()
    assert not list((manager_dir / "tmp" / "sshsig").iterdir())
