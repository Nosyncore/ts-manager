"""Integração local da colaboração: Mutagen + Git + HTTP reais.

Layout em ``tmp_path``::

    srv/projects/demo/{workspaces/pca,pcb, shared, history}   (Manager)
    manager.json                                              (config do Manager)
    pcA/{work,cache,state,mutagen-data,token}  pcA.json       (idem pcB)
    admin.json + admin-token                                  (identidade admin)
    sentinel/                                                 (não pode mudar)

O Manager roda como processo separado (``python -m tsm_manager serve``) numa porta livre
de ``127.0.0.1``. Os comandos ``tsm`` rodam no processo do teste, como nos testes de transporte.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.integration.conftest import wait_until
from tsm_client.cli import default_collab, default_service
from tsm_client.cli import run as cli_run
from tsm_client.collab import CollabService
from tsm_client.config import load_config
from tsm_manager.auth import token_sha256

DEMO = REPO_ROOT / "examples" / "demo-project"
SPELLS = "data/scripts/spells.lua"
CREATURES = "data/scripts/creatures.lua"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        h.update(rel.encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


@dataclass
class ManagerProc:
    cfg_path: Path
    port: int
    env_extra: dict[str, str] = field(default_factory=dict)
    proc: subprocess.Popen | None = None
    log: Path | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self, faults: dict | None = None) -> None:
        env = dict(os.environ)
        env.pop("TSM_MANAGER_FAULTS", None)
        if faults:
            env["TSM_MANAGER_FAULTS"] = json.dumps(faults)
        self.log = self.cfg_path.parent / f"manager-{int(time.time() * 1000)}.log"
        fh = open(self.log, "wb")  # noqa: SIM115 - fechado pelo processo filho/stop
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "tsm_manager", "serve", "--config", str(self.cfg_path),
             "--port", str(self.port)], stdout=fh, stderr=subprocess.STDOUT, env=env)
        fh.close()

        def up() -> bool:
            if self.proc.poll() is not None:
                raise AssertionError(f"Manager saiu: {self.log.read_text('utf-8', 'replace')}")
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                return True

        wait_until(up, 30, 0.2, "Manager no ar")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(10)
        self.proc = None

    def restart(self, faults: dict | None = None) -> None:
        self.stop()
        self.start(faults)


@dataclass
class Pc:
    name: str
    root: Path
    cfg_path: Path
    binding: str

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    def tsm(self, *args: str, expect: int | None = 0) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli_run(["--config", str(self.cfg_path), *args], out=out, err=err)
        if expect is not None:
            assert code == expect, (f"tsm {' '.join(args)} -> {code}\n{out.getvalue()}"
                                    f"{err.getvalue()}")
        return code, out.getvalue(), err.getvalue()

    def collab(self) -> CollabService:
        cfg = load_config(self.cfg_path)
        return default_collab(cfg, default_service(cfg))

    def read(self, rel: str) -> bytes:
        return (self.work / rel).read_bytes()

    def write(self, rel: str, data: bytes | str) -> None:
        p = self.work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)

    def edit(self, rel: str, old: bytes, new: bytes) -> None:
        data = self.read(rel)
        assert old in data, (rel, old)
        self.write(rel, data.replace(old, new, 1))

    def state(self) -> dict:
        return json.loads((self.root / "state" / "bindings" / self.binding / "state.json")
                          .read_text("utf-8"))


@dataclass
class Collab:
    root: Path
    manager: ManagerProc
    project_dir: Path
    pcs: dict[str, Pc]
    admin_cfg: Path
    sentinel: Path

    @property
    def a(self) -> Pc:
        return self.pcs["pcA"]

    @property
    def b(self) -> Pc:
        return self.pcs["pcB"]

    @property
    def shared(self) -> Path:
        return self.project_dir / "shared"

    def workspace(self, device: str) -> Path:
        return self.project_dir / "workspaces" / device

    def admin(self, *args: str, expect: int | None = 0) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli_run(["--config", str(self.admin_cfg), *args], out=out, err=err)
        if expect is not None:
            assert code == expect, f"{code}\n{out.getvalue()}{err.getvalue()}"
        return code, out.getvalue(), err.getvalue()

    def main_files(self) -> dict[str, bytes]:
        from tsm_manager.adapters.git import Git

        git = Git(self.project_dir / "history" / "repo.git")
        main = git.resolve("refs/heads/main")
        return {p: git.cat_blob(o) for p, o in git.ls_tree(main).items()}

    def verify(self) -> None:
        out = subprocess.run([sys.executable, "-m", "tsm_manager", "verify", "--config",
                              str(self.manager.cfg_path)], capture_output=True, text=True,
                             encoding="utf-8")
        assert out.returncode == 0, out.stdout + out.stderr


def _client_cfg(pc_root: Path, exe: Path, binding: str, device: str, project_dir: Path,
                url: str, token_file: Path) -> dict:
    return {
        "version": 2, "device_id": device,
        "mutagen": {"data_directory": str(pc_root / "mutagen-data"), "executable": str(exe)},
        "state_directory": str(pc_root / "state"),
        "manager": {"url": url, "token_file": str(token_file)},
        "bindings": [{
            "id": binding, "project_id": "demo",
            "local": str(pc_root / "work"), "cache": str(pc_root / "cache"),
            "workspace": str(project_dir / "workspaces" / device),
            "shared": str(project_dir / "shared"),
            "rules": {"allow": [], "ignore": []},
        }],
    }


def make_collab(tmp_path: Path, exe: Path, *, test_faults: bool = True) -> Collab:
    tokens = {"pca": "token-pca", "pcb": "token-pcb", "admin": "token-admin"}
    mcfg = {
        "version": 1, "root": "srv", "test_faults": test_faults,
        "projects": [{"id": "demo", "bindings": [
            {"id": "demo-pca", "device": "pca", "workspace": "pca"},
            {"id": "demo-pcb", "device": "pcb", "workspace": "pcb"}]}],
        "identities": [
            {"name": "dev-a", "role": "developer", "device": "pca",
             "token_sha256": token_sha256(tokens["pca"])},
            {"name": "dev-b", "role": "developer", "device": "pcb",
             "token_sha256": token_sha256(tokens["pcb"])},
            {"name": "admin", "role": "admin", "token_sha256": token_sha256(tokens["admin"])},
        ],
    }
    cfg_path = tmp_path / "manager.json"
    cfg_path.write_text(json.dumps(mcfg, indent=1), encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "tsm_manager", "init-project", "--config",
                        str(cfg_path), "--project", "demo", "--from", str(DEMO)],
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stdout + r.stderr
    project_dir = tmp_path / "srv" / "projects" / "demo"
    manager = ManagerProc(cfg_path, free_port())

    pcs = {}
    for name, device in (("pcA", "pca"), ("pcB", "pcb")):
        root = tmp_path / name
        root.mkdir()
        tok = root / "token"
        tok.write_text(tokens[device], encoding="utf-8")
        cfg = _client_cfg(root, exe, f"demo-{device}", device, project_dir, manager.url, tok)
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
        pcs[name] = Pc(name, root, p, f"demo-{device}")
    admin_tok = tmp_path / "admin-token"
    admin_tok.write_text(tokens["admin"], encoding="utf-8")
    admin = json.loads(pcs["pcA"].cfg_path.read_text("utf-8"))
    admin["manager"]["token_file"] = str(admin_tok)
    admin_cfg = tmp_path / "admin.json"
    admin_cfg.write_text(json.dumps(admin), encoding="utf-8")
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    (sentinel / "secret.txt").write_text("intocado\n", encoding="utf-8")
    return Collab(tmp_path, manager, project_dir, pcs, admin_cfg, sentinel)


@pytest.fixture
def collab(tmp_path: Path, mutagen_exe: Path) -> Iterator[Collab]:
    env = make_collab(tmp_path, mutagen_exe)
    env.manager.start()
    sentinel_before = tree_hash(env.sentinel)
    try:
        yield env
    finally:
        for pc in env.pcs.values():
            with _suppress():
                pc.tsm("teardown", "--stop-daemon", expect=None)
        env.manager.stop()
    assert tree_hash(env.sentinel) == sentinel_before
    for pc in env.pcs.values():  # temporários do pull nunca ficam na pasta
        if pc.work.exists():
            assert not [p for p in pc.work.rglob("*.tsm-*.tmp")]


@pytest.fixture
def ready(collab: Collab) -> Collab:
    """Os dois PCs inicializados."""
    for pc in collab.pcs.values():
        pc.tsm("init")
    return collab


class _suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


def wait_workspace(env: Collab, pc: Pc, rel: str, data: bytes | None,
                   timeout: float = 30) -> None:
    ws = env.workspace("pca" if pc.name == "pcA" else "pcb") / rel

    def check() -> bool:
        if data is None:
            return not ws.exists()
        return ws.is_file() and ws.read_bytes() == data

    wait_until(check, timeout, 0.25, f"workspace de {pc.name}: {rel}")


def wait_for(pred: Callable[[], bool], what: str, timeout: float = 30) -> None:
    wait_until(pred, timeout, 0.25, what)


def copy_demo(dest: Path) -> None:
    shutil.copytree(DEMO, dest)
