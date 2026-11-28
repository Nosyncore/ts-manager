"""Integração local da colaboração com identidade real: Mutagen, Git, HTTP e ``ssh-keygen``.

Layout em ``tmp_path``::

    mgr/srv/projects/demo/{workspaces/<conta>/tree, shared, history}   (Manager)
    mgr/srv/manager/manager.db                                         (banco do Manager)
    mgr/cfg/manager.json                                               (config version 2)
    pcA/{home, work, cache}    pcB/{...}                               (Client de cada dev)
    admin/{home, work, cache}                                          (só no rollback)
    sentinel/                                                          (não pode mudar)

O Manager roda como processo separado (``tsm-manager serve``, ``LocalProvisioner``,
``transport: local``). O lado do Client é só o ``tsm``, com ``<home>`` próprio e endereço de
loopback próprio por PC: ``tsm enroll`` com um convite e ``tsm bind`` (que roda o ``init``).
O lado do operador (convites e aprovações com o fingerprint mostrado pelo ``enroll``) usa os
serviços de domínio sobre o mesmo banco (``tests/identity_seed.py``), como a CLI do servidor.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.identity.conftest import Pc as IdentityPc
from tests.identity_seed import Seed
from tests.integration.conftest import wait_until
from tests.manager.server import Server
from tsm_client.cli import default_collab, default_service
from tsm_client.collab import CollabService
from tsm_client.config import load_home_config
from tsm_client.enroll import Toolkit
from tsm_client.home import Home
from tsm_manager.config import load_manager_config
from tsm_manager.services import Manager

DEMO = REPO_ROOT / "examples" / "demo-project"
SPELLS = "data/scripts/spells.lua"
CREATURES = "data/scripts/creatures.lua"


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        h.update(rel.encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


class Pc(IdentityPc):
    """Um PC de dev: ``<home>``, pasta de trabalho e cache próprios."""

    def __init__(self, name: str, root: Path, n: int, srv: Server) -> None:
        super().__init__(root, n, srv)
        self.name = name
        self.binding: str | None = None
        self.device_id: str | None = None

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    @property
    def state_dir(self) -> Path:
        return self.home / "state"

    @property
    def connection(self) -> dict:
        assert self.binding, f"{self.name} sem vínculo"
        return json.loads(Home(self.home).connection_file(self.binding).read_text("utf-8"))

    @property
    def workspace(self) -> Path:
        """Raiz sincronizada no servidor (``workspaces/<conta>/tree``), vinda do ``bind``."""
        return Path(self.connection["paths"]["workspace"])

    def enroll(self, seed: Seed, code: str, display_name: str) -> None:
        res = self.json("enroll", "--manager", self.url, "--invite", code, "--name",
                        display_name)
        assert res["status"] == "pending", res
        self.device_id = res["device_id"]
        seed.approve(res["device_id"], res["fingerprint"])

    def bind(self, *extra: str, expect: int | None = 0) -> tuple[int, str, str]:
        """``tsm bind`` da pasta e do cache do PC; roda o ``init`` se ainda não houver."""
        r = self.tsm("bind", "--project", "demo", "--local", str(self.work), "--cache",
                     str(self.cache), *extra, expect=expect)
        if self.binding is None:
            binding = json.loads(Home(self.home).config_path.read_text("utf-8"))["bindings"]
            if binding:
                self.binding = binding[0]["id"]
        return r

    def collab(self) -> CollabService:
        cfg = load_home_config(Home(self.home))
        return default_collab(cfg, default_service(cfg),
                              toolkit=Toolkit(transport=self.transport))

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
        return json.loads((self.state_dir / "bindings" / self.binding / "state.json")
                          .read_text("utf-8"))


@dataclass
class Collab:
    root: Path
    manager: Server
    seed: Seed
    pcs: dict[str, Pc]
    sentinel: Path
    _admin: Pc | None = field(default=None)

    @property
    def a(self) -> Pc:
        return self.pcs["pcA"]

    @property
    def b(self) -> Pc:
        return self.pcs["pcB"]

    @property
    def project_dir(self) -> Path:
        return self.manager.root / "projects" / "demo"

    @property
    def shared(self) -> Path:
        return self.project_dir / "shared"

    def admin(self, *args: str, expect: int | None = 0) -> tuple[int, str, str]:
        """Admin do projeto, criado no primeiro uso: bootstrap, cadastro, aprovação e vínculo."""
        if self._admin is None:
            pc = Pc("admin", self.root / "admin", 3, self.manager)
            pc.enroll(self.seed, self.seed.bootstrap_invite(), "admin")
            pc.bind()
            self._admin = pc
        return self._admin.tsm(*args, expect=expect)

    def main_files(self) -> dict[str, bytes]:
        from tsm_manager.adapters.git import Git

        git = Git(self.project_dir / "history" / "repo.git")
        main = git.resolve("refs/heads/main")
        return {p: git.cat_blob(o) for p, o in git.ls_tree(main).items()}

    def verify(self) -> None:
        out = subprocess.run([sys.executable, "-m", "tsm_manager", "verify", "--config",
                              str(self.manager.cfg)], capture_output=True, text=True,
                             encoding="utf-8")
        assert out.returncode == 0, out.stdout + out.stderr

    def all_pcs(self) -> list[Pc]:
        return [*self.pcs.values(), *([self._admin] if self._admin else [])]


@pytest.fixture
def collab(tmp_path: Path, mutagen_exe: Path) -> Iterator[Collab]:
    """Manager no ar e os dois PCs cadastrados e aprovados, ainda sem vínculo."""
    srv = Server(tmp_path / "mgr", test_faults=True, projects=("demo",))
    srv.cli("migrate")
    srv.cli("init-project", "--project", "demo", "--from", str(DEMO))
    srv.start()
    operator = Manager(load_manager_config(srv.cfg))
    seed = Seed(operator.identity, tmp_path / "keys")
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    (sentinel / "secret.txt").write_text("intocado\n", encoding="utf-8")
    env = Collab(tmp_path, srv, seed, {}, sentinel)
    sentinel_before = tree_hash(sentinel)
    try:
        for name, n, who in (("pcA", 1, "dev-a"), ("pcB", 2, "dev-b")):
            pc = Pc(name, tmp_path / name, n, srv)
            pc.enroll(seed, seed.invite(), who)
            env.pcs[name] = pc
        yield env
    finally:
        for pc in env.all_pcs():
            if (pc.home / "config.json").exists():
                with _suppress():
                    pc.tsm("teardown", "--stop-daemon", expect=None)
        srv.stop()
        operator.close()
    assert tree_hash(env.sentinel) == sentinel_before
    for pc in env.pcs.values():  # temporários do pull nunca ficam na pasta
        if pc.work.exists():
            assert not [p for p in pc.work.rglob("*.tsm-*.tmp")]


@pytest.fixture
def ready(collab: Collab) -> Collab:
    """Os dois PCs vinculados (e por isso inicializados)."""
    for pc in collab.pcs.values():
        pc.bind()
    return collab


class _suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


def wait_workspace(env: Collab, pc: Pc, rel: str, data: bytes | None,
                   timeout: float = 30) -> None:
    ws = pc.workspace / rel

    def check() -> bool:
        if data is None:
            return not ws.exists()
        return ws.is_file() and ws.read_bytes() == data

    wait_until(check, timeout, 0.25, f"workspace de {pc.name}: {rel}")


def wait_for(pred: Callable[[], bool], what: str, timeout: float = 30) -> None:
    wait_until(pred, timeout, 0.25, what)


def copy_demo(dest: Path) -> None:
    shutil.copytree(DEMO, dest)
