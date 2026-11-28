"""Manager com Git real, sem Mutagen.

Os workspaces são escritos diretamente pelo teste, como o Mutagen faria. O "dev" é um
pequeno modelo do Client: mantém a base (commit + manifesto) e monta as requisições. O
banco do Manager fica em ``<root>/manager/manager.db``, migrado antes do uso.

As identidades são reais (``tests/identity_seed.py``): ``dev-a`` e ``dev-b`` (developers)
e ``admin`` (bootstrap) se cadastram com prova de posse e são aprovados com o
``LocalProvisioner``; os vínculos vêm do banco (``DbBindings``) e cada workspace é o
``workspaces/<conta>/tree`` da conta do dispositivo.
"""

from __future__ import annotations

import hashlib
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import REPO_ROOT
from tests.identity_seed import KEYGEN, Seed, SeedDevice
from tsm_common.protocol import REVISION_FILE, RevisionInfo
from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager.bindings import DbBindings
from tsm_manager.config import (
    DEFAULT_DATABASE,
    AuthConfig,
    BindingConfig,
    Limits,
    ManagerConfig,
    ProjectConfig,
    ProvisionerConfig,
)
from tsm_manager.db import Database, Repository, upgrade
from tsm_manager.faults import Faults
from tsm_manager.project import Outcome, ProjectService, Requester, open_project
from tsm_manager.services import build_identity

DEMO = REPO_ROOT / "examples" / "demo-project"

# pessoas criadas por raiz do Manager: "a", "b", "admin" (e as que o teste pedir)
PEOPLE: dict[Path, dict[str, SeedDevice]] = {}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Dev:
    svc: ProjectService
    identity: Requester
    binding: BindingConfig
    base: str
    files: dict[str, bytes] = field(default_factory=dict)  # estado "local" do dev

    @property
    def workspace(self) -> Path:
        return self.svc.bindings.workspace_path(self.svc.layout, self.binding)

    def sync_workspace(self) -> None:
        """Faz o workspace espelhar ``files`` (o papel do upload do Mutagen)."""
        ws = self.workspace
        if ws.exists():
            shutil.rmtree(ws)
        ws.mkdir(parents=True)
        for rel, data in self.files.items():
            p = ws / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    def write(self, rel: str, data: bytes | str) -> None:
        self.files[rel] = data.encode() if isinstance(data, str) else data
        self.sync_workspace()

    def delete(self, rel: str) -> None:
        self.files.pop(rel, None)
        self.sync_workspace()

    def request(self, puts: list[str] = (), deletes: list[str] = (), *, key: str | None = None,
                base: str | None = None, message: str = "") -> dict[str, Any]:
        changes = [{"path": p, "op": "put", "sha256": sha(self.files[p]),
                    "size": len(self.files[p])} for p in puts]
        changes += [{"path": p, "op": "delete"} for p in deletes]
        return {
            "idempotency_key": key or str(uuid.uuid4()),
            "base": {"commit": base or self.base},
            "rules_digest": rules_digest(self.svc.project.rules),
            "message": message,
            "changes": changes,
        }

    def publish(self, puts: list[str] = (), deletes: list[str] = (), **kw: Any) -> Outcome:
        out = self.svc.publish(self.identity, self.binding, self.request(puts, deletes, **kw))
        if out.status == "published":
            self.base = out.payload["commit"]
        return out

    def pull(self) -> None:
        """Pull ingênuo: só para testes sem mudança local pendente nos mesmos arquivos."""
        main = self.svc.git.resolve("refs/heads/main")
        blobs = self.svc.git.ls_tree(main)
        self.files = {p: self.svc.git.cat_blob(b) for p, b in blobs.items()}
        self.base = main
        self.sync_workspace()


def demo_files() -> dict[str, bytes]:
    out = {}
    for p in sorted(DEMO.rglob("*")):
        if p.is_file():
            out[p.relative_to(DEMO).as_posix()] = p.read_bytes()
    return out


def migrated_db(root: Path) -> Database:
    """Banco do Manager sob ``root``, com todas as migrations aplicadas."""
    db = Database(root / DEFAULT_DATABASE)
    upgrade(db)
    return db


def open_service(root: Path, project: ProjectConfig, **kw: Any) -> ProjectService:
    """Serviço sobre ``root``, com conexão própria ao banco (como um Manager novo)."""
    db = Database(root / DEFAULT_DATABASE)
    return open_project(root, project, db, bindings=DbBindings(Repository(db), project.id),
                        **kw)


def reopen(svc: ProjectService, **kw: Any) -> ProjectService:
    """O mesmo projeto num serviço novo: simula o reinício do Manager."""
    return open_service(svc.layout.root, svc.project, **kw)


def manager_config(root: Path, project: ProjectConfig) -> ManagerConfig:
    """Config ``version: 2`` local do Manager destes testes (sem arquivo em disco)."""
    return ManagerConfig(root.parent / "manager.json", root, {project.id: project},
                         root / DEFAULT_DATABASE, shared_group="tsm-readers",
                         workspace_group="tsm-ws", provisioner=ProvisionerConfig("local"),
                         auth=AuthConfig(ssh_keygen=str(KEYGEN)))


def seed_for(root: Path, project: ProjectConfig, db: Database) -> Seed:
    return Seed(build_identity(manager_config(root, project), db), root.parent / "keys")


def make_project(tmp_path: Path, *, rules: ProjectRules | None = None,
                 limits: Limits | None = None, faults: Faults | None = None,
                 people: tuple[str, ...] = ("a", "b")) -> ProjectService:
    """Projeto inicializado, com ``admin`` e os developers pedidos (``dev-<nome>``)."""
    project = ProjectConfig("demo", rules or ProjectRules(), limits or Limits())
    root = tmp_path / "srv"
    db = migrated_db(root)
    svc = open_project(root, project, db, bindings=DbBindings(Repository(db), "demo"),
                       faults=faults, lock_timeout=60)
    out = svc.init_project(DEMO)
    assert out.status == "published", out.payload
    seed = seed_for(root, project, db)
    PEOPLE[root] = {"admin": seed.device("admin", admin=True),
                    **{n: seed.device(f"dev-{n}") for n in people}}
    return svc


def person(svc: ProjectService, which: str) -> SeedDevice:
    return PEOPLE[svc.layout.root][which]


def requester(svc: ProjectService, which: str) -> Requester:
    return person(svc, which).requester


@pytest.fixture
def svc(tmp_path: Path) -> ProjectService:
    return make_project(tmp_path)


def dev(svc: ProjectService, which: str) -> Dev:
    p = person(svc, which)
    binding = svc.bindings.get(p.binding.id)
    assert binding is not None
    d = Dev(svc, p.requester, binding,
            svc.git.resolve("refs/heads/main"), demo_files())
    d.sync_workspace()
    return d


@pytest.fixture
def a(svc: ProjectService) -> Dev:
    return dev(svc, "a")


@pytest.fixture
def b(svc: ProjectService) -> Dev:
    return dev(svc, "b")


def main_files(svc: ProjectService) -> dict[str, bytes]:
    main = svc.git.resolve("refs/heads/main")
    return {p: svc.git.cat_blob(o) for p, o in svc.git.ls_tree(main).items()}


def shared_files(svc: ProjectService) -> dict[str, bytes]:
    root = svc.layout.shared
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
            if p.is_file() and not p.relative_to(root).as_posix().startswith(".tsm/")}


def assert_shared_is_main(svc: ProjectService) -> RevisionInfo:
    assert shared_files(svc) == main_files(svc)
    info = RevisionInfo.from_json((svc.layout.shared / REVISION_FILE).read_text("utf-8"))
    assert info.commit == svc.git.resolve("refs/heads/main")
    assert svc.verify() == []
    return info


def refs(svc: ProjectService) -> dict[str, str]:
    return svc.git.list_refs("refs")
