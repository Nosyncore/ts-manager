"""Integração local com Mutagen real (sem SSH): dois "PCs" com daemons isolados.

Layout em ``tmp_path``::

    pcA/work pcA/cache pcA/mutagen-data              (idem pcB)
    server/projects/demo/workspaces/devA|devB
    server/projects/demo/shared
    sentinel/            + sentinelas vizinhas a cada raiz

Cada PC tem um ``Config`` de transporte montado em código (``tests/transport_config.py``) e
entregue ao ``tsm`` por ``run(..., config=…)``: estes testes não usam Manager nem identidade.

Restrição global (automática): tudo em ``tmp_path`` fora das raízes declaradas
precisa estar idêntico ao fim do teste (sentinelas, diretórios vizinhos), e
nenhum temporário do Mutagen pode sobrar nos alphas.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.transport_config import BindingSpec, transport_config
from tsm_client.adapters.mutagen import (
    MutagenAdapter,
    SessionState,
    Status,
    SubprocessRunner,
    mutagen_env,
)
from tsm_client.cli import run as cli_run
from tsm_client.config import Config
from tsm_client.rules import IgnoreMatcher, ProjectRules, ignore_patterns
from tsm_client.service import TransportService
from tsm_client.treehash import manifest

DEMO = REPO_ROOT / "examples" / "demo-project"
DEFAULT_TIMEOUT = 60.0


def wait_until(pred: Callable[[], bool], timeout: float = DEFAULT_TIMEOUT, interval: float = 0.25,
               what: str = "condição") -> None:
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if pred():
                return
        except Exception as exc:  # relatado se o tempo esgotar
            last_exc = exc
        time.sleep(interval)
    detail = f": {last_exc!r}" if last_exc else ""
    raise AssertionError(f"tempo esgotado esperando {what}{detail}")


@dataclass
class Pc:
    name: str
    root: Path
    config: Config
    rules: ProjectRules
    exe: Path
    data_dir: Path
    ssh_path: Path | None = None
    ssh_home: Path | None = None

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    @property
    def adapter(self) -> MutagenAdapter:
        env = mutagen_env(self.data_dir, ssh_path=self.ssh_path, ssh_home=self.ssh_home)
        return MutagenAdapter(self.exe, SubprocessRunner(env))

    @property
    def service(self) -> TransportService:
        return TransportService(self.config, self.adapter)

    @property
    def matcher(self) -> IgnoreMatcher:
        return IgnoreMatcher(ignore_patterns(self.rules))

    def tsm(self, *args: str, expect: int | None = 0) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli_run(list(args), config=self.config, out=out, err=err)
        if expect is not None:
            msg = f"tsm {' '.join(args)} -> {code}\n{out.getvalue()}{err.getvalue()}"
            assert code == expect, msg
        return code, out.getvalue(), err.getvalue()

    def sessions(self) -> dict[str, SessionState]:
        return {s.labels["tsm-role"]: s for s in self.service.managed_sessions()}

    def wait_status(self, role: str, pred: Callable[[SessionState], bool],
                    timeout: float = DEFAULT_TIMEOUT, what: str = "") -> SessionState:
        holder: dict[str, SessionState] = {}

        def check() -> bool:
            s = self.sessions().get(role)
            if s is not None and pred(s):
                holder["s"] = s
                return True
            return False

        wait_until(check, timeout, 0.5, what or f"{self.name}/{role}")
        return holder["s"]

    def wait_watching(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        for role in ("upload", "download"):
            self.wait_status(role, lambda s: s.status is Status.WATCHING and not s.paused,
                             timeout, f"{self.name}/{role} em watching")


@dataclass
class Layout:
    root: Path
    server: Path
    shared: Path
    workspaces: Path
    sentinel: Path
    pcs: dict[str, Pc] = field(default_factory=dict)
    extra_roots: list[Path] = field(default_factory=list)

    def workspace(self, dev: str) -> Path:
        return self.workspaces / dev

    @property
    def a(self) -> Pc:
        return self.pcs["pcA"]

    @property
    def b(self) -> Pc:
        return self.pcs["pcB"]

    def mutable_roots(self) -> list[Path]:
        roots = [self.shared, self.workspace("devA"), self.workspace("devB"), *self.extra_roots]
        for pc in self.pcs.values():
            roots += [pc.work, pc.cache, pc.data_dir]
            if pc.ssh_home:
                roots.append(pc.ssh_home)
        return roots


def pc_config(pc_root: Path, *, exe: Path, binding: str, workspace: str, shared: str,
              rules: ProjectRules, ssh_path: Path | None = None,
              ssh_home: Path | None = None) -> Config:
    """``Config`` de transporte do PC: pasta e cache em ``pc_root``, daemon isolado."""
    return transport_config(
        pc_root, device_id=pc_root.name, data_directory=pc_root / "mutagen-data",
        executable=exe, ssh_path=ssh_path, ssh_home=ssh_home,
        bindings=[BindingSpec(binding, pc_root / "work", pc_root / "cache", workspace, shared,
                              rules)])


def make_layout(tmp_path: Path, exe: Path, rules: ProjectRules | None = None) -> Layout:
    rules = rules or ProjectRules()
    server = tmp_path / "server"
    project = server / "projects" / "demo"
    workspaces = project / "workspaces"
    workspaces.mkdir(parents=True)
    shutil.copytree(DEMO, project / "shared")
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    (sentinel / "secret.txt").write_text("não pode ser lido nem alterado\n", encoding="utf-8")
    (sentinel / "nested").mkdir()
    (sentinel / "nested" / "data.lua").write_text("return 1\n", encoding="utf-8")
    # sentinelas vizinhas às raízes
    (project / "sentinel.txt").write_text("vizinho do shared\n", encoding="utf-8")
    (workspaces / "sentinel.txt").write_text("vizinho dos workspaces\n", encoding="utf-8")

    layout = Layout(tmp_path, server, project / "shared", workspaces, sentinel)
    for name, binding, dev in (("pcA", "demo-pca", "devA"), ("pcB", "demo-pcb", "devB")):
        pc_root = tmp_path / name
        shutil.copytree(DEMO, pc_root / "work")
        (pc_root / "sentinel.txt").write_text(f"vizinho de {name}\n", encoding="utf-8")
        cfg = pc_config(pc_root, exe=exe, binding=binding, workspace=str(workspaces / dev),
                        shared=str(project / "shared"), rules=rules)
        layout.pcs[name] = Pc(name, pc_root, cfg, rules, exe, pc_root / "mutagen-data")
    return layout


def _outside_snapshot(root: Path, mutable: list[Path]) -> dict[str, str]:
    skip = {str(p.resolve()).lower() for p in mutable}
    out: dict[str, str] = {}

    def walk(d: Path, prefix: str) -> None:
        for entry in sorted(d.iterdir(), key=lambda p: p.name):
            rel = prefix + entry.name
            if str(entry.resolve()).lower() in skip and not entry.is_symlink():
                continue  # raízes podem surgir/mudar; o resto não
            if entry.is_symlink() or entry.is_junction():
                out[rel] = "link"
            elif entry.is_dir():
                out[rel] = "dir"
                walk(entry, rel + "/")
            else:
                out[rel] = manifest_file(entry)

    walk(root, "")
    return out


def manifest_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _mutagen_temporaries(root: Path) -> list[str]:
    if not root.is_dir():
        return []
    return [str(p) for p in root.rglob(".mutagen*")]


@pytest.fixture
def layout_factory(tmp_path, mutagen_exe):
    """Cria layouts e aplica a restrição global ao final (após parar os daemons)."""
    created: list[tuple[Layout, dict[str, str]]] = []

    def factory(rules: ProjectRules | None = None) -> Layout:
        lay = make_layout(tmp_path, mutagen_exe, rules)
        created.append((lay, _outside_snapshot(tmp_path, lay.mutable_roots())))
        return lay

    yield factory

    for lay, _ in created:
        for pc in lay.pcs.values():
            pc.adapter.daemon_stop()
    for lay, before in created:
        after = _outside_snapshot(tmp_path, lay.mutable_roots())
        assert after == before, "conteúdo fora das raízes de sincronização mudou"
        for alpha in [lay.shared, *(pc.work for pc in lay.pcs.values())]:
            assert _mutagen_temporaries(alpha) == [], f"temporários do Mutagen em {alpha}"


@pytest.fixture
def layout(layout_factory) -> Layout:
    return layout_factory()


def filtered(pc_or_matcher, root: Path) -> dict[str, str]:
    """Manifesto de ``root`` filtrado pelas regras do PC (ou por um matcher)."""
    matcher = pc_or_matcher.matcher if isinstance(pc_or_matcher, Pc) else pc_or_matcher
    return manifest(root, matcher)
