"""Testes na VM ARM64 real (``-m remote``), com contas de teste dedicadas.

Ativação (sem estas variáveis os testes são pulados):
  TSM_REMOTE_ROOT   raiz provisionada (ex.: /srv/ts-poc)
  TSM_REMOTE_KEYS   diretório com id_ed25519_tsm_poc_dev_a/_b (scripts/poc_remote_prepare.py)
  e um destes:
  TSM_REMOTE_ALIAS  alias SSH do operador (ex.: ts-dev): só para LER HostName/Port via
                    ``ssh -G`` e a chave de host já confiada no known_hosts pessoal
                    (``ssh-keygen -F``). Os testes nunca conectam com esse alias nem
                    usam a chave dele.
  TSM_REMOTE_HOSTNAME + TSM_REMOTE_PORT + TSM_REMOTE_KNOWN_HOSTS
                    alvo explícito (ensaio do procedimento contra o contêiner).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.integration.conftest import DEMO, Pc, _outside_snapshot, write_config
from tsm_client.rules import IgnoreMatcher, ProjectRules

SSH_DIR = Path(os.environ.get("TSM_SSH_PATH", r"C:\Program Files\Git\usr\bin"))
USERS = {
    "pcA": ("tsm-poc-dev-a", "dev-a", "tsm-poc-a"),
    "pcB": ("tsm-poc-dev-b", "dev-b", "tsm-poc-b"),
}


def _ssh_tool(name: str) -> str:
    exe = SSH_DIR / f"{name}.exe"
    return str(exe if exe.exists() else SSH_DIR / name)


@dataclass(frozen=True)
class Target:
    hostname: str
    port: int
    known_hosts: str
    root: str
    keys: Path


def _from_alias(alias: str) -> tuple[str, int, str]:
    """Lê HostName/Port e a chave de host confiada, sem conectar e sem gravar nada."""
    out = subprocess.run([_ssh_tool("ssh"), "-G", alias], capture_output=True, text=True,
                         check=True).stdout
    opts = dict(line.split(" ", 1) for line in out.splitlines() if " " in line)
    hostname, port = opts["hostname"], int(opts["port"])
    personal = Path.home() / ".ssh" / "known_hosts"
    lookup = hostname if port == 22 else f"[{hostname}]:{port}"
    found = subprocess.run([_ssh_tool("ssh-keygen"), "-F", lookup, "-f", str(personal)],
                           capture_output=True, text=True, check=False).stdout
    lines = [ln for ln in found.splitlines() if ln and not ln.startswith("#")]
    if not lines:
        pytest.fail(f"chave de host de {lookup} não está no known_hosts pessoal")
    return hostname, port, "\n".join(lines) + "\n"


@pytest.fixture(scope="session")
def target() -> Target:
    root, keys = os.environ.get("TSM_REMOTE_ROOT"), os.environ.get("TSM_REMOTE_KEYS")
    alias = os.environ.get("TSM_REMOTE_ALIAS")
    explicit = os.environ.get("TSM_REMOTE_HOSTNAME")
    if not root or not keys or not (alias or explicit):
        pytest.skip("VM não configurada (TSM_REMOTE_ROOT, TSM_REMOTE_KEYS e TSM_REMOTE_ALIAS)")
    if explicit:
        hostname, port = explicit, int(os.environ["TSM_REMOTE_PORT"])
        known = Path(os.environ["TSM_REMOTE_KNOWN_HOSTS"]).read_text(encoding="utf-8")
    else:
        hostname, port, known = _from_alias(alias or "")
    return Target(hostname, port, known, root.rstrip("/"), Path(keys))


@dataclass
class RemoteLayout:
    root: Path
    target: Target
    pcs: dict[str, Pc] = field(default_factory=dict)
    extra_roots: list[Path] = field(default_factory=list)

    @property
    def a(self) -> Pc:
        return self.pcs["pcA"]

    @property
    def b(self) -> Pc:
        return self.pcs["pcB"]

    def workspace(self, dev: str) -> str:
        return f"{self.target.root}/projects/demo/workspaces/{dev}"

    @property
    def shared(self) -> str:
        return f"{self.target.root}/projects/demo/shared"

    def sh(self, pc: Pc, script: str, *, check: bool = True,
           timeout: float = 120) -> subprocess.CompletedProcess[str]:
        """Executa um comando na VM com a conta de teste do PC (config gerenciada)."""
        alias = USERS[pc.name][2]
        env = {**os.environ, "HOME": str(pc.ssh_home)}
        env.pop("SSH_AUTH_SOCK", None)
        proc = subprocess.run([_ssh_tool("ssh"), alias, script], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=env, timeout=timeout,
                              stdin=subprocess.DEVNULL, check=False)
        if check and proc.returncode != 0:
            raise AssertionError(f"ssh {alias} falhou ({proc.returncode}): {proc.stderr.strip()}")
        return proc

    def manifest(self, pc: Pc, path: str) -> dict[str, str]:
        script = (f"cd '{path}' || exit 3; "
                  "find . -mindepth 1 -type d -printf 'd\\t%P\\n'; "
                  "find . -mindepth 1 -type l -printf 'l\\t%P\\n'; "
                  "find . -mindepth 1 -type f -exec sha256sum {} +")
        m: dict[str, str] = {}
        for line in self.sh(pc, script).stdout.splitlines():
            if line.startswith("d\t"):
                m[line[2:]] = "dir"
            elif line.startswith("l\t"):
                m[line[2:]] = "link"
            elif line.strip():
                digest, rel = line.split("  ", 1)
                m[rel.removeprefix("./")] = digest
        return dict(sorted(m.items()))

    def matcher(self) -> IgnoreMatcher:
        return self.a.matcher

    def mutable_roots(self) -> list[Path]:
        roots = list(self.extra_roots)
        for pc in self.pcs.values():
            roots += [pc.work, pc.cache, pc.data_dir, pc.ssh_home]
        return roots


def _managed_home(home: Path, t: Target, *, user: str, alias: str) -> Path:
    dot = home / ".ssh"
    dot.mkdir(parents=True)
    key_name = f"id_ed25519_{user.replace('-', '_')}"
    src = t.keys / key_name
    if not src.is_file():
        pytest.fail(f"chave de teste ausente: {src} (rode scripts/poc_remote_prepare.py)")
    shutil.copyfile(src, dot / key_name)
    (dot / "config").write_text(
        f"""Host {alias}
  HostName {t.hostname}
  Port {t.port}
  User {user}
  IdentityFile ~/.ssh/{key_name}
  IdentitiesOnly yes
  UserKnownHostsFile ~/.ssh/known_hosts
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  UpdateHostKeys no
  BatchMode yes
  PreferredAuthentications publickey
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  ForwardAgent no
  ForwardX11 no
  ClearAllForwardings yes
  RequestTTY no
  ControlMaster no
""", encoding="utf-8")
    (dot / "known_hosts").write_text(t.known_hosts, encoding="utf-8")
    return home


@pytest.fixture
def remote_layout(tmp_path, target, mutagen_exe) -> Iterator[RemoteLayout]:
    lay = RemoteLayout(tmp_path, target)
    rules = ProjectRules()
    for pc_name, (user, dev, alias) in USERS.items():
        pc_root = tmp_path / pc_name
        shutil.copytree(DEMO, pc_root / "work")
        home = _managed_home(pc_root / "ssh-home", target, user=user, alias=alias)
        cfg = tmp_path / f"{pc_name}.json"
        write_config(pc_root, cfg, exe=mutagen_exe, binding=f"poc-{pc_name.lower()}",
                     workspace=f"{alias}:{lay.workspace(dev)}", shared=f"{alias}:{lay.shared}",
                     rules=rules, ssh_path=SSH_DIR, ssh_home=home)
        lay.pcs[pc_name] = Pc(pc_name, pc_root, cfg, rules, mutagen_exe,
                              pc_root / "mutagen-data", ssh_path=SSH_DIR, ssh_home=home)
    before = _outside_snapshot(tmp_path, lay.mutable_roots())
    yield lay
    for pc in lay.pcs.values():
        pc.tsm("teardown", "--stop-daemon", expect=None)
    assert _outside_snapshot(tmp_path, lay.mutable_roots()) == before
