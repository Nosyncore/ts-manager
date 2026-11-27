"""Integração SSH: Mutagen + OpenSSH reais contra um contêiner sshd ``linux/arm64``.

- Imagem: ``tests/fixtures/sshd`` (contas tsm-dev-a, tsm-dev-b, tsm-manager; shell de
  auditoria; /srv/ts em volume nomeado, outro filesystem que /home).
- O Client usa HOME gerenciado (config SSH, known_hosts fixado, chave por dispositivo) e
  o OpenSSH do Git for Windows via ``MUTAGEN_SSH_PATH``. O ``~/.ssh`` pessoal é conferido
  por hash antes e depois de toda a sessão de testes.
- A chave de host vem de ``docker exec`` (canal local confiável), nunca de TOFU.

Variáveis:
  TSM_SSH_PLATFORM  plataforma do contêiner (padrão linux/arm64; linux/amd64 = ciclo rápido)
  TSM_SSH_PATH      diretório do ssh (padrão C:/Program Files/Git/usr/bin)
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.integration.conftest import (
    DEMO,
    Pc,
    _mutagen_temporaries,
    _outside_snapshot,
    wait_until,
    write_config,
)
from tsm_client.rules import IgnoreMatcher, ProjectRules

PLATFORM = os.environ.get("TSM_SSH_PLATFORM", "linux/arm64")
SSH_DIR = Path(os.environ.get("TSM_SSH_PATH", r"C:\Program Files\Git\usr\bin"))
IMAGE = f"tsm-sshd-test:{PLATFORM.split('/')[-1]}"
SSHD_CONTEXT = REPO_ROOT / "tests" / "fixtures" / "sshd"
REMOTE_PROJECT = "/srv/ts/projects/demo"
DEVS = {"pcA": ("tsm-dev-a", "dev-a", "tsm-test-a"), "pcB": ("tsm-dev-b", "dev-b", "tsm-test-b")}


def docker(*args: str, input: str | None = None, check: bool = True,
           timeout: float = 120) -> subprocess.CompletedProcess[str]:
    # bytes na entrada: em modo texto o Windows converteria "\n" em "\r\n" (scripts sh quebram)
    raw = subprocess.run(["docker", *args], input=input.encode() if input is not None else None,
                         capture_output=True, timeout=timeout, check=False)
    proc = subprocess.CompletedProcess(
        raw.args, raw.returncode,
        raw.stdout.decode("utf-8", "replace").replace("\r\n", "\n"),
        raw.stderr.decode("utf-8", "replace").replace("\r\n", "\n"),
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} falhou: {proc.stderr.strip()}")
    return proc


@dataclass
class Container:
    name: str
    volume: str
    port: int
    host_keys: list[str]

    def sh(self, script: str, *, user: str = "root", input: str | None = None,
           check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return docker("exec", "-i", "-u", user, self.name, "sh", "-c", script, input=input,
                      check=check, timeout=timeout)

    def setup(self, *args: str, input: str | None = None) -> None:
        self.sh("tsm-setup " + " ".join(args), input=input)

    def manifest(self, path: str, *, user: str = "root") -> dict[str, str]:
        """Manifesto remoto no mesmo formato de ``treehash.manifest`` (links como 'link')."""
        script = (
            f"cd '{path}' || exit 3; "
            "find . -mindepth 1 -type d -printf 'd\\t%P\\n'; "
            "find . -mindepth 1 -type l -printf 'l\\t%P\\n'; "
            "find . -mindepth 1 -type f -exec sha256sum {} +"
        )
        out = self.sh(script, user=user).stdout
        m: dict[str, str] = {}
        for line in out.splitlines():
            if line.startswith("d\t"):
                m[line[2:]] = "dir"
            elif line.startswith("l\t"):
                m[line[2:]] = "link"
            elif line.strip():
                digest, rel = line.split("  ", 1)
                m[rel.removeprefix("./")] = digest
        return dict(sorted(m.items()))

    def read(self, path: str, *, user: str = "root") -> str:
        return self.sh(f"cat '{path}'", user=user).stdout

    def audit_log(self) -> list[str]:
        return self.sh("cat /var/log/tsm-audit.log").stdout.splitlines()


def filter_manifest(m: dict[str, str], matcher: IgnoreMatcher) -> dict[str, str]:
    return {k: v for k, v in m.items() if not matcher.is_ignored(k, v == "dir")}


@pytest.fixture(scope="session")
def ssh_dir() -> Path:
    if not (SSH_DIR / "ssh.exe").is_file() and not (SSH_DIR / "ssh").is_file():
        pytest.fail(f"OpenSSH não encontrado em {SSH_DIR} (defina TSM_SSH_PATH)")
    return SSH_DIR


def _tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    if not root.exists():
        return "ausente"
    for p in sorted(root.rglob("*")):
        h.update(str(p.relative_to(root)).encode())
        if p.is_file():
            h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


@pytest.fixture(scope="session", autouse=True)
def personal_ssh_untouched() -> Iterator[None]:
    """O ~/.ssh pessoal fica idêntico durante toda a sessão de testes."""
    personal = Path.home() / ".ssh"
    before = _tree_hash(personal)
    yield
    assert _tree_hash(personal) == before, "o ~/.ssh pessoal foi alterado"


@pytest.fixture(scope="session")
def sshd() -> Iterator[Container]:
    if docker("info", check=False, timeout=60).returncode != 0:
        pytest.fail("Docker indisponível: os testes SSH dependem dele")
    if docker("image", "inspect", IMAGE, check=False).returncode != 0:
        docker("build", "--platform", PLATFORM, "-t", IMAGE, str(SSHD_CONTEXT), timeout=1800)
    suffix = uuid.uuid4().hex[:8]
    name, volume = f"tsm-sshd-{suffix}", f"tsm-srv-{suffix}"
    docker("run", "-d", "--platform", PLATFORM, "--name", name, "--hostname", "tsm-sshd",
           "-p", "127.0.0.1::22", "-v", f"{volume}:/srv/ts", IMAGE)
    try:
        docker("cp", f"{DEMO}{os.sep}.", f"{name}:/opt/demo")
        wait_until(lambda: docker("exec", name, "pgrep", "-x", "sshd", check=False).returncode == 0,
                   60, 0.5, "sshd no contêiner")
        port = int(docker("port", name, "22/tcp").stdout.strip().splitlines()[0].rsplit(":", 1)[1])
        keys = docker("exec", name, "sh", "-c", "cat /etc/ssh/ssh_host_*_key.pub").stdout
        arch = docker("exec", name, "uname", "-m").stdout.strip()
        expected = {"linux/arm64": "aarch64", "linux/amd64": "x86_64"}.get(PLATFORM)
        assert arch == expected, f"contêiner em {arch}, esperado {expected}"
        yield Container(name, volume, port, [k for k in keys.splitlines() if k.strip()])
    finally:
        docker("rm", "-f", name, check=False)
        docker("volume", "rm", "-f", volume, check=False)


def ssh_config(alias: str, user: str, port: int, key_name: str) -> str:
    return f"""Host {alias}
  HostName 127.0.0.1
  Port {port}
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
"""


def make_ssh_home(home: Path, container: Container, ssh_dir: Path, *, user: str,
                  alias: str) -> Path:
    """HOME gerenciado: config, known_hosts fixado e chave Ed25519 do dispositivo."""
    dot = home / ".ssh"
    dot.mkdir(parents=True)
    key_name = f"id_ed25519_{user.replace('-', '_')}"
    keygen = ssh_dir / ("ssh-keygen.exe" if (ssh_dir / "ssh-keygen.exe").exists() else "ssh-keygen")
    subprocess.run([str(keygen), "-q", "-t", "ed25519", "-N", "", "-C", f"{user}@tsm-test",
                    "-f", str(dot / key_name)], check=True, capture_output=True)
    (dot / "config").write_text(ssh_config(alias, user, container.port, key_name), encoding="utf-8")
    known = "".join(f"[127.0.0.1]:{container.port} {' '.join(k.split()[:2])}\n"
                    for k in container.host_keys)
    (dot / "known_hosts").write_text(known, encoding="utf-8")
    container.setup("authorize", user, input=(dot / f"{key_name}.pub").read_text())
    return home


@dataclass
class SshLayout:
    root: Path
    container: Container
    pcs: dict[str, Pc] = field(default_factory=dict)
    extra_roots: list[Path] = field(default_factory=list)

    @property
    def a(self) -> Pc:
        return self.pcs["pcA"]

    @property
    def b(self) -> Pc:
        return self.pcs["pcB"]

    @staticmethod
    def workspace(dev: str) -> str:
        return f"{REMOTE_PROJECT}/workspaces/{dev}"

    shared = f"{REMOTE_PROJECT}/shared"

    def mutable_roots(self) -> list[Path]:
        roots: list[Path] = list(self.extra_roots)
        for pc in self.pcs.values():
            roots += [pc.work, pc.cache, pc.data_dir]
            if pc.ssh_home:
                roots.append(pc.ssh_home)
        return roots

    def matcher(self) -> IgnoreMatcher:
        return self.a.matcher


@pytest.fixture
def ssh_layout(tmp_path, sshd, mutagen_exe, ssh_dir) -> Iterator[SshLayout]:
    sshd.setup("restore-host-keys")
    sshd.setup("reset")
    lay = SshLayout(tmp_path, sshd)
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    (sentinel / "secret.txt").write_text("sentinela\n", encoding="utf-8")
    rules = ProjectRules()
    for pc_name, (user, dev, alias) in DEVS.items():
        pc_root = tmp_path / pc_name
        shutil.copytree(DEMO, pc_root / "work")
        home = make_ssh_home(pc_root / "ssh-home", sshd, ssh_dir, user=user, alias=alias)
        cfg_path = tmp_path / f"{pc_name}.json"
        write_config(pc_root, cfg_path, exe=mutagen_exe, binding=f"demo-{pc_name.lower()}",
                     workspace=f"{alias}:{SshLayout.workspace(dev)}",
                     shared=f"{alias}:{SshLayout.shared}", rules=rules,
                     ssh_path=ssh_dir, ssh_home=home)
        lay.pcs[pc_name] = Pc(pc_name, pc_root, cfg_path, rules, mutagen_exe,
                              pc_root / "mutagen-data", ssh_path=ssh_dir, ssh_home=home)
    before = _outside_snapshot(tmp_path, lay.mutable_roots())
    remote_before = sshd.manifest(f"{REMOTE_PROJECT}/history")
    yield lay
    for pc in lay.pcs.values():
        pc.adapter.daemon_stop()
    assert _outside_snapshot(tmp_path, lay.mutable_roots()) == before, "SSH: conteúdo fora das raízes mudou"
    for pc in lay.pcs.values():
        assert _mutagen_temporaries(pc.work) == []
    assert sshd.manifest(f"{REMOTE_PROJECT}/history") == remote_before


def timed(fn) -> float:
    start = time.monotonic()
    fn()
    return time.monotonic() - start


MANAGER_IMAGE = f"tsm-manager-test:{PLATFORM.split('/')[-1]}"
VENV = "/opt/tsm-venv/bin"
API_PORT, RELAY_PORT = 8740, 8741


# ---------------------------------------------------------------- contêiner com Manager


@dataclass
class MgrContainer(Container):
    api_port: int = 0

    def manager(self, *args: str, check: bool = True):
        return self.sh(f"{VENV}/tsm-manager " + " ".join(args), user="tsm-manager",
                       check=check, timeout=600)


@pytest.fixture(scope="session")
def manager_image(sshd) -> str:
    if docker("image", "inspect", MANAGER_IMAGE, check=False).returncode == 0 and not \
            os.environ.get("TSM_REBUILD_MANAGER_IMAGE"):
        return MANAGER_IMAGE
    with tempfile.TemporaryDirectory(prefix="tsm-mgr-ctx-") as ctx:
        ign = shutil.ignore_patterns("*.egg-info", "__pycache__", "build", "dist")
        shutil.copytree(REPO_ROOT / "common", Path(ctx) / "common", ignore=ign)
        shutil.copytree(REPO_ROOT / "server", Path(ctx) / "server", ignore=ign)
        shutil.copy(REPO_ROOT / "tests" / "fixtures" / "manager" / "Dockerfile", ctx)
        docker("build", "--platform", PLATFORM, "--build-arg", f"BASE={IMAGE}", "-t",
               MANAGER_IMAGE, ctx, timeout=3600)
    return MANAGER_IMAGE


@pytest.fixture(scope="session")
def mgr_container(manager_image) -> Iterator[MgrContainer]:
    suffix = uuid.uuid4().hex[:8]
    name, volume = f"tsm-mgr-{suffix}", f"tsm-mgr-srv-{suffix}"
    docker("run", "-d", "--platform", PLATFORM, "--name", name, "--hostname", "tsm-sshd",
           "-p", "127.0.0.1::22", "-p", f"127.0.0.1::{RELAY_PORT}", "-v", f"{volume}:/srv/ts",
           manager_image)
    try:
        docker("cp", f"{DEMO}{os.sep}.", f"{name}:/opt/demo")
        wait_until(lambda: docker("exec", name, "pgrep", "-x", "sshd",
                                  check=False).returncode == 0, 60, 0.5, "sshd")

        def mapped(port: int) -> int:
            out = docker("port", name, f"{port}/tcp").stdout.strip().splitlines()[0]
            return int(out.rsplit(":", 1)[1])

        keys = docker("exec", name, "sh", "-c", "cat /etc/ssh/ssh_host_*_key.pub").stdout
        c = MgrContainer(name, volume, mapped(22), [k for k in keys.splitlines() if k.strip()],
                         api_port=mapped(RELAY_PORT))
        # relay de teste: host 127.0.0.1:<mapeada> → contêiner :8741 → 127.0.0.1:8740
        docker("exec", "-d", name, "socat", f"TCP-LISTEN:{RELAY_PORT},fork,reuseaddr",
               f"TCP:127.0.0.1:{API_PORT}")
        yield c
    finally:
        docker("rm", "-f", name, check=False)
        docker("volume", "rm", "-f", volume, check=False)
