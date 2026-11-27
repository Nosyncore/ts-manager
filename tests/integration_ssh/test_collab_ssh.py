"""Colaboração via SSH real contra contêiner ``linux/arm64``.

O Manager roda **dentro** do contêiner como ``tsm-manager`` (Python 3.12 e Git 2.43 do
Ubuntu 24.04), lê os workspaces escritos pelos agentes Mutagen das contas de dispositivo e
materializa o shared. A API escuta só em ``127.0.0.1`` do contêiner; um relay ``socat`` de
teste a expõe no loopback do host.
"""

from __future__ import annotations

import io
import json
import os
import random
import shutil
import statistics
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.integration.conftest import wait_until, write_config
from tests.integration_ssh.conftest import (
    DEVS,
    IMAGE,
    PLATFORM,
    REMOTE_PROJECT,
    Container,
    docker,
    make_ssh_home,
)
from tsm_client.adapters.mutagen import MutagenAdapter, SubprocessRunner, mutagen_env
from tsm_client.cli import run as cli_run
from tsm_client.rules import ProjectRules
from tsm_manager.auth import token_sha256

pytestmark = [pytest.mark.ssh, pytest.mark.timeout(1800)]

MANAGER_IMAGE = f"tsm-manager-test:{PLATFORM.split('/')[-1]}"
VENV = "/opt/tsm-venv/bin"
API_PORT, RELAY_PORT = 8740, 8741
SPELLS = "data/scripts/spells.lua"
CREATURES = "data/scripts/creatures.lua"
DEMO = REPO_ROOT / "examples" / "demo-project"


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


TOKENS = {"pca": "ssh-token-pca", "pcb": "ssh-token-pcb", "admin": "ssh-token-admin"}


def manager_config() -> dict:
    return {
        "version": 1, "root": "/srv/ts", "shared_group": "tsm-readers",
        "projects": [{"id": "demo", "bindings": [
            {"id": "demo-pca", "device": "pca", "workspace": "dev-a"},
            {"id": "demo-pcb", "device": "pcb", "workspace": "dev-b"}]}],
        "identities": [
            {"name": "dev-a", "role": "developer", "device": "pca",
             "token_sha256": token_sha256(TOKENS["pca"])},
            {"name": "dev-b", "role": "developer", "device": "pcb",
             "token_sha256": token_sha256(TOKENS["pcb"])},
            {"name": "admin", "role": "admin", "token_sha256": token_sha256(TOKENS["admin"])},
        ],
    }


@dataclass
class SshPc:
    name: str
    root: Path
    cfg_path: Path
    binding: str
    data_dir: Path
    ssh_home: Path

    @property
    def work(self) -> Path:
        return self.root / "work"

    def tsm(self, *args: str, expect: int | None = 0) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli_run(["--config", str(self.cfg_path), *args], out=out, err=err)
        if expect is not None:
            assert code == expect, (f"{self.name}: tsm {' '.join(args)} -> {code}\n"
                                    f"{out.getvalue()}{err.getvalue()}")
        return code, out.getvalue(), err.getvalue()

    def edit(self, rel: str, old: bytes, new: bytes) -> None:
        p = self.work / rel
        data = p.read_bytes()
        assert old in data
        p.write_bytes(data.replace(old, new, 1))

    def sessions(self) -> dict[str, dict]:
        out = self.tsm("status", "--json")[1]
        return {s["role"]: s for s in json.loads(out)["sessions"]}


@dataclass
class SshCollab:
    c: MgrContainer
    pcs: dict[str, SshPc] = field(default_factory=dict)

    @property
    def a(self) -> SshPc:
        return self.pcs["pcA"]

    @property
    def b(self) -> SshPc:
        return self.pcs["pcB"]


@pytest.fixture
def ssh_collab(tmp_path, mgr_container, mutagen_exe, ssh_dir) -> Iterator[SshCollab]:
    c = mgr_container
    c.sh("pkill -u tsm-manager -f 'tsm-manager serve' || true")
    c.setup("restore-host-keys")
    c.setup("reset")
    c.sh("cat > /etc/tsm/manager.json && chgrp tsm-manager /etc/tsm/manager.json && "
         "chmod 0640 /etc/tsm/manager.json", input=json.dumps(manager_config()))
    c.manager("init-project", "--config", "/etc/tsm/manager.json", "--project", "demo",
              "--from", "/opt/demo")
    docker("exec", "-d", "-u", "tsm-manager", c.name, f"{VENV}/tsm-manager", "serve",
           "--config", "/etc/tsm/manager.json", "--port", str(API_PORT))
    import urllib.request

    def health() -> bool:
        with urllib.request.urlopen(f"http://127.0.0.1:{c.api_port}/health", timeout=2) as r:
            return r.status == 200

    wait_until(health, 120, 0.5, "Manager no contêiner")
    env = SshCollab(c)
    for pc_name, (user, _dev, alias) in DEVS.items():
        device = "pca" if pc_name == "pcA" else "pcb"
        root = tmp_path / pc_name
        root.mkdir()
        home = make_ssh_home(root / "ssh-home", c, ssh_dir, user=user, alias=alias)
        tok = root / "token"
        tok.write_text(TOKENS[device], encoding="utf-8")
        ws_dir = "dev-a" if device == "pca" else "dev-b"
        cfg = {
            "version": 2, "device_id": device,
            "mutagen": {"data_directory": str(root / "mutagen-data"),
                        "executable": str(mutagen_exe), "ssh_path": str(ssh_dir),
                        "ssh_home": str(home)},
            "state_directory": str(root / "state"),
            "manager": {"url": f"http://127.0.0.1:{c.api_port}", "token_file": str(tok)},
            "bindings": [{
                "id": f"demo-{device}", "project_id": "demo",
                "local": str(root / "work"), "cache": str(root / "cache"),
                "workspace": f"{alias}:{REMOTE_PROJECT}/workspaces/{ws_dir}",
                "shared": f"{alias}:{REMOTE_PROJECT}/shared",
                "rules": {"allow": [], "ignore": []},
            }],
        }
        p = tmp_path / f"{pc_name}.json"
        p.write_text(json.dumps(cfg, indent=1), encoding="utf-8")
        env.pcs[pc_name] = SshPc(pc_name, root, p, f"demo-{device}", root / "mutagen-data",
                                 home)
    yield env
    for pc in env.pcs.values():
        pc.tsm("teardown", "--stop-daemon", expect=None)
    c.sh("pkill -u tsm-manager -f 'tsm-manager serve' || true")


# ----------------------------------------------------------------


def test_publish_merge_conflict_over_ssh(ssh_collab: SshCollab):
    env = ssh_collab
    a, b = env.a, env.b
    a.tsm("init", "--wait", "300")
    b.tsm("init", "--wait", "300")
    # arquivos distintos
    a.edit(SPELLS, b"mana = 20", b"mana = 21")
    b.edit(CREATURES, b"health = 20", b"health = 22")
    assert "publicado: r2" in a.tsm("publish", SPELLS)[1]
    assert "publicado: r3" in b.tsm("publish", CREATURES)[1]
    a.tsm("pull", "--wait", "300")
    b.tsm("pull", "--wait", "300")
    for pc in (a, b):
        assert b"mana = 21" in (pc.work / SPELLS).read_bytes()
        assert b"health = 22" in (pc.work / CREATURES).read_bytes()
    # mesma linha → bloqueado, pasta intacta, resolução explícita
    a.edit(SPELLS, b"level = 15", b"level = 16")
    b.edit(SPELLS, b"level = 15", b"level = 17")
    a.tsm("publish", SPELLS)
    before = (b.work / SPELLS).read_bytes()
    assert "conflito (content)" in b.tsm("publish", SPELLS, expect=4)[2]
    assert (b.work / SPELLS).read_bytes() == before
    b.tsm("pull", "--wait", "300", "--resolve", f"{SPELLS}=ours")
    assert "publicado: r5" in b.tsm("publish", SPELLS)[1]
    a.tsm("pull", "--wait", "300")
    assert b"level = 17" in (a.work / SPELLS).read_bytes()
    out = env.c.manager("verify", "--config", "/etc/tsm/manager.json")
    assert "verify: ok" in out.stdout
    # o Manager roda no Python do sistema do Ubuntu 24.04 arm64
    assert env.c.sh(f"{VENV}/python -c 'import sys; print(sys.version_info[:2])'"
                    ).stdout.strip() == "(3, 12)"


def test_merge_tree_on_container_git(mgr_container):
    """Merge por caminho no Git do Ubuntu 24.04.

    O ``git merge-tree`` do Git 2.43 infere renomeações mesmo com ``merge.renames=false``
    (registrado abaixo como evidência). O merge por caminho do Manager não infere:
    renomeação = exclusão + criação, e os tipos de conflito são os mesmos do Git 2.53.
    """
    script = r'''
import tempfile, pathlib
from tsm_manager.adapters.git import Git, Author
d = pathlib.Path(tempfile.mkdtemp())
g = Git(d / "r.git"); g.init_bare(); g.check_version()
au = Author("t", "t@t")
def commit(files, parents):
    blobs = {p: g.hash_bytes(c) for p, c in files.items()}
    return g.commit_tree(g.build_tree(None, blobs), parents, "m\n", au)
base = commit({"old.txt": b"1\n2\n3\n4\n5\n6\n", "f.txt": b"a\nb\nc\n", "b.bin": b"\0a"}, [])
ours = commit({"new.txt": b"1\n2\n3\n4\n5\n6\n", "f.txt": b"A\nb\nc\n", "b.bin": b"\0b"},
              [base])
theirs = commit({"old.txt": b"1\n2\n3\n4\n5\nX\n", "f.txt": b"Z\nb\nc\n", "b.bin": b"\0c"},
                [base])
r = g.merge_trees(base, ours, theirs)
raw = g.run("merge-tree", "--write-tree", "--name-only", f"--merge-base={base}", ours, theirs,
            ok_codes=(0, 1)).stdout.decode()
print(g.version())
print(sorted((c.path, c.kind) for c in r.conflicts))
print("old.txt" in raw.split("\n\n")[0].splitlines()[1:])
crlf = "﻿-- t\r\na = 1\r\nb = 2\r\nc = 3\r\nd = 4\r\n".encode()
n, merged = g.merge_file(crlf.replace(b"a = 1", b"a = 10"), crlf,
                         crlf.replace(b"d = 4", b"d = 40"))
print(n == 0 and merged == crlf.replace(b"a = 1", b"a = 10").replace(b"d = 4", b"d = 40"))
'''
    out = mgr_container.sh(f"{VENV}/python -", user="tsm-manager", input=script).stdout
    version_line, conflicts_line, raw_line, crlf_line = out.strip().splitlines()
    assert version_line.startswith("(2, 43")
    assert conflicts_line == ("[('b.bin', 'binary'), ('f.txt', 'content'), "
                              "('old.txt', 'delete_modify')]")
    assert crlf_line == "True"  # no Linux: bytes (CRLF, BOM) preservados no merge
    print(f"\nG1: merge-tree do Git 2.43 marca old.txt como conflito? {raw_line}")


# ----------------------------------------------------------------


def test_shared_permissions_and_no_halt(ssh_collab: SshCollab):
    env = ssh_collab
    a, b = env.a, env.b
    a.tsm("init", "--wait", "300")
    b.tsm("init", "--wait", "300")
    (a.work / "data" / "new").mkdir(parents=True)
    (a.work / "data" / "new" / "x.lua").write_bytes(b"return 'x'\n")
    for rel in ("README.md", SPELLS, CREATURES):
        (a.work / rel).unlink()
    a.tsm("publish", "--all", expect=3)  # 3 de 4 arquivos: exclusão em massa
    assert "publicado: r2" in a.tsm("publish", "--all", "--confirm-deletions")[1]
    shared = f"{REMOTE_PROJECT}/shared"
    stat = env.c.sh(f"cd {shared} && find . -mindepth 1 -exec stat -c '%a %U %G %n' {{}} +"
                    ).stdout.splitlines()
    entries = {line.split(" ", 3)[3]: line.split(" ", 3)[:3] for line in stat}
    for path, (mode, owner, group) in entries.items():
        assert owner == "tsm-manager" and group == "tsm-readers", (path, owner, group)
        is_dir = env.c.sh(f"test -d '{shared}/{path}' && echo d || echo f").stdout.strip()
        assert mode == ("2750" if is_dir == "d" else "640"), (path, mode)
    assert "./.tsm/revision.json" in entries and "./data/new/x.lua" in entries
    assert "./data/scripts/spells.lua" not in entries
    # o dev continua sem escrever no shared
    r = env.c.sh(f"touch {shared}/intruso 2>&1; echo rc=$?", user="tsm-dev-a", check=False)
    assert "rc=0" not in r.stdout
    # nenhuma sessão de download parou por salvaguarda; B converge
    b.tsm("pull", "--wait", "300", "--confirm-deletions")
    assert not (b.work / SPELLS).exists() and (b.work / "data/new/x.lua").exists()
    for pc in (a, b):
        sessions = pc.sessions()
        assert not sessions["download"]["status"].startswith("halted"), sessions["download"]
    assert "verify: ok" in env.c.manager("verify", "--config", "/etc/tsm/manager.json").stdout


# ----------------------------------------------------------------


def _counter_config(alias: str, user: str, port: int, key_name: str, counts: Path) -> str:
    proxy = Path(REPO_ROOT / "tests" / "fixtures" / "traffic" / "count_proxy.py").as_posix()
    python = Path(sys.executable).as_posix()
    return f"""Host {alias}
  HostName 127.0.0.1
  Port {port}
  User {user}
  ProxyCommand "{python}" "{proxy}" %h %p "{counts.as_posix()}"
  IdentityFile ~/.ssh/{key_name}
  IdentitiesOnly yes
  UserKnownHostsFile ~/.ssh/known_hosts
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  BatchMode yes
  PreferredAuthentications publickey
  ClearAllForwardings yes
  RequestTTY no
"""


def _total(counts: Path) -> int:
    data = json.loads(counts.read_text("utf-8"))
    return int(data["sent"]) + int(data["received"])


def _stable_total(counts: Path, quiet: float = 1.5, timeout: float = 120) -> int:
    deadline = time.monotonic() + timeout
    last, since = _total(counts), time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(0.25)
        cur = _total(counts)
        if cur != last:
            last, since = cur, time.monotonic()
        elif time.monotonic() - since >= quiet:
            return cur
    return last


def test_differential_traffic(tmp_path, mgr_container, mutagen_exe, ssh_dir):
    c = mgr_container
    c.sh("pkill -u tsm-manager -f 'tsm-manager serve' || true")
    c.setup("restore-host-keys")
    c.setup("reset")
    user, dev, alias = DEVS["pcA"]
    root = tmp_path / "pcA"
    work = root / "work"
    shutil.copytree(DEMO, work)
    home = make_ssh_home(root / "ssh-home", c, ssh_dir, user=user, alias=alias)
    counts = tmp_path / "counts.json"
    key_name = f"id_ed25519_{user.replace('-', '_')}"
    with open(home / ".ssh" / "config", "a", encoding="utf-8") as fh:
        fh.write("\n" + _counter_config("tsm-traffic-a", user, c.port, key_name, counts))
    cfg_path = tmp_path / "pcA.json"
    # upload pelo alias contado; download pelo alias normal (fora da contagem)
    write_config(root, cfg_path, exe=mutagen_exe, binding="demo-pca",
                 workspace=f"tsm-traffic-a:{REMOTE_PROJECT}/workspaces/{dev}",
                 shared=f"{alias}:{REMOTE_PROJECT}/shared", rules=ProjectRules(),
                 ssh_path=ssh_dir, ssh_home=home)
    rng = random.Random(20261126)
    size = 50 * 1024 * 1024
    big = work / "data" / "big.bin"
    big.write_bytes(rng.randbytes(size))

    def tsm(*args: str) -> str:
        out, err = io.StringIO(), io.StringIO()
        code = cli_run(["--config", str(cfg_path), *args], out=out, err=err)
        assert code == 0, out.getvalue() + err.getvalue()
        return out.getvalue()

    env = mutagen_env(root / "mutagen-data", ssh_path=ssh_dir, ssh_home=home)
    adapter = MutagenAdapter(mutagen_exe, SubprocessRunner(env))
    try:
        tsm("up")
        tsm("flush", "--role", "upload")
        wait_until(lambda: counts.exists(), 60, 0.5, "contador ativo")
        _stable_total(counts)
        # repouso: keepalives (ServerAliveInterval=10) para descontar
        t0, idle0 = time.monotonic(), _total(counts)
        time.sleep(12)
        idle_rate = (_total(counts) - idle0) / (time.monotonic() - t0)

        def measure(action) -> int:
            start_t = time.monotonic()
            start = _stable_total(counts)
            action()
            tsm("flush", "--role", "upload")
            end = _stable_total(counts)
            return max(0, int(end - start - idle_rate * (time.monotonic() - start_t)))

        def t1a():
            with open(big, "r+b") as fh:
                fh.seek(size // 2)
                fh.write(rng.randbytes(16))

        def t1b():
            with open(big, "ab") as fh:
                fh.write(rng.randbytes(1024 * 1024))

        def t1c():
            p = work / SPELLS
            data = p.read_bytes()
            old, new = (b"level = 8,", b"level = 7,") if b"level = 8," in data else (
                b"level = 7,", b"level = 8,")
            p.write_bytes(data.replace(old, new, 1))

        def t1d():
            big.write_bytes(rng.randbytes(size))

        results: dict[str, list[int]] = {k: [] for k in ("T1a", "T1b", "T1c", "T1d")}
        for _ in range(3):
            results["T1a"].append(measure(t1a))
            results["T1b"].append(measure(t1b))
            results["T1c"].append(measure(t1c))
        for _ in range(3):
            results["T1d"].append(measure(t1d))
            size = big.stat().st_size
        summary = {
            "file_bytes": size, "idle_bytes_per_s": round(idle_rate, 1),
            "spells_bytes": (work / SPELLS).stat().st_size,
            **{k: {"runs": v, "median": int(statistics.median(v))} for k, v in results.items()},
        }
        out = Path(os.environ.get("TSM_TRAFFIC_OUT", tmp_path / "traffic.json"))
        out.write_text(json.dumps(summary, indent=1), encoding="utf-8")
        print("\nT1:", json.dumps(summary, indent=1))
        # T1d é a linha de base (arquivo inteiro); T1a precisa ser muito menor
        assert summary["T1d"]["median"] > size * 0.9
        assert summary["T1a"]["median"] < summary["T1d"]["median"]
    finally:
        tsm_out = io.StringIO()
        cli_run(["--config", str(cfg_path), "teardown", "--stop-daemon"], out=tsm_out,
                err=tsm_out)
        adapter.daemon_stop()
