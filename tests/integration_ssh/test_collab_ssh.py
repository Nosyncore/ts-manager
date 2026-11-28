"""Manager e colaboração no contêiner ``linux/arm64``.

O Manager roda **dentro** do contêiner como ``tsm-manager`` (Python 3.12 e Git 2.43 do
Ubuntu 24.04), com a config ``version: 2``. A API escuta só em ``127.0.0.1`` do contêiner;
um relay ``socat`` de teste a expõe no loopback do host.

A publicação pelo Mutagen sobre SSH, com contas de dispositivo ``tsm-d-…`` criadas na
aprovação, exige o helper sob ``sudo`` e o sshd com ``AuthorizedKeysFile`` e
``Match Group``: esses cenários ficam marcados como pulados até a imagem ter essa
infraestrutura. Aqui ficam o Manager no contêiner, o merge no Git do Ubuntu e o tráfego
diferencial do transporte (sem Manager).
"""

from __future__ import annotations

import io
import json
import os
import random
import shutil
import statistics
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.integration.conftest import pc_config, wait_until
from tests.integration_ssh.conftest import (
    API_PORT,
    DEVS,
    REMOTE_PROJECT,
    VENV,
    MgrContainer,
    docker,
    make_ssh_home,
)
from tsm_client.adapters.mutagen import MutagenAdapter, SubprocessRunner, mutagen_env
from tsm_client.cli import run as cli_run
from tsm_client.rules import ProjectRules

pytestmark = [pytest.mark.ssh, pytest.mark.timeout(1800)]

SPELLS = "data/scripts/spells.lua"
DEMO = REPO_ROOT / "examples" / "demo-project"
CONFIG = "/etc/tsm/manager.json"
NEEDS_DEVICE_ACCOUNTS = pytest.mark.skip(
    reason="exige o helper sob sudo e o sshd com AuthorizedKeysFile no contêiner")


def manager_config() -> dict:
    """Manager local no contêiner: sem contas de dispositivo (``provisioner: local``)."""
    return {
        "version": 2, "root": "/srv/ts", "shared_group": "tsm-readers",
        "workspace_group": "tsm-ws", "provisioner": {"mode": "local"},
        "projects": [{"id": "demo"}],
    }


def install_config(c: MgrContainer, data: dict) -> None:
    c.sh(f"cat > {CONFIG} && chgrp tsm-manager {CONFIG} && chmod 0640 {CONFIG}",
         input=json.dumps(data))


def health(c: MgrContainer) -> dict:
    with urllib.request.urlopen(f"http://127.0.0.1:{c.api_port}/health", timeout=2) as r:
        return json.loads(r.read())


def stop_manager(c: MgrContainer) -> None:
    c.sh("pkill -u tsm-manager -f 'tsm-manager serve' || true")


# ----------------------------------------------------------------


def test_manager_v2_in_container(mgr_container):
    """``migrate``, ``init-project`` e ``serve`` como ``tsm-manager``, com os grupos reais."""
    c = mgr_container
    stop_manager(c)
    c.setup("reset")
    shared = f"{REMOTE_PROJECT}/shared"
    c.sh(f"find {shared} -mindepth 1 -delete")  # o shared nasce da materialização do r1
    c.sh("rm -rf /srv/ts/manager && install -d -o tsm-manager -g tsm-manager -m 0700 "
         "/srv/ts/manager")
    # a config da identidade de teste é recusada, com a orientação de migração
    install_config(c, {"version": 1, "root": "/srv/ts", "identities": [],
                       "projects": [{"id": "demo", "bindings": []}]})
    old = c.manager("migrate", "--config", CONFIG, check=False)
    assert old.returncode == 2 and "não é mais aceita" in old.stderr, old.stderr
    install_config(c, manager_config())
    groups = c.sh("id -nG tsm-manager").stdout.split()
    assert {"tsm-readers", "tsm-ws"} <= set(groups), groups
    c.manager("migrate", "--config", CONFIG)
    c.manager("init-project", "--config", CONFIG, "--project", "demo", "--from", "/opt/demo")
    docker("exec", "-d", "-u", "tsm-manager", c.name, f"{VENV}/tsm-manager", "serve",
           "--config", CONFIG, "--port", str(API_PORT))
    try:
        wait_until(lambda: health(c)["ok"] is True, 120, 0.5, "Manager no contêiner")
        assert health(c)["server_id"]
        stat = c.sh(f"cd {shared} && find . -mindepth 1 -exec stat -c '%a %U %G %n' {{}} +"
                    ).stdout.splitlines()
        entries = {line.split(" ", 3)[3]: line.split(" ", 3)[:3] for line in stat}
        assert "./.tsm/revision.json" in entries and f"./{SPELLS}" in entries
        for path, (mode, owner, group) in entries.items():
            assert owner == "tsm-manager" and group == "tsm-readers", (path, owner, group)
            is_dir = c.sh(f"test -d '{shared}/{path}' && echo d || echo f").stdout.strip()
            assert mode == ("2750" if is_dir == "d" else "640"), (path, mode)
        r = c.sh(f"touch {shared}/intruso 2>&1; echo rc=$?", user="tsm-dev-a", check=False)
        assert "rc=0" not in r.stdout  # dispositivo não escreve no shared
        assert "verify: ok" in c.manager("verify", "--config", CONFIG).stdout
        assert c.sh(f"{VENV}/python -c 'import sys; print(sys.version_info[:2])'"
                    ).stdout.strip() == "(3, 12)"
    finally:
        stop_manager(c)


@NEEDS_DEVICE_ACCOUNTS
def test_publish_merge_conflict_over_ssh():
    """Dois dispositivos aprovados publicam pelo Mutagen sobre SSH: arquivos distintos
    mesclam, a mesma linha bloqueia sem tocar a pasta e a resolução explícita publica."""


@NEEDS_DEVICE_ACCOUNTS
def test_shared_permissions_and_no_halt():
    """Exclusão em massa confirmada, shared ``tsm-manager:tsm-readers`` (``2750``/``0640``)
    escrito pelo Manager e nenhuma sessão de download parada por salvaguarda."""


# ----------------------------------------------------------------


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
    # o proxy troca o arquivo com os.replace; no Windows a leitura pode cair na troca
    deadline = time.monotonic() + 2
    while True:
        try:
            data = json.loads(counts.read_text("utf-8"))
            return int(data["sent"]) + int(data["received"])
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


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
    stop_manager(c)
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
    # upload pelo alias contado; download pelo alias normal (fora da contagem)
    cfg = pc_config(root, exe=mutagen_exe, binding="demo-pca",
                    workspace=f"tsm-traffic-a:{REMOTE_PROJECT}/workspaces/{dev}",
                    shared=f"{alias}:{REMOTE_PROJECT}/shared", rules=ProjectRules(),
                    ssh_path=ssh_dir, ssh_home=home)
    rng = random.Random(20261126)
    size = 50 * 1024 * 1024
    big = work / "data" / "big.bin"
    big.write_bytes(rng.randbytes(size))

    def tsm(*args: str) -> str:
        out, err = io.StringIO(), io.StringIO()
        code = cli_run(list(args), config=cfg, out=out, err=err)
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
        cli_run(["teardown", "--stop-daemon"], config=cfg, out=tsm_out, err=tsm_out)
        adapter.daemon_stop()
