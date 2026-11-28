"""Manager real como processo para os testes de integração: config ``version: 2`` local.

``tsm-manager serve`` numa porta livre de ``127.0.0.1``, com ``LocalProvisioner`` (sem
contas do sistema), ``ssh-keygen`` real e uma chave de host Ed25519 gerada para o teste. A
CLI (``migrate``, ``init-project``, ``bootstrap-admin``, ``requests approve``…) roda como
processo, como o operador faria. Falhas injetadas (``TSM_MANAGER_FAULTS``) só valem com
``test_faults``.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from tests.conftest import REPO_ROOT
from tests.integration.conftest import wait_until
from tests.manager.identity_http import KEYGEN, Device, Http
from tests.sshsig_signer import generate_key
from tsm_manager.db import Database

DEMO = REPO_ROOT / "examples" / "demo-project"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def write_config(tmp: Path, root: Path, *, keygen: Path = KEYGEN, test_faults: bool = False,
                 projects: tuple[str, ...] = ("demo", "outro")) -> Path:
    """Config ``version: 2`` local, com uma chave de host Ed25519 gerada para o teste."""
    if not (tmp / "hostkey").exists():
        generate_key(KEYGEN, tmp / "hostkey", "ssh_host_ed25519_key")
    cfg = tmp / "cfg" / "manager.json"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({
        "version": 2, "root": str(root), "shared_group": "tsm-readers",
        "workspace_group": "tsm-ws", "provisioner": {"mode": "local"},
        "ssh": {"host": "127.0.0.1", "port": 22,
                "host_key_files": [str(tmp / "hostkey" / "ssh_host_ed25519_key.pub")]},
        "auth": {"ssh_keygen": str(keygen)}, "test_faults": test_faults,
        "projects": [{"id": p} for p in projects],
    }), encoding="utf-8")
    return cfg


class Server:
    def __init__(self, tmp: Path, *, test_faults: bool = False,
                 projects: tuple[str, ...] = ("demo", "outro"), port: int | None = None) -> None:
        self.tmp = tmp
        self.root = tmp / "srv"
        self.cfg = write_config(tmp, self.root, test_faults=test_faults, projects=projects)
        self.port = port or free_port()  # port: a mesma de outro Manager (troca de servidor)
        self.proc: subprocess.Popen | None = None
        self.log = tmp / "serve.log"

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def database(self) -> Path:
        return self.root / "manager" / "manager.db"

    def cli(self, *args: str, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
        r = subprocess.run([sys.executable, "-m", "tsm_manager", *args, "--config",
                            str(self.cfg)], capture_output=True, text=True, encoding="utf-8",
                           timeout=300)
        assert r.returncode in ok, f"{args}: {r.returncode}\n{r.stdout}{r.stderr}"
        return r

    def init_project(self, project: str = "demo") -> None:
        """``init-project`` a partir do projeto de exemplo, com o ``project_id`` pedido."""
        src = DEMO
        if project != "demo":
            src = self.tmp / f"{project}-src"
            if not src.exists():
                shutil.copytree(DEMO, src)
                (src / "ts-project.json").write_text(
                    json.dumps({"project_id": project, "version": 1}), encoding="utf-8")
        self.cli("init-project", "--project", project, "--from", str(src))

    def start(self, faults: dict[str, Any] | None = None) -> None:
        env = dict(os.environ)
        env.pop("TSM_MANAGER_FAULTS", None)
        if faults:
            env["TSM_MANAGER_FAULTS"] = json.dumps(faults)
        self.log = self.tmp / f"serve-{int(time.time() * 1000)}.log"
        fh = open(self.log, "wb")  # noqa: SIM115 - herdado pelo processo filho
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "tsm_manager", "serve", "--config", str(self.cfg),
             "--port", str(self.port)], stdout=fh, stderr=subprocess.STDOUT, env=env)
        fh.close()

        def up() -> bool:
            if self.proc.poll() is not None:
                raise AssertionError(self.log.read_text("utf-8", "replace"))
            return Http(self.port).get("/health").status == 200

        wait_until(up, 60, 0.2, "Manager no ar")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(10)
        self.proc = None

    def restart(self, faults: dict[str, Any] | None = None) -> None:
        self.stop()
        self.start(faults)

    def device(self, n: int, name: str) -> Device:
        return Device.create(self.port, self.tmp / "pcs" / f"pc{n}", n, name)

    def rows(self, sql: str, params: tuple = ()) -> list[dict]:
        """Consulta de leitura no banco do Manager (o teste nunca escreve nele)."""
        db = Database(self.database)
        try:
            with db.read() as conn:
                return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            db.close()

    def audit(self, event: str) -> list[dict]:
        rows = self.rows("SELECT fields FROM audit_logs WHERE event = ? ORDER BY id", (event,))
        return [json.loads(r["fields"]) for r in rows]
