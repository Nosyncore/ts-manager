"""Cria o ambiente da demo local: Manager com identidade real + admin e dois "PCs".

Layout (em ``--root``, padrão ``.collab``)::

    manager.json                    config do Manager (version 2, provisionador local)
    srv/manager/manager.db          banco do Manager (criado por tsm-manager migrate)
    srv/projects/demo/...           workspaces, shared e history (Git interno)
    admin/home                      diretório do tsm do admin (bootstrap)
    pcA/home  pcB/home              diretórios do tsm dos devs A e B

O script cria o banco (``migrate``), inicializa o projeto a partir de
``examples/demo-project`` (revisão r1) e sobe o Manager só durante o cadastro:

1. ``tsm-manager bootstrap-admin`` → ``tsm enroll`` do admin → ``tsm-manager requests
   approve`` com o fingerprint mostrado pelo ``enroll``;
2. para A e B: ``tsm admin invite create`` (pelo admin) → ``tsm enroll`` do dev →
   ``tsm admin requests approve`` com o fingerprint.

Cada dispositivo tem a própria chave Ed25519 no seu ``home``. As pastas de trabalho não
existem: cada PC as cria com ``tsm bind`` (vínculo + ``init``), com o Manager no ar.

``--reset`` apaga um ambiente criado antes por este script (identificado por marcador),
depois de encerrar as sessões do Mutagen de cada ``home``.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "demo-project"
MARKER = ".tsm-collab-root"
PORT = 8740
PCS = ("admin", "pcA", "pcB")


def manager(root: Path, *args: str) -> str:
    r = subprocess.run([sys.executable, "-m", "tsm_manager", *args, "--config",
                        str(root / "manager.json")], capture_output=True, text=True,
                       encoding="utf-8")
    if r.returncode != 0:
        raise SystemExit(f"tsm-manager {args[0]} falhou ({r.returncode}):\n{r.stderr}")
    return r.stdout


def tsm(root: Path, pc: str, *args: str) -> str:
    r = subprocess.run([sys.executable, "-m", "tsm_client", "--home",
                        str(root / pc / "home"), *args], capture_output=True, text=True,
                       encoding="utf-8")
    if r.returncode != 0:
        raise SystemExit(f"tsm ({pc}) {args[0]} falhou ({r.returncode}):\n{r.stderr}")
    return r.stdout


def remove_tree(root: Path) -> None:
    """Apaga o ambiente; os objetos do Git interno são somente leitura no Windows."""
    def retry(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    shutil.rmtree(root, onexc=retry)


def wait_health(url: str, proc: subprocess.Popen, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"o Manager saiu (código {proc.returncode}); a porta está livre?")
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=2) as resp:
                if resp.status == 200:
                    return
        except OSError:
            time.sleep(0.3)
    raise SystemExit("o Manager não respondeu a tempo")


def enroll(root: Path, pc: str, url: str, code: str, name: str) -> dict:
    return json.loads(tsm(root, pc, "enroll", "--manager", url, "--invite", code, "--name",
                          name, "--device-name", f"{pc} da demo", "--json"))


def create(root: Path, port: int) -> None:
    root.mkdir(parents=True)
    (root / MARKER).write_text("criado por scripts/collab_local_setup.py\n", encoding="utf-8")
    (root / "manager.json").write_text(json.dumps({
        "version": 2, "root": "srv", "shared_group": "tsm-readers",
        "workspace_group": "tsm-ws", "provisioner": {"mode": "local"},
        "projects": [{"id": "demo"}],
    }, indent=2), encoding="utf-8")
    manager(root, "migrate")
    manager(root, "init-project", "--project", "demo", "--from", str(DEMO))
    url = f"http://127.0.0.1:{port}"
    log = open(root / "setup-serve.log", "wb")  # noqa: SIM115 - fechado abaixo
    proc = subprocess.Popen([sys.executable, "-m", "tsm_manager", "serve", "--config",
                             str(root / "manager.json"), "--port", str(port)],
                            stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_health(url, proc)
        boot = json.loads(manager(root, "bootstrap-admin", "--project", "demo", "--json"))
        admin = enroll(root, "admin", url, boot["code"], "Admin")
        manager(root, "requests", "approve", admin["device_id"], "--fingerprint",
                admin["fingerprint"])
        print(f"admin: dispositivo {admin['device_id']} aprovado ({admin['fingerprint']})")
        for pc, name in (("pcA", "Dev A"), ("pcB", "Dev B")):
            invite = json.loads(tsm(root, "admin", "admin", "invite", "create", "--project",
                                    "demo", "--json"))
            dev = enroll(root, pc, url, invite["code"], name)
            tsm(root, "admin", "admin", "requests", "approve", dev["device_id"],
                "--fingerprint", dev["fingerprint"])
            print(f"{pc}: dispositivo {dev['device_id']} aprovado ({dev['fingerprint']})")
    finally:
        proc.terminate()
        proc.wait(10)
        log.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(REPO_ROOT / ".collab"))
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--reset", action="store_true", help="apaga um ambiente anterior")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    if root.exists():
        if not args.reset:
            print(f"{root} já existe (use --reset para recriar)", file=sys.stderr)
            return 2
        if not (root / MARKER).is_file():
            print(f"{root} não foi criado por este script; nada apagado", file=sys.stderr)
            return 2
        for pc in PCS:
            home = root / pc / "home"
            if (home / "config.json").is_file():
                subprocess.run([sys.executable, "-m", "tsm_client", "--home", str(home),
                                "teardown", "--stop-daemon"], check=False)
        remove_tree(root)
    create(root, args.port)
    rel = root.relative_to(REPO_ROOT) if root.is_relative_to(REPO_ROOT) else root
    print(f"ambiente criado em {rel}")
    print(f"  Manager: .venv\\Scripts\\tsm-manager serve --config {rel}\\manager.json "
          f"--port {args.port}")
    for pc in ("pcA", "pcB", "admin"):
        print(f"  {pc + ':':6}   .venv\\Scripts\\tsm --home {rel}\\{pc}\\home bind --project "
              f"demo --local {rel}\\{pc}\\work")
    print("  depois: tsm --home <home> status | publish | pull | history | whoami "
          "(rollback e audit pelo admin)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
