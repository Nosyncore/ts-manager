"""Cria o ambiente da demo de colaboração: Manager local + dois "PCs".

Layout (em ``--root``, padrão ``.collab``)::

    manager.json                    config do Manager (identidades de teste)
    srv/manager/manager.db          banco do Manager (criado por tsm-manager migrate)
    srv/projects/demo/...           workspaces, shared e history (Git interno)
    pcA.json  pcA/{token, ...}      Client do dev A (config version 2)
    pcB.json  pcB/{token, ...}      Client do dev B
    admin.json  admin-token         identidade admin (rollback, auditoria)

O banco é criado com ``tsm-manager migrate`` e o projeto, inicializado com
``tsm-manager init-project`` a partir de ``examples/demo-project`` (revisão r1). As
pastas de trabalho não existem: cada PC as cria com ``tsm init``. Os tokens são gerados
aqui e só valem para esta demo local.

``--reset`` apaga um ambiente criado antes por este script (identificado por marcador).
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "demo-project"
MARKER = ".tsm-collab-root"
PORT = 8740


def _sha(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()


def create(root: Path, port: int) -> None:
    root.mkdir(parents=True)
    (root / MARKER).write_text("criado por scripts/collab_local_setup.py\n", encoding="utf-8")
    tokens = {k: secrets.token_urlsafe(24) for k in ("pca", "pcb", "admin")}
    manager = {
        "version": 1, "root": "srv",
        "projects": [{"id": "demo", "bindings": [
            {"id": "demo-pca", "device": "pca", "workspace": "pca"},
            {"id": "demo-pcb", "device": "pcb", "workspace": "pcb"}]}],
        "identities": [
            {"name": "dev-a", "role": "developer", "device": "pca",
             "token_sha256": _sha(tokens["pca"])},
            {"name": "dev-b", "role": "developer", "device": "pcb",
             "token_sha256": _sha(tokens["pcb"])},
            {"name": "admin", "role": "admin", "token_sha256": _sha(tokens["admin"])},
        ],
    }
    (root / "manager.json").write_text(json.dumps(manager, indent=2), encoding="utf-8")
    subprocess.run([sys.executable, "-m", "tsm_manager", "migrate", "--config",
                    str(root / "manager.json")], check=True)
    subprocess.run([sys.executable, "-m", "tsm_manager", "init-project", "--config",
                    str(root / "manager.json"), "--project", "demo", "--from", str(DEMO)],
                   check=True)
    url = f"http://127.0.0.1:{port}"
    for name, device in (("pcA", "pca"), ("pcB", "pcb")):
        (root / name).mkdir()
        (root / name / "token").write_text(tokens[device], encoding="utf-8")
        cfg = {
            "version": 2, "device_id": device,
            "mutagen": {"data_directory": f"{name}/mutagen-data"},
            "state_directory": f"{name}/state",
            "manager": {"url": url, "token_file": f"{name}/token"},
            "bindings": [{
                "id": f"demo-{device}", "project_id": "demo",
                "local": f"{name}/work", "cache": f"{name}/cache",
                "workspace": f"srv/projects/demo/workspaces/{device}",
                "shared": "srv/projects/demo/shared",
            }],
        }
        (root / f"{name}.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    (root / "admin-token").write_text(tokens["admin"], encoding="utf-8")
    admin = json.loads((root / "pcA.json").read_text(encoding="utf-8"))
    admin["manager"]["token_file"] = "admin-token"
    (root / "admin.json").write_text(json.dumps(admin, indent=2), encoding="utf-8")


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
        for name in ("pcA", "pcB"):
            cfg = root / f"{name}.json"
            if cfg.is_file():
                subprocess.run([sys.executable, "-m", "tsm_client", "--config", str(cfg),
                                "teardown", "--stop-daemon"], check=False)
        shutil.rmtree(root)
    create(root, args.port)
    rel = root.relative_to(REPO_ROOT) if root.is_relative_to(REPO_ROOT) else root
    print(f"ambiente criado em {rel}")
    print(f"  Manager: .venv\\Scripts\\tsm-manager serve --config {rel}\\manager.json "
          f"--port {args.port}")
    print(f"  PC A:    .venv\\Scripts\\tsm --config {rel}\\pcA.json init")
    print(f"  PC B:    .venv\\Scripts\\tsm --config {rel}\\pcB.json init")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
