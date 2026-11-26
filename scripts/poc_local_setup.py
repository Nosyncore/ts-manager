"""Cria o ambiente da demo local: dois "PCs" simulados e um "servidor" em diretórios.

Layout (em ``--root``, padrão ``.poc``)::

    pcA/work   pcA/cache   pcA/mutagen-data   pcA.json
    pcB/work   pcB/cache   pcB/mutagen-data   pcB.json
    server/projects/demo/workspaces/devA|devB
    server/projects/demo/shared        (semeado a partir de examples/demo-project)

As pastas de trabalho recebem o projeto fictício e arquivos que devem ser ignorados
(``.env``, ``logs/``, ``build/``, ``*.tmp``, ``__pycache__/``). A cópia para o shared
aqui é só preparação da demo: não é publicação.

``--reset`` apaga um ambiente criado antes por este script (identificado por um
marcador), depois de garantir que não há sessões gerenciadas rodando nele.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "demo-project"
MARKER = ".tsm-poc-root"

IGNORED_SAMPLES = {
    ".env": "SECRET=nao-sincronizar\n",
    "logs/server.log": "log local\n",
    "build/output.bin": "artefato\n",
    "scratch.tmp": "temporário\n",
    "__pycache__/x.pyc": "cache\n",
}


def _config(device: str, binding: str, dev_dir: str) -> dict:
    return {
        "version": 1,
        "device_id": device,
        "mutagen": {"data_directory": f"{device}/mutagen-data"},
        "bindings": [
            {
                "id": binding,
                "project_id": "demo",
                "local": f"{device}/work",
                "cache": f"{device}/cache",
                "workspace": f"server/projects/demo/workspaces/{dev_dir}",
                "shared": "server/projects/demo/shared",
            }
        ],
    }


def create(root: Path) -> None:
    root.mkdir(parents=True)
    (root / MARKER).write_text("criado por scripts/poc_local_setup.py\n", encoding="utf-8")
    project = root / "server" / "projects" / "demo"
    (project / "workspaces").mkdir(parents=True)
    shutil.copytree(DEMO, project / "shared")
    for device, binding, dev_dir in (("pcA", "demo-pca", "devA"), ("pcB", "demo-pcb", "devB")):
        work = root / device / "work"
        shutil.copytree(DEMO, work)
        for rel, content in IGNORED_SAMPLES.items():
            target = work / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        cfg = _config(device, binding, dev_dir)
        (root / f"{device}.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--root", type=Path, default=REPO_ROOT / ".poc")
    ap.add_argument("--reset", action="store_true", help="apaga e recria um ambiente anterior")
    args = ap.parse_args(argv)
    root: Path = args.root.resolve()

    if root.exists():
        if not args.reset:
            print(f"{root} já existe; use --reset para recriar", file=sys.stderr)
            return 1
        if not (root / MARKER).is_file():
            print(f"{root} não foi criado por este script; não será apagado", file=sys.stderr)
            return 1
        from tsm_client.cli import run

        for device in ("pcA", "pcB"):
            cfg = root / f"{device}.json"
            if cfg.is_file() and run(["--config", str(cfg), "teardown", "--stop-daemon"]) != 0:
                print(f"teardown de {device} falhou; ambiente mantido", file=sys.stderr)
                return 1
        shutil.rmtree(root)

    create(root)
    print(f"ambiente criado em {root}")
    print(f"  tsm --config {root / 'pcA.json'} up")
    print(f"  tsm --config {root / 'pcB.json'} up")
    return 0


if __name__ == "__main__":
    sys.exit(main())
