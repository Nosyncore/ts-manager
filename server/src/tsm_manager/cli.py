"""CLI ``tsm-manager`` (no servidor): init-project, serve, recover, verify, token.

Códigos de saída: 0 sucesso; 1 falha; 2 config/uso inválido; 3 verificação com problemas.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from tsm_manager import __version__
from tsm_manager.auth import new_token, token_sha256
from tsm_manager.config import ManagerConfigError, load_manager_config
from tsm_manager.project import ProjectError

EXIT_OK, EXIT_FAIL, EXIT_CONFIG, EXIT_PROBLEMS = 0, 1, 2, 3


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tsm-manager", description="TS Manager — servidor")
    p.add_argument("--version", action="version", version=f"tsm-manager {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="comando")
    ip = sub.add_parser("init-project", help="cria o Git interno, r1 e o shared")
    ip.add_argument("--config", "-c", required=True)
    ip.add_argument("--project", required=True)
    ip.add_argument("--from", dest="source", required=True, help="diretório da revisão r1")
    sv = sub.add_parser("serve", help="sobe a API (só loopback)")
    sv.add_argument("--config", "-c", required=True)
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8740)
    rc = sub.add_parser("recover", help="conclui/descarta operações do diário; reconcilia o shared")
    rc.add_argument("--config", "-c", required=True)
    vf = sub.add_parser("verify", help="confere shared, revision.json, vínculos e diário")
    vf.add_argument("--config", "-c", required=True)
    tk = sub.add_parser("token", help="gera um token de teste e o SHA-256 para a config")
    tk.add_argument("--quiet", action="store_true", help="só o token")
    return p


def run(argv: Sequence[str], out: TextIO | None = None, err: TextIO | None = None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    args = build_parser().parse_args(list(argv))
    if args.command == "token":
        token = new_token()
        out.write(f"{token}\n" if args.quiet else f"token: {token}\nsha256: "
                  f"{token_sha256(token)}\n")
        return EXIT_OK
    try:
        cfg = load_manager_config(args.config)
    except ManagerConfigError as exc:
        err.write(f"tsm-manager: config inválida: {exc}\n")
        return EXIT_CONFIG

    from tsm_manager.api import Manager  # importa FastAPI só quando necessário

    manager = Manager(cfg)
    try:
        match args.command:
            case "init-project":
                svc = manager.projects.get(args.project)
                if svc is None:
                    err.write(f"tsm-manager: projeto desconhecido: {args.project}\n")
                    return EXIT_CONFIG
                outcome = svc.init_project(Path(args.source))
                if outcome.status != "published":
                    for e in outcome.payload.get("errors", []):
                        err.write(f"  {e['path']}: {e['reason']}\n")
                    return EXIT_FAIL
                out.write(f"{args.project}: r1 {outcome.payload['commit'][:12]}\n")
            case "recover":
                for note in manager.recover_all():
                    out.write(note + "\n")
                out.write("recover: ok\n")
            case "verify":
                problems = []
                for pid, svc in manager.projects.items():
                    if not svc.initialized:
                        problems.append(f"{pid}: não inicializado")
                        continue
                    problems += [f"{pid}: {p}" for p in svc.verify()]
                for p in problems:
                    out.write(p + "\n")
                out.write("verify: ok\n" if not problems else "")
                return EXIT_PROBLEMS if problems else EXIT_OK
            case "serve":
                if not is_loopback(args.host):
                    err.write("tsm-manager: a API só escuta em loopback\n")
                    return EXIT_CONFIG
                import uvicorn

                from tsm_manager.api import create_app

                for note in manager.recover_all():
                    out.write(note + "\n")
                out.flush()
                uvicorn.run(create_app(manager), host=args.host, port=args.port,
                            log_level="warning", access_log=False)
    except ProjectError as exc:
        err.write(f"tsm-manager: {exc}\n")
        return EXIT_FAIL
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    return run(sys.argv[1:] if argv is None else argv)
