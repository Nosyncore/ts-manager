"""CLI ``tsm-manager`` (no servidor).

Comandos: ``migrate``, ``init-project``, ``serve``, ``recover``, ``verify`` e, com a config
``version: 2``, os de identidade (``bootstrap-admin``, ``invites``, ``requests``, ``users``,
``devices``; ver ``cli_identity``). ``token`` gera tokens da identidade de teste da config
``version: 1`` (será removido).

``serve``, ``init-project``, ``recover``, ``verify`` e os comandos de identidade recusam
banco ausente ou desatualizado: o banco é criado e atualizado só pelo ``migrate``.

Códigos de saída: 0 sucesso; 1 falha ou recusa; 2 config/uso inválido; 3 concluído com
pendências (``verify`` com problemas, operação de provisionamento pendente, ``migrate
--status`` com banco ausente ou migrations pendentes).
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from tsm_manager import __version__, cli_identity
from tsm_manager.auth import new_token, token_sha256
from tsm_manager.config import ManagerConfig, ManagerConfigError, load_manager_config
from tsm_manager.db import Database, MigrationError, require_current, schema_status, server_id
from tsm_manager.db import upgrade as db_upgrade
from tsm_manager.identity.base import IdentityError
from tsm_manager.project import ProjectError
from tsm_manager.startup import StartupError

EXIT_OK, EXIT_FAIL, EXIT_CONFIG, EXIT_PROBLEMS = 0, 1, 2, 3
LEGACY_WARNING = ("tsm-manager: aviso: a config version 1 usa a identidade de teste por "
                  "token; use a version 2\n")


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _with_config(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", "-c", required=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tsm-manager", description="TS Manager — servidor")
    p.add_argument("--version", action="version", version=f"tsm-manager {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="comando")
    mg = sub.add_parser("migrate", help="cria ou atualiza o banco do Manager")
    _with_config(mg)
    mg.add_argument("--status", action="store_true", help="só mostra a versão do esquema")
    ip = sub.add_parser("init-project", help="cria o Git interno, r1 e o shared")
    _with_config(ip)
    ip.add_argument("--project", required=True)
    ip.add_argument("--from", dest="source", required=True, help="diretório da revisão r1")
    sv = sub.add_parser("serve", help="sobe a API (só loopback)")
    _with_config(sv)
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8740)
    rc = sub.add_parser("recover", help="conclui operações do diário e de provisionamento")
    _with_config(rc)
    vf = sub.add_parser("verify", help="confere shared, revision.json, vínculos, diário e "
                                       "contas")
    _with_config(vf)
    cli_identity.add_commands(sub, _with_config)
    tk = sub.add_parser("token", help="gera um token da identidade de teste (config version 1)")
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
    if args.command == "migrate":
        return _migrate(cfg, args.status, out, err)
    if args.command in cli_identity.COMMANDS and not cfg.is_v2:
        err.write(f"tsm-manager: {args.command} exige a config version 2\n")
        return EXIT_CONFIG
    if args.command == "serve":
        if not is_loopback(args.host):
            err.write("tsm-manager: a API só escuta em loopback\n")
            return EXIT_CONFIG
        if cfg.is_v2:
            from tsm_manager.startup import check_process_groups

            try:
                check_process_groups(cfg)
            except StartupError as exc:
                err.write(f"tsm-manager: {exc}\n")
                return EXIT_FAIL
        else:
            err.write(LEGACY_WARNING)

    from tsm_manager.services import Manager

    db = Database(cfg.database)
    try:
        require_current(db)
    except MigrationError as exc:
        db.close()
        err.write(f"tsm-manager: {exc}\n")
        return EXIT_FAIL
    manager = Manager(cfg, db=db)
    try:
        match args.command:
            case "init-project":
                return _init_project(manager, args, out, err)
            case "recover":
                return _recover(manager, out)
            case "verify":
                return _verify(manager, out)
            case "serve":
                return _serve(manager, args, out)
            case _:
                return cli_identity.run(args, manager, out)
    except ProjectError as exc:
        err.write(f"tsm-manager: {exc}\n")
        return EXIT_FAIL
    except StartupError as exc:
        err.write(f"tsm-manager: {exc}\n")
        return EXIT_FAIL
    except IdentityError as exc:
        err.write(f"tsm-manager: {exc.code}: {exc.message}\n")
        return EXIT_FAIL
    finally:
        manager.close()


def _init_project(manager, args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
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
    return EXIT_OK


def _recover(manager, out: TextIO) -> int:
    for note in manager.recover_all():
        out.write(note + "\n")
    code = EXIT_OK
    if manager.identity is not None:
        for r in manager.identity.provisioning.recover():
            line = f"provisionamento: operação {r.op_id} ({r.action}, dispositivo " \
                   f"{r.device_id}): {r.status}"
            out.write(line + (f" — {r.error}" if r.error else "") + "\n")
            if r.status == "pending":
                code = EXIT_PROBLEMS
    out.write("recover: ok\n" if code == EXIT_OK else "recover: operações ainda pendentes\n")
    return code


def _verify(manager, out: TextIO) -> int:
    problems = []
    for pid, svc in manager.projects.items():
        if not svc.initialized:
            problems.append(f"{pid}: não inicializado")
            continue
        problems += [f"{pid}: {p}" for p in svc.verify()]
    if manager.identity is not None:
        from tsm_manager.provisioning.verify import verify_accounts

        problems += verify_accounts(manager.identity.provisioning)
    for p in problems:
        out.write(p + "\n")
    out.write("verify: ok\n" if not problems else "")
    return EXIT_PROBLEMS if problems else EXIT_OK


def _serve(manager, args: argparse.Namespace, out: TextIO) -> int:
    import uvicorn

    from tsm_manager.api import create_app

    def log(line: str) -> None:
        out.write(line + "\n")
        out.flush()

    maintenance = None
    if manager.identity is not None:
        from tsm_manager.startup import prepare_identity

        maintenance = prepare_identity(manager, log=log)
        maintenance.start()
    else:
        for note in manager.recover_all():
            log(note)
    out.flush()
    try:
        uvicorn.run(create_app(manager), host=args.host, port=args.port, log_level="warning",
                    access_log=False)
    finally:
        if maintenance is not None:
            maintenance.stop()
    return EXIT_OK


def _migrate(cfg: ManagerConfig, status_only: bool, out: TextIO, err: TextIO) -> int:
    if status_only and not cfg.database.is_file():
        out.write(f"banco: ausente ({cfg.database})\n")
        return EXIT_PROBLEMS
    db = Database(cfg.database)
    try:
        if status_only:
            st = schema_status(db)
            out.write(f"banco: {cfg.database}\nesquema: versão {st.current} de {st.latest}\n")
            for mg in st.pending:
                out.write(f"  pendente: {mg.version:04d}_{mg.name}\n")
            return EXIT_OK if st.up_to_date else EXIT_PROBLEMS
        applied = db_upgrade(db, backup_dir=cfg.backups)
        st = schema_status(db)
        for v in applied:
            out.write(f"aplicada: {v:04d}\n")
        out.write(f"esquema: versão {st.current} de {st.latest}; server_id {server_id(db)}\n")
        return EXIT_OK
    except MigrationError as exc:
        err.write(f"tsm-manager: {exc}\n")
        return EXIT_FAIL
    finally:
        db.close()


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    return run(sys.argv[1:] if argv is None else argv)
