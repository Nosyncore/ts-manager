"""CLI ``tsm`` (argparse, sem dependências de runtime).

Códigos de saída:
  0  sucesso
  1  falha do Mutagen/daemon
  2  configuração ou vínculo inválido (inclui erros de uso)
  3  recusado por segurança (sessão parada por salvaguarda, config alterada)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

from tsm_client import __version__
from tsm_client.adapters.mutagen import MutagenAdapter, MutagenError, SubprocessRunner, mutagen_env
from tsm_client.config import Config, ConfigError, load_config
from tsm_client.paths import PathError
from tsm_client.rules import RulesError
from tsm_client.service import RefusedError, TransportService, resolve_executable
from tsm_client.sessions import Role, SessionRuleError

EXIT_OK, EXIT_MUTAGEN, EXIT_CONFIG, EXIT_REFUSED = 0, 1, 2, 3

ServiceFactory = Callable[[Config], TransportService]


def default_service(cfg: Config) -> TransportService:
    env = mutagen_env(
        cfg.mutagen.data_directory,
        ssh_path=cfg.mutagen.ssh_path,
        ssh_home=cfg.mutagen.ssh_home,
    )
    adapter = MutagenAdapter(resolve_executable(cfg), SubprocessRunner(env))
    return TransportService(cfg, adapter)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tsm", description="TS Manager — transporte")
    p.add_argument("--version", action="version", version=f"tsm {__version__}")
    p.add_argument("--config", "-c", required=True, help="arquivo de configuração do dispositivo")
    sub = p.add_subparsers(dest="command", required=True, metavar="comando")
    sub.add_parser("doctor", help="verifica Mutagen, ssh e daemon")
    sub.add_parser("up", help="cria ou retoma as sessões (idempotente)")
    st = sub.add_parser("status", help="estado das sessões gerenciadas")
    st.add_argument("--json", action="store_true", help="saída em JSON")
    fl = sub.add_parser("flush", help="força um ciclo de sincronização e espera terminar")
    fl.add_argument("--role", choices=[r.value for r in Role], default=None)
    sub.add_parser("pause", help="desconecta (pausa) as sessões gerenciadas")
    rs = sub.add_parser("resume", help="retoma sessões pausadas")
    rs.add_argument("--confirm-halted", action="store_true",
                    help="retoma também sessões paradas por salvaguarda (halted-on-root-*)")
    td = sub.add_parser("teardown", help="termina somente as sessões gerenciadas desta config")
    td.add_argument("--stop-daemon", action="store_true", help="para o daemon isolado no final")
    return p


def _print_status(service: TransportService, out: TextIO, as_json: bool) -> None:
    if not service.adapter.daemon_running():
        if as_json:
            out.write(json.dumps({"daemon": "stopped", "sessions": []}) + "\n")
        else:
            out.write("daemon: parado (rode 'tsm up')\n")
        return
    views = service.status()
    if as_json:
        data = []
        for v in views:
            s = v.session
            data.append({
                "binding": v.binding_id, "role": v.role.value, "name": v.name,
                "identifier": s.identifier if s else None,
                "status": s.raw_status if s else "absent",
                "paused": s.paused if s else None,
                "alpha": s.alpha.endpoint.url if s else None,
                "beta": s.beta.endpoint.url if s else None,
                "alpha_connected": s.alpha.connected if s else None,
                "beta_connected": s.beta.connected if s else None,
                "problems": [{"path": p.path, "error": p.error} for p in s.problems] if s else [],
                "conflicts": s.conflicts if s else 0,
                "last_error": s.last_error if s else None,
            })
        out.write(json.dumps({"daemon": "running", "sessions": data}, indent=2) + "\n")
        return
    for v in views:
        s = v.session
        if s is None:
            out.write(f"{v.name:<28} ausente\n")
            continue
        flags = " [pausada]" if s.paused else ""
        out.write(f"{v.name:<28} {s.raw_status}{flags}\n")
        out.write(f"    {s.alpha.endpoint.url}  ->  {s.beta.endpoint.url}\n")
        if s.last_error:
            out.write(f"    último erro: {s.last_error}\n")
        for prob in s.problems:
            out.write(f"    problema: {prob.path}: {prob.error}\n")
        if s.conflicts:
            out.write(
                f"    conflitos: {s.conflicts} (destino tem conteúdo que impede a réplica; "
                "veja 'mutagen sync list --long')\n"
            )
        if s.status.halted:
            out.write(
                "    parada por salvaguarda: verifique as pastas; "
                "'tsm resume --confirm-halted'\n"
            )


def run(argv: Sequence[str], *, service_factory: ServiceFactory = default_service,
        out: TextIO | None = None, err: TextIO | None = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(list(argv))
    try:
        cfg = load_config(args.config)
        service = service_factory(cfg)
        match args.command:
            case "doctor":
                report = service.doctor()
                for label, value, ok in report.lines:
                    out.write(f"{'ok ' if ok else 'ERRO'} {label}: {value}\n")
                return EXIT_OK if report.ok else EXIT_MUTAGEN
            case "up":
                for r in service.up():
                    out.write(f"{r.spec.name}: {r.action} ({r.identifier})\n")
            case "status":
                _print_status(service, out, args.json)
            case "flush":
                role = Role(args.role) if args.role else None
                for s in service.flush(role):
                    out.write(f"{s.name}: flush concluído\n")
            case "pause":
                for s in service.pause():
                    out.write(f"{s.name}: pausada\n")
            case "resume":
                for s in service.resume(confirm_halted=args.confirm_halted):
                    out.write(f"{s.name}: retomada\n")
            case "teardown":
                for s in service.teardown(stop_daemon=args.stop_daemon):
                    out.write(f"{s.name}: terminada\n")
    except (ConfigError, SessionRuleError, PathError, RulesError) as exc:
        err.write(f"tsm: configuração inválida: {exc}\n")
        return EXIT_CONFIG
    except RefusedError as exc:
        err.write(f"tsm: recusado: {exc}\n")
        return EXIT_REFUSED
    except MutagenError as exc:
        err.write(f"tsm: erro do Mutagen ({type(exc).__name__}): {exc}\n")
        return EXIT_MUTAGEN
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        # em pipes no Windows a codificação padrão é a da página de código local
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    return run(sys.argv[1:] if argv is None else argv)
