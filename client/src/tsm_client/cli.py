"""CLI ``tsm`` (argparse, sem dependências de terceiros em runtime).

Transporte: doctor, up, status, flush, pause, resume, teardown.
Colaboração (config ``version: 2``): init, changes, diff, publish, pull, history,
show, rollback, audit.

Códigos de saída:
  0  sucesso
  1  falha do Mutagen/daemon ou do git
  2  configuração ou vínculo inválido (inclui erros de uso)
  3  recusado por segurança (salvaguarda, config alterada, pendência, recusa do Manager)
  4  bloqueado por conflito (nada mudou)
  5  Manager inacessível ou cache ainda não verificado (repita depois)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from typing import Any, TextIO

from tsm_client import __version__
from tsm_client.adapters.git import ClientGit, GitUnavailable, find_git
from tsm_client.adapters.manager import ManagerClient, ManagerProtocolError, ManagerUnavailable
from tsm_client.adapters.mutagen import MutagenAdapter, MutagenError, SubprocessRunner, mutagen_env
from tsm_client.collab import CollabService, PublishReport, PullReport, read_token
from tsm_client.config import Config, ConfigError, load_config
from tsm_client.paths import PathError
from tsm_client.pulling import CONFLICT, CacheNotReady, PlanError
from tsm_client.rules import RulesError
from tsm_client.service import RefusedError, TransportService, resolve_executable
from tsm_client.sessions import Role, SessionRuleError
from tsm_client.state import StateError, StateStore
from tsm_common import protocol as P

EXIT_OK, EXIT_MUTAGEN, EXIT_CONFIG, EXIT_REFUSED, EXIT_CONFLICT, EXIT_UNAVAILABLE = range(6)

ServiceFactory = Callable[[Config], TransportService]
CollabFactory = Callable[[Config, TransportService], CollabService]

COLLAB_COMMANDS = {"init", "changes", "diff", "publish", "pull", "history", "show", "rollback",
                   "audit"}


def default_service(cfg: Config) -> TransportService:
    env = mutagen_env(
        cfg.mutagen.data_directory,
        ssh_path=cfg.mutagen.ssh_path,
        ssh_home=cfg.mutagen.ssh_home,
    )
    adapter = MutagenAdapter(resolve_executable(cfg), SubprocessRunner(env))
    initialized = None
    if cfg.collab_enabled:
        assert cfg.state_directory is not None
        store = StateStore(cfg.state_directory)
        initialized = store.initialized
    return TransportService(cfg, adapter, initialized)


def default_collab(cfg: Config, transport: TransportService) -> CollabService:
    if not cfg.collab_enabled:
        raise ConfigError("colaboração exige config version 2 (state_directory e manager)")
    assert cfg.state_directory is not None and cfg.manager is not None
    store = StateStore(cfg.state_directory)
    git = ClientGit(find_git(cfg.git), store.git_global_config)
    manager = ManagerClient(cfg.manager.url, read_token(cfg))
    return CollabService(cfg, transport, manager, git, store)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tsm", description="TS Manager — Client de terminal")
    p.add_argument("--version", action="version", version=f"tsm {__version__}")
    p.add_argument("--config", "-c", required=True, help="arquivo de configuração do dispositivo")
    sub = p.add_subparsers(dest="command", required=True, metavar="comando")

    sub.add_parser("doctor", help="verifica Mutagen, ssh e daemon")
    sub.add_parser("up", help="cria ou retoma as sessões (idempotente)")
    st = sub.add_parser("status", help="estado das sessões e do vínculo")
    st.add_argument("--json", action="store_true", help="saída em JSON")
    fl = sub.add_parser("flush", help="força um ciclo de sincronização e espera terminar")
    fl.add_argument("--role", choices=[r.value for r in Role], default=None)
    sub.add_parser("pause", help="desconecta (pausa) as sessões gerenciadas")
    rs = sub.add_parser("resume", help="retoma sessões pausadas")
    rs.add_argument("--confirm-halted", action="store_true",
                    help="retoma também sessões paradas por salvaguarda (halted-on-root-*)")
    td = sub.add_parser("teardown", help="termina somente as sessões gerenciadas desta config")
    td.add_argument("--stop-daemon", action="store_true", help="para o daemon isolado no final")

    def with_binding(sp: argparse.ArgumentParser) -> argparse.ArgumentParser:
        sp.add_argument("--binding", default=None, help="vínculo (se a config tiver vários)")
        return sp

    it = with_binding(sub.add_parser("init", help="inicializa uma pasta vazia a partir do shared"))
    it.add_argument("--wait", type=float, default=60.0, help="segundos esperando o cache")
    ch = with_binding(sub.add_parser("changes", help="mudanças locais contra a base (offline)"))
    ch.add_argument("--json", action="store_true")
    df = with_binding(sub.add_parser("diff", help="diff textual contra a base"))
    df.add_argument("paths", nargs="*")
    pb = with_binding(sub.add_parser("publish", help="publica arquivos selecionados ou todos"))
    pb.add_argument("paths", nargs="*", help="caminhos ou diretórios do projeto")
    pb.add_argument("--all", action="store_true", help="publica todas as mudanças locais")
    pb.add_argument("-m", "--message", default="")
    pb.add_argument("--dry-run", action="store_true")
    pb.add_argument("--confirm-deletions", action="store_true")
    pb.add_argument("--resume", action="store_true", help="reenvia a publicação pendente")
    pb.add_argument("--json", action="store_true")
    pl = with_binding(sub.add_parser("pull", help="traz a revisão do shared para a pasta local"))
    pl.add_argument("--dry-run", action="store_true")
    pl.add_argument("--wait", type=float, default=60.0, help="segundos esperando o cache")
    pl.add_argument("--resolve", action="append", default=[], metavar="CAMINHO=ours|theirs|markers")
    pl.add_argument("--confirm-deletions", action="store_true")
    pl.add_argument("--json", action="store_true")
    hs = with_binding(sub.add_parser("history", help="revisões do projeto"))
    hs.add_argument("--limit", type=int, default=20)
    hs.add_argument("--json", action="store_true")
    sh = with_binding(sub.add_parser("show", help="detalhe de uma revisão"))
    sh.add_argument("revision", help="rN ou N")
    sh.add_argument("--json", action="store_true")
    rb = with_binding(sub.add_parser("rollback", help="cria revisão com o conteúdo de rN (admin)"))
    rb.add_argument("revision", help="rN ou N")
    rb.add_argument("--confirm", action="store_true", required=True)
    rb.add_argument("-m", "--message", default="")
    au = with_binding(sub.add_parser("audit", help="eventos de auditoria (admin)"))
    au.add_argument("--limit", type=int, default=50)
    au.add_argument("--json", action="store_true")
    return p


def _revision_number(raw: str) -> int:
    text = raw[1:] if raw.lower().startswith("r") else raw
    if not text.isdigit():
        raise ConfigError(f"revisão inválida: {raw!r} (use rN)")
    return int(text)


def _print_status(service: TransportService, out: TextIO, as_json: bool,
                  collab: dict[str, Any] | None) -> None:
    if not service.adapter.daemon_running():
        if as_json:
            out.write(json.dumps({"daemon": "stopped", "sessions": [], "binding": collab}) + "\n")
        else:
            out.write("daemon: parado (rode 'tsm up')\n")
            _print_collab(out, collab)
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
        payload: dict[str, Any] = {"daemon": "running", "sessions": data}
        if collab is not None:
            payload["binding"] = collab
        out.write(json.dumps(payload, indent=2) + "\n")
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
    _print_collab(out, collab)


def _print_collab(out: TextIO, info: dict[str, Any] | None) -> None:
    if info is None:
        return
    if not info.get("initialized"):
        out.write(f"vínculo {info['binding']}: não inicializado (rode 'tsm init')\n")
        return
    head = info.get("head")
    head_txt = f"r{head['revision']}" if head else "Manager inacessível"
    out.write(f"vínculo {info['binding']}: base r{info['base_revision']} "
              f"({info['base_commit'][:12]}), Manager em {head_txt}\n")
    if "local_changes" in info:
        out.write(f"    mudanças locais: {info['local_changes']}\n")
    if info.get("pending_publish"):
        out.write("    publicação pendente: rode 'tsm publish --resume'\n")
    for m in info.get("markers", []):
        out.write(f"    marcadores de conflito a resolver: {m}\n")


def _print_publish(out: TextIO, err: TextIO, rep: PublishReport, as_json: bool) -> int:
    if as_json:
        out.write(json.dumps({"status": rep.status, "result": rep.body,
                              "changes": rep.changes}, indent=2, ensure_ascii=False) + "\n")
    if rep.dry_run:
        if not as_json:
            out.write("prévia da publicação (nada enviado):\n")
            for c in rep.changes:
                out.write(f"  {c['op']:<6} {c['path']}\n")
        return EXIT_OK
    body = rep.body
    match rep.status:
        case P.PUBLISHED:
            if not as_json:
                out.write(f"publicado: r{body['revision']} ({len(rep.changes)} arquivo(s))\n")
            return EXIT_OK
        case P.NO_CHANGE:
            if not as_json:
                out.write(f"sem mudança: {body.get('message', '')}\n")
            return EXIT_OK
        case P.CONFLICT:
            if not as_json:
                err.write(f"tsm: publicação bloqueada: {body.get('message', '')}\n")
                for c in body.get("conflicts", []):
                    err.write(f"  conflito ({c['kind']}): {c['path']}\n")
            return EXIT_CONFLICT
        case P.BUSY:
            if not as_json:
                err.write("tsm: Manager ocupado; a publicação ficou pendente: "
                          "'tsm publish --resume'\n")
            return EXIT_UNAVAILABLE
        case _:
            if not as_json:
                err.write(f"tsm: publicação recusada ({rep.status}): {body.get('message', '')}\n")
                for e in body.get("errors", []) + body.get("paths", []):
                    err.write(f"  {e.get('path', '')}: {e.get('reason', '')}\n")
            return EXIT_REFUSED


def _print_pull(out: TextIO, err: TextIO, rep: PullReport, as_json: bool) -> int:
    ops = [{"path": o.path, "action": o.action, "kind": o.kind, "resolution": o.resolution}
           for o in rep.plan.ops]
    if as_json:
        out.write(json.dumps({"status": rep.status, "revision": rep.revision, "ops": ops,
                              "skipped": rep.skipped, "record": rep.record,
                              "warning": rep.warning}, indent=2, ensure_ascii=False) + "\n")
    else:
        if rep.warning:
            err.write(f"tsm: aviso: {rep.warning}\n")
        for o in rep.plan.ops:
            if o.action == CONFLICT:
                continue
            note = f" ({o.resolution})" if o.resolution else ""
            out.write(f"  {o.action:<8} {o.path}{note}\n")
        for o in rep.plan.conflicts:
            err.write(f"  conflito ({o.kind}): {o.path}\n")
    if rep.status == "blocked":
        if not as_json:
            err.write("tsm: pull bloqueado por conflito; nada mudou. Resolva com "
                      "--resolve CAMINHO=ours|theirs|markers\n")
        return EXIT_CONFLICT
    if rep.status == "incomplete":
        if not as_json:
            err.write("tsm: pull incompleto: arquivos mudaram durante a operação: "
                      f"{', '.join(rep.skipped)}. Rode 'tsm pull' de novo\n")
        return EXIT_CONFLICT
    if not as_json:
        label = {"updated": "atualizado para", "up_to_date": "já atualizado em",
                 "dry_run": "prévia de"}[rep.status]
        out.write(f"{label} r{rep.revision}\n")
        for m in rep.plan.markers:
            out.write(f"  edite e remova os marcadores de conflito em {m} antes de publicar\n")
    return EXIT_OK


def _run_collab(args: argparse.Namespace, collab: CollabService, out: TextIO,
                err: TextIO) -> int:
    match args.command:
        case "init":
            res = collab.init(args.binding, wait=args.wait)
            out.write(f"inicializado em r{res['revision']} ({res['files']} arquivo(s))\n")
            for name, action in res["sessions"]:
                out.write(f"{name}: {action}\n")
        case "changes":
            changes = collab.changes(args.binding)
            if args.json:
                out.write(json.dumps([{"path": c.path, "kind": c.kind} for c in changes],
                                     indent=2, ensure_ascii=False) + "\n")
            elif not changes:
                out.write("nenhuma mudança local\n")
            for c in [] if args.json else changes:
                out.write(f"  {c.kind:<9} {c.path}\n")
        case "diff":
            out.write(collab.diff(args.paths or None, args.binding))
        case "publish":
            if not args.resume and not args.all and not args.paths:
                err.write("tsm: informe caminhos ou --all\n")
                return EXIT_CONFIG
            if args.all and args.paths:
                err.write("tsm: use caminhos ou --all, não ambos\n")
                return EXIT_CONFIG
            rep = collab.publish(None if args.all else args.paths, message=args.message,
                                 dry_run=args.dry_run, confirm_deletions=args.confirm_deletions,
                                 resume=args.resume, binding_id=args.binding)
            return _print_publish(out, err, rep, args.json)
        case "pull":
            resolutions = {}
            for raw in args.resolve:
                path, sep, choice = raw.rpartition("=")
                if not sep or not path:
                    err.write(f"tsm: --resolve inválido: {raw!r}\n")
                    return EXIT_CONFIG
                resolutions[path.replace("\\", "/")] = choice
            rep = collab.pull(dry_run=args.dry_run, wait=args.wait, resolutions=resolutions,
                              confirm_deletions=args.confirm_deletions, binding_id=args.binding)
            return _print_pull(out, err, rep, args.json)
        case "history":
            revs = collab.history(args.limit, args.binding)
            if args.json:
                out.write(json.dumps(revs, indent=2, ensure_ascii=False) + "\n")
            for r in [] if args.json else revs:
                extra = f" → r{r['rollback_to']}" if r.get("rollback_to") else ""
                who = r.get("user") or ""
                dev = f"@{r['device']}" if r.get("device") else ""
                out.write(f"r{r['revision']:<4} {r['date'][:19]} {r['kind']:<8}{extra} "
                          f"{who}{dev}: {r['message']}\n")
        case "show":
            d = collab.show(_revision_number(args.revision), args.binding)
            if args.json:
                out.write(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
            else:
                out.write(f"r{d['revision']} {d['commit'][:12]} {d['kind']} {d.get('user')} "
                          f"{d['date']}\n    {d['message']}\n")
                for c in d["changes"]:
                    out.write(f"  {c['status']} {c['path']}\n")
        case "rollback":
            resp = collab.rollback(_revision_number(args.revision), args.message, args.binding)
            if resp.status == P.PUBLISHED:
                out.write(f"rollback: r{resp.body['revision']} com o conteúdo de "
                          f"r{resp.body['rollback_to']}\n")
            elif resp.status == P.NO_CHANGE:
                out.write(f"sem mudança: {resp.body.get('message')}\n")
            else:
                err.write(f"tsm: rollback recusado ({resp.status}): "
                          f"{resp.body.get('message', '')}\n")
                return EXIT_UNAVAILABLE if resp.status == P.BUSY else EXIT_REFUSED
        case "audit":
            events = collab.audit(args.limit, args.binding)
            if args.json:
                out.write(json.dumps(events, indent=2, ensure_ascii=False) + "\n")
            for e in [] if args.json else events:
                rest = {k: v for k, v in e.items() if k not in ("at", "event")}
                out.write(f"{e['at']} {e['event']} {json.dumps(rest, ensure_ascii=False)}\n")
    return EXIT_OK


def run(argv: Sequence[str], *, service_factory: ServiceFactory = default_service,
        collab_factory: CollabFactory = default_collab,
        out: TextIO | None = None, err: TextIO | None = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(list(argv))
    try:
        cfg = load_config(args.config)
        service = service_factory(cfg)
        if args.command in COLLAB_COMMANDS:
            return _run_collab(args, collab_factory(cfg, service), out, err)
        match args.command:
            case "doctor":
                report = service.doctor()
                for label, value, ok in report.lines:
                    out.write(f"{'ok ' if ok else 'ERRO'} {label}: {value}\n")
                return EXIT_OK if report.ok else EXIT_MUTAGEN
            case "up":
                for r in service.up():
                    out.write(f"{r.spec.name}: {r.action} ({r.identifier})\n")
                if cfg.state_directory is not None:
                    store = StateStore(cfg.state_directory)
                    for b in cfg.bindings:
                        if not store.initialized(b.id):
                            out.write(f"vínculo {b.id}: sem upload até 'tsm init'\n")
            case "status":
                info = None
                if cfg.collab_enabled and len(cfg.bindings) == 1:
                    try:
                        info = collab_factory(cfg, service).status_info()
                    except (ConfigError, GitUnavailable) as exc:
                        err.write(f"tsm: estado do vínculo indisponível: {exc}\n")
                _print_status(service, out, args.json, info)
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
    except (ConfigError, SessionRuleError, PathError, RulesError, PlanError) as exc:
        err.write(f"tsm: configuração ou uso inválido: {exc}\n")
        return EXIT_CONFIG
    except (RefusedError, StateError) as exc:
        err.write(f"tsm: recusado: {exc}\n")
        return EXIT_REFUSED
    except ManagerUnavailable as exc:
        err.write(f"tsm: {exc}\n")
        if args.command == "publish":
            err.write("tsm: se a publicação foi enviada, ela ficou pendente: "
                      "'tsm publish --resume'\n")
        return EXIT_UNAVAILABLE
    except CacheNotReady as exc:
        err.write(f"tsm: cache ainda não verificado: {exc}. Repita (ou aumente --wait)\n")
        return EXIT_UNAVAILABLE
    except ManagerProtocolError as exc:
        err.write(f"tsm: resposta inesperada do Manager: {exc}\n")
        return EXIT_MUTAGEN
    except GitUnavailable as exc:
        err.write(f"tsm: git: {exc}\n")
        return EXIT_MUTAGEN
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
