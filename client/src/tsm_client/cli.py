"""CLI ``tsm`` (argparse, sem dependências de terceiros em runtime).

Origem da configuração: o diretório do tsm (``--home DIR`` / ``TSM_HOME`` / padrão
``%LOCALAPPDATA%\\tsm``), com a config ``version: 3`` e a sessão por challenge-response.
Quem chama ``run`` pode entregar um ``Config`` pronto (``config=``), como entrega o serviço
(``service_factory``): sem ``<home>`` não há sessão, então só os comandos de transporte
funcionam com ele.

Identidade (só com o ``<home>``): enroll, whoami, bind, logout, admin.
Transporte: doctor, up, status, flush, pause, resume, teardown.
Colaboração: init, changes, diff, publish, pull, history, show, rollback, audit.

Códigos de saída:
  0  sucesso
  1  falha do Mutagen/daemon, do git, do ssh-keygen ou do icacls; provisionamento falhou
  2  configuração ou uso inválido (inclui URL do Manager insegura e pedido inválido)
  3  recusado (salvaguarda, config alterada, pendência, recusa do Manager, outro servidor)
  4  bloqueado por conflito (nada mudou)
  5  Manager inacessível, limitado (429) ou cache ainda não verificado (repita depois)
  6  identidade pendente, rejeitada, revogada, expirada ou bloqueada
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any, TextIO

from tsm_client import __version__
from tsm_client.adapters.acl import AclError
from tsm_client.adapters.git import ClientGit, GitUnavailable, find_git
from tsm_client.adapters.manager import (
    ManagerClient,
    ManagerProtocolError,
    ManagerUnavailable,
    ManagerUrlError,
)
from tsm_client.adapters.mutagen import MutagenAdapter, MutagenError, SubprocessRunner, mutagen_env
from tsm_client.adapters.sshkeygen import KeygenError
from tsm_client.admin import AdminService, parse_duration, ssh_pending
from tsm_client.collab import CollabService, PublishReport, PullReport
from tsm_client.config import Config, ConfigError, load_home_config, read_home_config
from tsm_client.enroll import Identity, Toolkit
from tsm_client.home import Home, HomeError, resolve_home
from tsm_client.login import IdentityPending, IdentityRefused, ManagerRefused
from tsm_client.paths import PathError
from tsm_client.pulling import CONFLICT, CacheNotReady, PlanError
from tsm_client.rules import RulesError
from tsm_client.service import RefusedError, TransportService, resolve_executable
from tsm_client.sessions import Role, SessionRuleError
from tsm_client.state import StateError, StateStore
from tsm_common import protocol as P

(EXIT_OK, EXIT_MUTAGEN, EXIT_CONFIG, EXIT_REFUSED, EXIT_CONFLICT, EXIT_UNAVAILABLE,
 EXIT_IDENTITY) = range(7)

ServiceFactory = Callable[[Config], TransportService]
CollabFactory = Callable[[Config, TransportService], CollabService]

COLLAB_COMMANDS = {"init", "changes", "diff", "publish", "pull", "history", "show", "rollback",
                   "audit"}
IDENTITY_COMMANDS = {"enroll", "whoami", "bind", "logout", "admin"}


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


def manager_client(cfg: Config, toolkit: Toolkit | None = None) -> ManagerClient:
    """Cliente do Manager autenticado pela sessão do dispositivo do ``<home>``."""
    if cfg.home is None:
        raise ConfigError("o Manager exige o diretório do tsm (tsm enroll)")
    return Identity(cfg.home, toolkit).session(read_home_config(cfg.home))[0]


def default_collab(cfg: Config, transport: TransportService, *,
                   toolkit: Toolkit | None = None) -> CollabService:
    if not cfg.collab_enabled or cfg.home is None:
        raise ConfigError("colaboração exige o diretório do tsm (tsm enroll)")
    assert cfg.state_directory is not None
    store = StateStore(cfg.state_directory)
    git = ClientGit(find_git(cfg.git), store.git_global_config)
    return CollabService(cfg, transport, manager_client(cfg, toolkit), git, store)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tsm", description="TS Manager — Client de terminal")
    p.add_argument("--version", action="version", version=f"tsm {__version__}")
    p.add_argument("--home", default=None,
                   help="diretório do tsm (padrão: TSM_HOME ou %%LOCALAPPDATA%%\\tsm)")
    sub = p.add_subparsers(dest="command", required=True, metavar="comando")

    # ------------------------------------------------------------ identidade
    en = sub.add_parser("enroll", help="cadastra este dispositivo com um convite")
    en.add_argument("--manager", required=True, help="URL do Manager")
    en.add_argument("--invite", required=True, help="código do convite (tsm-inv-…)")
    en.add_argument("--name", default=None, help="seu nome de exibição (convite de usuário)")
    en.add_argument("--device-name", default=None, help="nome deste dispositivo")
    en.add_argument("--ca-file", default=None, help="CA do Manager (https)")
    en.add_argument("--wait", type=float, default=None, metavar="S",
                    help="espera a aprovação por até S segundos")
    en.add_argument("--json", action="store_true")
    wh = sub.add_parser("whoami", help="usuário, dispositivo, status e vínculos")
    wh.add_argument("--json", action="store_true")
    bd = sub.add_parser("bind", help="vincula uma pasta a um projeto e inicializa")
    bd.add_argument("--project", required=True)
    bd.add_argument("--local", default=None, help="pasta de trabalho (vazia ou ausente)")
    bd.add_argument("--cache", default=None, help="cache do shared (padrão: no diretório do tsm)")
    bd.add_argument("--wait", type=float, default=60.0, help="segundos esperando o cache")
    bd.add_argument("--json", action="store_true")
    sub.add_parser("logout", help="encerra a sessão atual")

    ad = sub.add_parser("admin", help="administração (admin)")
    adsub = ad.add_subparsers(dest="area", required=True, metavar="área")
    inv = adsub.add_parser("invite", help="convites").add_subparsers(dest="action",
                                                                      required=True)
    ic = inv.add_parser("create")
    ic.add_argument("--project", required=True)
    ic.add_argument("--role", choices=["developer", "admin"], default="developer")
    ic.add_argument("--for-user", default=None, help="novo dispositivo de usuário existente")
    ic.add_argument("--ttl", default=None, help="validade (30m, 24h, 7d)")
    ic.add_argument("--json", action="store_true")
    inv.add_parser("list").add_argument("--json", action="store_true")
    inv.add_parser("revoke").add_argument("id")
    req = adsub.add_parser("requests", help="solicitações").add_subparsers(dest="action",
                                                                            required=True)
    req.add_parser("list").add_argument("--json", action="store_true")
    ap = req.add_parser("approve")
    ap.add_argument("id")
    ap.add_argument("--fingerprint", required=True)
    req.add_parser("reject").add_argument("id")
    dev = adsub.add_parser("devices", help="dispositivos").add_subparsers(dest="action",
                                                                           required=True)
    dev.add_parser("list").add_argument("--json", action="store_true")
    dev.add_parser("revoke").add_argument("id")
    usr = adsub.add_parser("users", help="usuários").add_subparsers(dest="action",
                                                                     required=True)
    usr.add_parser("list").add_argument("--json", action="store_true")
    usr.add_parser("block").add_argument("id")
    usr.add_parser("unblock").add_argument("id")

    # ------------------------------------------------------------ transporte
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

    # ------------------------------------------------------------ colaboração
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


def _dump(out: TextIO, data: Any) -> None:
    out.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


# ================================================================ transporte e colaboração


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
                if rep.status == P.RULES_MISMATCH:
                    err.write("tsm: as regras do projeto mudaram; com o diretório do tsm, "
                              "atualize com 'tsm bind --project <projeto>'\n")
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


def _run_transport(args: argparse.Namespace, cfg: Config, service: TransportService,
                   collab_factory: CollabFactory, out: TextIO, err: TextIO) -> int:
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
    return EXIT_OK


# ================================================================ identidade


def _print_enroll(out: TextIO, res: Any, as_json: bool) -> None:
    if as_json:
        _dump(out, res.to_dict())
        return
    if res.recovered:
        out.write("chave já cadastrada neste Manager: cadastro recuperado\n")
    state = "aprovado" if res.status == "active" else res.status
    out.write(f"dispositivo {res.device_id} ({state})\n")
    out.write(f"fingerprint: {res.fingerprint}\n")
    out.write(f"servidor: {res.server_id}\n")
    if res.status != "active":
        out.write("peça a aprovação conferindo o fingerprint acima:\n"
                  f"  tsm admin requests approve {res.device_id} --fingerprint "
                  f"{res.fingerprint}\n"
                  "  (primeiro admin, no servidor: tsm-manager requests approve "
                  f"{res.device_id} --fingerprint {res.fingerprint})\n")


def _print_whoami(out: TextIO, info: dict[str, Any], as_json: bool) -> None:
    if as_json:
        _dump(out, info)
        return
    user, device = info.get("user") or {}, info.get("device") or {}
    session = info.get("session") or {}
    out.write(f"usuário: {user.get('display_name')} ({user.get('role')}, "
              f"{user.get('status')}) {user.get('id')}\n")
    out.write(f"dispositivo: {device.get('name')} ({device.get('status')}) "
              f"{device.get('id')}\n")
    out.write(f"fingerprint: {info.get('fingerprint')}\n")
    out.write(f"Manager: {info.get('manager')} (servidor {info.get('server_id')})\n")
    out.write(f"sessão: {session.get('scope')} até {session.get('expires_at')}\n")
    if device.get("status") in ("pending", "provisioning"):
        out.write("aguardando aprovação do admin\n")
    local = {b["id"]: b for b in info.get("local_bindings", [])}
    for b in info.get("bindings", []):
        where = local.get(b["id"], {}).get("local", "(sem pasta local: rode 'tsm bind')")
        out.write(f"vínculo {b['id']} ({b['project_id']}): {where}\n")


def _print_list(out: TextIO, rows: list[dict[str, Any]], as_json: bool,
                fmt: Callable[[dict[str, Any]], str], empty: str) -> None:
    if as_json:
        _dump(out, rows)
        return
    if not rows:
        out.write(empty + "\n")
    for row in rows:
        out.write(fmt(row) + "\n")


def _warn_ssh_pending(err: TextIO, result: dict[str, Any]) -> None:
    for item in ssh_pending(result):
        err.write(f"tsm: aviso: a parte SSH de {item.get('device_id')} ficou pendente "
                  f"({item.get('error') or 'helper falhou'}); o recover do Manager conclui. "
                  "A API já recusa o acesso\n")


def _run_admin(args: argparse.Namespace, admin: AdminService, out: TextIO,
               err: TextIO) -> int:
    as_json = getattr(args, "json", False)
    match (args.area, args.action):
        case ("invite", "create"):
            ttl = parse_duration(args.ttl) if args.ttl else None
            inv = admin.invite_create(args.project, role=args.role, for_user=args.for_user,
                                      ttl_s=ttl)
            if as_json:
                _dump(out, inv)
            else:
                out.write(f"convite {inv['id']} ({inv['kind']}, {inv['role']}, projeto "
                          f"{inv['project_id']}) válido até {inv['expires_at']}\n")
                out.write(f"código (mostrado uma vez): {inv['code']}\n")
        case ("invite", "list"):
            _print_list(out, admin.invite_list(), as_json,
                        lambda i: f"{i['id']} {i['state']:<8} {i['kind']:<10} {i['role']:<9} "
                                  f"{i['project_id']} até {i['expires_at']}",
                        "nenhum convite")
        case ("invite", "revoke"):
            inv = admin.invite_revoke(args.id)
            out.write(f"convite {inv['id']}: {inv['state']}\n")
        case ("requests", "list"):
            _print_list(out, admin.requests_list(), as_json,
                        lambda r: f"{r['device']['id']} {r['device']['status']:<12} "
                                  f"{r['device']['fingerprint']} {r['user']['display_name']} / "
                                  f"{r['device']['name']} (convite {r['invite']['kind']}, "
                                  f"{r['invite']['project_id']}) {r['device']['created_at']}",
                        "nenhuma solicitação pendente")
        case ("requests", "approve"):
            res = admin.approve(args.id, args.fingerprint)
            out.write(f"aprovado: dispositivo {args.id}, vínculo {res['binding']['id']} "
                      f"({res['binding']['project_id']})\n")
        case ("requests", "reject"):
            admin.reject(args.id)
            out.write(f"rejeitado: dispositivo {args.id}\n")
        case ("devices", "list"):
            def fmt(d: dict[str, Any]) -> str:
                note = " [revogação SSH pendente]" if d.get("ssh_revocation_pending") else ""
                return (f"{d['id']} {d['status']:<12} {d['fingerprint']} "
                        f"{d['user']['display_name']} / {d['name']}{note}")
            _print_list(out, admin.devices_list(), as_json, fmt, "nenhum dispositivo")
        case ("devices", "revoke"):
            res = admin.device_revoke(args.id)
            out.write(f"revogado: dispositivo {args.id} (SSH: {res.get('ssh')})\n")
            _warn_ssh_pending(err, res)
        case ("users", "list"):
            _print_list(out, admin.users_list(), as_json,
                        lambda u: f"{u['id']} {u['status']:<8} {u['role']:<9} "
                                  f"{u['display_name']}",
                        "nenhum usuário")
        case ("users", ("block" | "unblock") as action):
            res = admin.user_block(args.id) if action == "block" else \
                admin.user_unblock(args.id)
            out.write(f"usuário {args.id}: {res['status']}\n")
            _warn_ssh_pending(err, res)
    return EXIT_OK


def _run_identity(args: argparse.Namespace, home: Home, toolkit: Toolkit,
                  service_factory: ServiceFactory, collab_factory: CollabFactory,
                  out: TextIO, err: TextIO) -> int:
    ident = Identity(home, toolkit)
    match args.command:
        case "enroll":
            res = ident.enroll(manager_url=args.manager, invite=args.invite, name=args.name,
                               device_name=args.device_name, ca_file=args.ca_file,
                               wait=args.wait)
            _print_enroll(out, res, args.json)
        case "whoami":
            _print_whoami(out, ident.whoami(), args.json)
        case "bind":
            res = ident.bind(args.project, args.local, args.cache)
            if res.host_keys_changed:
                err.write(f"tsm: aviso: a chave de host do servidor mudou para o vínculo "
                          f"{res.binding.id} (recebida pela /connection/config)\n")
            cfg = load_home_config(home)
            service = service_factory(cfg)
            initialized = StateStore(home.state).initialized(res.binding.id)
            info: dict[str, Any] = {"binding": res.binding.id, "project_id": args.project,
                                    "local": res.binding.local, "cache": res.binding.cache,
                                    "transport": res.connection.transport,
                                    "created": res.created, "initialized": initialized}
            if not initialized:
                init = collab_factory(cfg, service).init(res.binding.id, wait=args.wait)
                info.update(initialized=True, revision=init["revision"], files=init["files"])
            if args.json:
                _dump(out, info)
            else:
                verb = "vinculado" if res.created else "conexão atualizada"
                out.write(f"{verb}: {res.binding.id} ({args.project}) em {res.binding.local}\n")
                if "revision" in info:
                    out.write(f"inicializado em r{info['revision']} ({info['files']} "
                              "arquivo(s))\n")
        case "logout":
            try:
                had = ident.logout()
            except ManagerUnavailable as exc:
                err.write(f"tsm: {exc}\ntsm: token local apagado; a sessão segue válida no "
                          "Manager até expirar\n")
                return EXIT_UNAVAILABLE
            out.write("sessão encerrada\n" if had else "nenhuma sessão ativa\n")
        case "admin":
            client = Identity(home, toolkit).session(read_home_config(home))[0]
            return _run_admin(args, AdminService(client), out, err)
    return EXIT_OK


def _refused_code(exc: ManagerRefused) -> int:
    if exc.status == P.INVALID_REQUEST:
        return EXIT_CONFIG
    if exc.status == P.PROVISIONING_FAILED or exc.http_status >= 500:
        return EXIT_MUTAGEN
    return EXIT_REFUSED


def run(argv: Sequence[str], *, config: Config | None = None,
        service_factory: ServiceFactory = default_service,
        collab_factory: CollabFactory | None = None, toolkit: Toolkit | None = None,
        environ: Mapping[str, str] | None = None,
        out: TextIO | None = None, err: TextIO | None = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(list(argv))
    toolkit = toolkit or Toolkit()
    collab_factory = collab_factory or functools.partial(default_collab, toolkit=toolkit)
    try:
        if config is not None:
            if args.command in IDENTITY_COMMANDS or args.home is not None:
                raise ConfigError(f"'{args.command}' exige o diretório do tsm (--home)")
            cfg = config
        else:
            home = resolve_home(args.home, os.environ if environ is None else environ)
            if args.command in IDENTITY_COMMANDS:
                return _run_identity(args, home, toolkit, service_factory, collab_factory,
                                     out, err)
            cfg = load_home_config(home)
        service = service_factory(cfg)
        if args.command in COLLAB_COMMANDS:
            return _run_collab(args, collab_factory(cfg, service), out, err)
        return _run_transport(args, cfg, service, collab_factory, out, err)
    except (IdentityRefused, IdentityPending) as exc:
        err.write(f"tsm: {exc}\n")
        return EXIT_IDENTITY
    except ManagerRefused as exc:
        err.write(f"tsm: recusado: {exc}\n")
        return _refused_code(exc)
    except (ConfigError, SessionRuleError, PathError, RulesError, PlanError, HomeError,
            ManagerUrlError) as exc:
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
    except (KeygenError, AclError) as exc:
        err.write(f"tsm: {exc}\n")
        return EXIT_MUTAGEN
    except MutagenError as exc:
        err.write(f"tsm: erro do Mutagen ({type(exc).__name__}): {exc}\n")
        return EXIT_MUTAGEN


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        # em pipes no Windows a codificação padrão é a da página de código local
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    return run(sys.argv[1:] if argv is None else argv)
