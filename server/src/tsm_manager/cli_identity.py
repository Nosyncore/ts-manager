"""Comandos de identidade do ``tsm-manager``, como operador local.

``bootstrap-admin``, ``invites``, ``requests``, ``users`` e ``devices`` usam os mesmos
serviços de domínio da API, com o ator ``operador``: só pela CLI do servidor existem o
bootstrap, a aprovação das solicitações de bootstrap, a promoção e o rebaixamento, o expurgo
e a revogação do último admin (``--allow-last-admin``).

Códigos de saída: 0 ok; 1 recusa ou falha; 2 config ou uso inválido; 3 concluído com
pendências (operação de provisionamento que ficou pendente: rode ``recover``).
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TextIO

from tsm_manager.api_identity import device_view, invite_view, op_view, user_view
from tsm_manager.identity import accounts, invites
from tsm_manager.identity.base import Actor
from tsm_manager.provisioning.service import OpResult

if TYPE_CHECKING:
    from tsm_manager.services import IdentityServices, Manager

EXIT_OK, EXIT_FAIL, EXIT_PROBLEMS = 0, 1, 3
OPERATOR = Actor.operator()
_DURATION_RE = re.compile(r"^(\d{1,7})([smhd]?)$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86_400}


def parse_duration(text: str) -> int:
    """``30m``, ``24h``, ``7d`` ou segundos."""
    match = _DURATION_RE.match(text.strip().lower())
    if not match or int(match.group(1)) == 0:
        raise argparse.ArgumentTypeError(f"duração inválida: {text!r} (ex.: 30m, 24h, 7d)")
    return int(match.group(1)) * _UNITS[match.group(2)]


def add_commands(sub: Any, with_config: Callable[[argparse.ArgumentParser], None]) -> None:
    def parser(name: str, help_: str, parent: Any = sub) -> argparse.ArgumentParser:
        p = parent.add_parser(name, help=help_)
        with_config(p)
        return p

    def listing(parent: Any, help_: str) -> None:
        parser("list", help_, parent).add_argument("--json", action="store_true")

    def target(parent: Any, name: str, help_: str) -> argparse.ArgumentParser:
        p = parser(name, help_, parent)
        p.add_argument("id")
        return p

    bs = parser("bootstrap-admin", "convite do primeiro admin (só sem admin ativo)")
    bs.add_argument("--project", required=True)
    bs.add_argument("--ttl", type=parse_duration, default=None, help="ex.: 24h, 7d")
    bs.add_argument("--json", action="store_true")

    inv = sub.add_parser("invites", help="convites (inclusive os de bootstrap)")
    inv_sub = inv.add_subparsers(dest="action", required=True, metavar="ação")
    listing(inv_sub, "lista os convites")
    target(inv_sub, "revoke", "revoga um convite aberto")

    req = sub.add_parser("requests", help="solicitações de dispositivo")
    req_sub = req.add_subparsers(dest="action", required=True, metavar="ação")
    listing(req_sub, "solicitações pendentes, inclusive as de bootstrap")
    ap = target(req_sub, "approve", "provisiona a conta e ativa o dispositivo")
    ap.add_argument("--fingerprint", required=True, help="SHA256:… mostrado no dispositivo")
    target(req_sub, "reject", "rejeita a solicitação")

    usr = sub.add_parser("users", help="usuários")
    usr_sub = usr.add_subparsers(dest="action", required=True, metavar="ação")
    listing(usr_sub, "lista os usuários")
    for name, help_ in (("promote", "torna admin"), ("demote", "volta a developer"),
                        ("block", "bloqueia (sessões e SSH)"),
                        ("unblock", "desbloqueia os dispositivos não revogados")):
        target(usr_sub, name, help_)

    dev = sub.add_parser("devices", help="dispositivos")
    dev_sub = dev.add_subparsers(dest="action", required=True, metavar="ação")
    listing(dev_sub, "dispositivos e pendências de provisionamento")
    rv = target(dev_sub, "revoke", "revoga o dispositivo (sessões e SSH)")
    rv.add_argument("--allow-last-admin", action="store_true",
                    help="permite revogar o dispositivo do último admin (recuperação)")
    target(dev_sub, "purge", "remove conta, chave e workspace de um dispositivo revogado")


def _json(out: TextIO, value: Any) -> None:
    out.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _results(out: TextIO, results: list[OpResult]) -> int:
    code = EXIT_OK
    for r in results:
        line = f"  dispositivo {r.device_id}: {r.action} ssh {r.status}"
        if r.error:
            line += f" — {r.error}"
        out.write(line + "\n")
        if r.status == "pending":
            code = EXIT_PROBLEMS
    if code == EXIT_PROBLEMS:
        out.write("operação SSH pendente: rode tsm-manager recover\n")
    return code


def run(args: argparse.Namespace, manager: Manager, out: TextIO) -> int:
    ids = manager.identity
    match args.command:
        case "bootstrap-admin":
            return _bootstrap(args, ids, out)
        case "invites":
            return _invites(args, ids, out)
        case "requests":
            return _requests(args, ids, out)
        case "users":
            return _users(args, ids, out)
        case _:
            return _devices(args, ids, out)


def _bootstrap(args: argparse.Namespace, ids: IdentityServices, out: TextIO) -> int:
    created = invites.create_bootstrap(ids.ctx, OPERATOR, project_id=args.project,
                                       ttl_s=args.ttl)
    view = {"code": created.code, "invite_id": created.invite.id,
            "project_id": created.invite.project_id,
            "expires_at": created.invite.expires_at, "server_id": ids.ctx.server_id}
    if args.json:
        _json(out, view)
        return EXIT_OK
    out.write(f"convite: {created.code}\nprojeto: {view['project_id']}\n"
              f"expira: {view['expires_at']}\nserver_id: {view['server_id']}\n"
              "o código só aparece agora; entregue-o ao primeiro admin fora de banda\n")
    return EXIT_OK


def _invites(args: argparse.Namespace, ids: IdentityServices, out: TextIO) -> int:
    if args.action == "revoke":
        invite = invites.revoke(ids.ctx, OPERATOR, args.id)
        out.write(f"convite {invite.id} revogado\n")
        return EXIT_OK
    listed = [invite_view(i, st) for i, st in invites.list_invites(ids.ctx, OPERATOR)]
    if args.json:
        _json(out, listed)
        return EXIT_OK
    for i in listed:
        out.write(f"{i['id']}  {i['kind']}  {i['role']}  {i['project_id']}  {i['state']}  "
                  f"expira {i['expires_at']}\n")
    if not listed:
        out.write("nenhum convite\n")
    return EXIT_OK


def _requests(args: argparse.Namespace, ids: IdentityServices, out: TextIO) -> int:
    if args.action == "approve":
        binding = ids.provisioning.approve(OPERATOR, args.id, args.fingerprint)
        out.write(f"dispositivo {args.id} ativo; vínculo {binding.id} em "
                  f"{binding.project_id} (conta {binding.workspace})\n")
        return EXIT_OK
    if args.action == "reject":
        accounts.reject(ids.ctx, OPERATOR, args.id)
        out.write(f"solicitação {args.id} rejeitada\n")
        return EXIT_OK
    reqs = accounts.list_requests(ids.ctx, OPERATOR, include_bootstrap=True)
    if args.json:
        _json(out, [{"device": device_view(r.device), "user": user_view(r.user),
                     "invite": {"id": r.invite.id, "kind": r.invite.kind,
                                "project_id": r.invite.project_id}} for r in reqs])
        return EXIT_OK
    for r in reqs:
        d = r.device
        out.write(f"{d.id}  {d.status}  {r.user.display_name} ({r.user.id})  {d.name}  "
                  f"{d.fingerprint}  {r.invite.kind}  {r.invite.project_id}  "
                  f"{d.created_at}\n")
        if d.last_error:
            out.write(f"  último erro: {d.last_error}\n")
    if not reqs:
        out.write("nenhuma solicitação pendente\n")
    return EXIT_OK


def _users(args: argparse.Namespace, ids: IdentityServices, out: TextIO) -> int:
    match args.action:
        case "promote":
            user = accounts.promote(ids.ctx, OPERATOR, args.id)
            out.write(f"usuário {user.id}: role {user.role}\n")
            return EXIT_OK
        case "demote":
            user = accounts.demote(ids.ctx, OPERATOR, args.id)
            out.write(f"usuário {user.id}: role {user.role}\n")
            return EXIT_OK
        case "block":
            results = ids.provisioning.block(OPERATOR, args.id)
            out.write(f"usuário {args.id} bloqueado\n")
            return _results(out, results)
        case "unblock":
            results = ids.provisioning.unblock(OPERATOR, args.id)
            out.write(f"usuário {args.id} desbloqueado\n")
            return _results(out, results)
    users = accounts.list_users(ids.ctx, OPERATOR)
    if args.json:
        _json(out, [user_view(u) for u in users])
        return EXIT_OK
    for u in users:
        out.write(f"{u.id}  {u.role}  {u.status}  {u.display_name}\n")
    if not users:
        out.write("nenhum usuário\n")
    return EXIT_OK


def _devices(args: argparse.Namespace, ids: IdentityServices, out: TextIO) -> int:
    if args.action == "revoke":
        result = ids.provisioning.revoke(OPERATOR, args.id,
                                         allow_last_admin=args.allow_last_admin)
        out.write(f"dispositivo {args.id} revogado\n")
        return _results(out, [result])
    if args.action == "purge":
        result = ids.provisioning.purge(OPERATOR, args.id)
        out.write(f"dispositivo {args.id} expurgado\n")
        return _results(out, [result])
    views = accounts.list_devices(ids.ctx, OPERATOR)
    if args.json:
        _json(out, [{**device_view(v.device), "user": user_view(v.user),
                     "pending_ops": [op_view(op) for op in v.pending_ops]} for v in views])
        return EXIT_OK
    for v in views:
        d = v.device
        out.write(f"{d.id}  {d.status}  {v.user.display_name} ({v.user.id})  {d.name}  "
                  f"{d.fingerprint}  {d.ssh_account or '-'}\n")
        for op in v.pending_ops:
            label = "revogação SSH pendente" if op.action == "disable" else \
                f"operação pendente: {op.action}"
            out.write(f"  {label}" + (f" — {op.error}" if op.error else "") + "\n")
    if not views:
        out.write("nenhum dispositivo\n")
    return EXIT_OK


__all__ = ["add_commands", "parse_duration", "run"]
