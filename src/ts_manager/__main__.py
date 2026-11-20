import argparse
import getpass
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

from .common import MAX_REQUEST_BYTES, ManagerError, lua_path, read_limited, sha256


def run_tool(command, *, data=None, timeout=45):
    result = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ManagerError(message or f"{command[0]} encerrou com código {result.returncode}.")
    return result.stdout


def flush_workspace(session, root):
    run_tool(["mutagen", "sync", "flush", "--", session])
    raw = run_tool(["mutagen", "sync", "list", "--template", "{{ json . }}", "--", session])
    sessions = json.loads(raw)
    if len(sessions) != 1:
        raise ManagerError("Informe o nome ou ID de uma única sessão Mutagen.")
    info = sessions[0]
    alpha, beta = info["alpha"], info["beta"]
    if alpha.get("host") or Path(alpha["path"]).resolve() != root:
        raise ManagerError("A raiz local difere da ponta alfa da sessão Mutagen.")
    if info.get("paused") or info.get("lastError") or not info.get("successfulCycles"):
        raise ManagerError("O Mutagen ainda precisa concluir um ciclo sem erros.")
    if info.get("conflicts") or info.get("excludedConflicts"):
        raise ManagerError("Resolva os conflitos da sessão Mutagen antes de publicar.")
    for endpoint in (alpha, beta):
        if not endpoint.get("connected") or endpoint.get("scanProblems") or endpoint.get("transitionProblems"):
            raise ManagerError("Confira a conexão e os erros da sessão com mutagen sync list --long.")


def remote(args):
    path = lua_path(args.path)
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", args.host):
        raise ManagerError("Informe um alias SSH para a conta de publicação.")
    request = {"operation": args.command, "path": path}
    if args.command == "publish":
        root = args.workspace.resolve(strict=True)
        with (root / path).open("rb") as source:
            request["sha256"] = sha256(read_limited(source))
        flush_workspace(args.session, root)
    command = ["ssh", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=10"]
    if args.ssh_config:
        command.extend(["-F", str(args.ssh_config)])
    raw = run_tool([*command, args.host], data=json.dumps(request).encode("utf-8") + b"\n")
    response = json.loads(raw)
    if "error" in response:
        raise ManagerError(response["error"])
    return response["result"]


def serve(publisher, actor):
    raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise ManagerError("Requisição SSH ausente ou acima do limite.")
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ManagerError("Requisição SSH inválida.")
    keys = request.keys()
    if request.get("operation") == "status" and keys == {"operation", "path"}:
        return publisher.status(request["path"], actor)
    if request.get("operation") == "publish" and keys == {"operation", "path", "sha256"}:
        return publisher.publish(request["path"], actor, request["sha256"])
    raise ManagerError("Operação SSH desconhecida ou parâmetros inválidos.")


def server(args):
    if sys.platform != "linux":
        raise ManagerError("O publicador precisa de Linux. Use a VM para ensaiar o lado servidor.")
    from .publisher import Publisher

    publisher = Publisher(args.config)
    if args.action == "serve":
        return {"result": serve(publisher, args.actor)}
    if args.action == "init":
        return publisher.initialize(args.path, getpass.getuser())
    if args.action == "adopt":
        return publisher.adopt(args.path, args.developer, args.revision)
    return publisher.rollback(args.path, getpass.getuser(), args.revision)


def parser():
    root = argparse.ArgumentParser(prog="ts", description="Publicação controlada de arquivos Lua.")
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in (("status", "Consultar revisões e hashes"), ("publish", "Publicar um Lua sincronizado")):
        client = commands.add_parser(name, help=help_text)
        client.add_argument("path", metavar="ARQUIVO")
        client.add_argument("--host", required=True, help="Alias SSH da conta de publicação")
        client.add_argument("--ssh-config", type=Path, help="Arquivo de configuração SSH alternativo")
        if name == "publish":
            client.add_argument("--session", required=True, help="Nome ou ID da sessão Mutagen")
            client.add_argument("--workspace", type=Path, required=True, help="Raiz local da sincronização")

    admin = commands.add_parser("server", help="Bootstrap, recuperação e entrada SSH na VM")
    admin.add_argument("--config", type=Path, required=True, help="Configuração TOML do publicador")
    operations = admin.add_subparsers(dest="action", required=True)
    entry = operations.add_parser("serve", help="Atender um pedido SSH para a identidade fixa")
    entry.add_argument("--actor", required=True)
    for name, help_text in (
        ("init", "Registrar a base a partir do mesmo arquivo nas três árvores"),
        ("adopt", "Confirmar a revisão-base após integração manual"),
        ("rollback", "Restaurar o snapshot anterior do arquivo"),
    ):
        operation = operations.add_parser(name, help=help_text)
        operation.add_argument("path", metavar="ARQUIVO")
        if name != "init":
            operation.add_argument("revision", type=int, metavar="REVISÃO_ATUAL")
        if name == "adopt":
            operation.add_argument("--developer", required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    is_serving = args.command == "server" and args.action == "serve"
    try:
        result = server(args) if args.command == "server" else remote(args)
    except (ManagerError, OSError, sqlite3.Error, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as error:
        if is_serving:
            if not isinstance(error, ManagerError):
                print(f"Falha no publicador. {error}", file=sys.stderr)
                error = ManagerError("Falha ao ler configuração, arquivo ou processo do publicador.")
            print(json.dumps({"error": str(error)}))
            return 0
        print(f"Erro. {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=None if is_serving else 2, ensure_ascii=is_serving))
    return 0


if __name__ == "__main__":
    sys.exit(main())
