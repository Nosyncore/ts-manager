"""Conexão de um vínculo (``/connection/config``) e os arquivos SSH gerenciados.

A ``/connection/config`` é a única fonte de host, porta, conta, chaves de host, caminhos e
regras do Client. Antes de gravar qualquer coisa, a resposta é validada campo a campo; uma
divergência recusa tudo.

Com ``transport: ssh``, cada vínculo ganha o alias ``tsm-<vínculo>`` em
``<home>/ssh/.ssh/config`` e as chaves de host em ``<home>/ssh/.ssh/known_hosts``, na forma
``tsm-<vínculo> ssh-ed25519 <base64>`` (sem hash e sem padrão de host: o ``HostKeyAlias``
faz o ``ssh`` procurar pelo alias). ``StrictHostKeyChecking yes``: nunca há aceite
automático. Os dois arquivos são reescritos inteiros a partir das conexões gravadas; o
``~/.ssh`` pessoal nunca é lido nem escrito.

Com ``transport: local`` (desenvolvimento e testes), não há entrada SSH: os endpoints são os
caminhos locais.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from tsm_client.errors import RefusedError
from tsm_client.home import Home
from tsm_client.paths import Endpoint, PathError, canonical_local, canonical_remote
from tsm_client.sessions import Binding, SessionRuleError
from tsm_common.fsutil import atomic_write_bytes
from tsm_common.rules import ProjectRules, RulesError, rules_digest
from tsm_common.sshkeys import PublicKeyError, parse_public_key

TRANSPORTS = ("ssh", "local")
HEADER = "# Gerado pelo tsm a partir da /connection/config do Manager; não editar.\n"

_BINDING_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_USER_RE = re.compile(r"^tsm-d-[0-9a-f]{12}$")
_GROUP_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DNS_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")

SSH_OPTIONS = (
    ("IdentityFile", "~/.ssh/id_ed25519"),
    ("IdentitiesOnly", "yes"),
    ("UserKnownHostsFile", "~/.ssh/known_hosts"),
    ("GlobalKnownHostsFile", "/dev/null"),
    ("StrictHostKeyChecking", "yes"),
    ("UpdateHostKeys", "no"),
    ("CheckHostIP", "no"),
    ("BatchMode", "yes"),
    ("PreferredAuthentications", "publickey"),
    ("PasswordAuthentication", "no"),
    ("KbdInteractiveAuthentication", "no"),
    ("ForwardAgent", "no"),
    ("ForwardX11", "no"),
    ("ClearAllForwardings", "yes"),
    ("RequestTTY", "no"),
    ("ControlMaster", "no"),
)


class ConnectionConfigError(RefusedError):
    """``/connection/config`` recusada na validação: nada foi gravado."""


@dataclass(frozen=True)
class Connection:
    server_id: str
    project_id: str
    binding_id: str
    device_id: str
    transport: str
    host: str | None
    port: int | None
    user: str | None
    host_keys: tuple[str, ...]
    workspace: str
    shared: str
    workspace_group: str
    rules: ProjectRules
    raw: dict[str, Any] = field(compare=False, repr=False)

    @property
    def alias(self) -> str:
        return f"tsm-{self.binding_id}"

    @property
    def is_ssh(self) -> bool:
        return self.transport == "ssh"

    def endpoints(self) -> tuple[Endpoint, Endpoint]:
        if self.is_ssh:
            return Endpoint(self.alias, self.workspace), Endpoint(self.alias, self.shared)
        return Endpoint(None, self.workspace), Endpoint(None, self.shared)

    def binding(self, local: str, cache: str) -> Binding:
        workspace, shared = self.endpoints()
        try:
            return Binding(id=self.binding_id, project_id=self.project_id,
                           local=Endpoint(None, canonical_local(local)),
                           cache=Endpoint(None, canonical_local(cache)),
                           workspace=workspace, shared=shared, rules=self.rules,
                           workspace_group=self.workspace_group if self.is_ssh else None)
        except (PathError, SessionRuleError) as exc:
            raise ConnectionConfigError(f"vínculo {self.binding_id}: {exc}") from exc


def _fail(message: str) -> ConnectionConfigError:
    return ConnectionConfigError(f"configuração de conexão recusada: {message}")


def valid_host(host: object) -> str:
    if not isinstance(host, str) or not host:
        raise _fail("host ausente")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _DNS_RE.match(host):
        raise _fail(f"host inválido: {host!r}")
    return host


def _expect(data: Mapping[str, Any], key: str, expected: str) -> str:
    value = data.get(key)
    if value != expected:
        raise _fail(f"{key} {value!r} difere do esperado ({expected})")
    return expected


def _path(raw: object, *, remote: bool, what: str) -> str:
    if not isinstance(raw, str):
        raise _fail(f"{what} ausente")
    try:
        return canonical_remote(raw) if remote else canonical_local(raw)
    except PathError as exc:
        raise _fail(f"{what}: {exc}") from exc


def parse_connection(data: object, *, server_id: str, device_id: str,
                     project_id: str | None = None) -> Connection:
    if not isinstance(data, dict):
        raise _fail("resposta não é um objeto")
    _expect(data, "server_id", server_id)
    _expect(data, "device_id", device_id)
    project = data.get("project_id")
    if not isinstance(project, str) or not project or (project_id and project != project_id):
        raise _fail(f"project_id {project!r} difere do pedido ({project_id})")
    binding_id = data.get("binding_id")
    if not isinstance(binding_id, str) or not _BINDING_RE.match(binding_id):
        raise _fail(f"binding_id inválido: {binding_id!r}")
    transport = data.get("transport")
    if transport not in TRANSPORTS:
        raise _fail(f"transporte desconhecido: {transport!r}")
    remote = transport == "ssh"

    host = port = user = None
    keys: tuple[str, ...] = ()
    if remote:
        ssh = data.get("ssh")
        if not isinstance(ssh, dict):
            raise _fail("bloco ssh ausente")
        host = valid_host(ssh.get("host"))
        port = ssh.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise _fail(f"porta inválida: {port!r}")
        user = ssh.get("user")
        if not isinstance(user, str) or not _USER_RE.match(user):
            raise _fail(f"conta SSH inválida: {user!r}")
        raw_keys = ssh.get("host_keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise _fail("nenhuma chave de host")
        parsed = []
        for k in raw_keys:
            try:
                line = parse_public_key(k).openssh
            except PublicKeyError as exc:
                raise _fail(f"chave de host recusada (só ssh-ed25519): {exc}") from exc
            if line not in parsed:
                parsed.append(line)
        keys = tuple(parsed)
    elif data.get("ssh") is not None:
        raise _fail("transporte local com bloco ssh")

    paths = data.get("paths")
    if not isinstance(paths, dict):
        raise _fail("caminhos ausentes")
    workspace = _path(paths.get("workspace"), remote=remote, what="paths.workspace")
    shared = _path(paths.get("shared"), remote=remote, what="paths.shared")
    group = data.get("workspace_group")
    if not isinstance(group, str) or not _GROUP_RE.match(group):
        raise _fail(f"workspace_group inválido: {group!r}")
    try:
        rules = ProjectRules.from_dict(data.get("rules"))
    except RulesError as exc:
        raise _fail(f"regras: {exc}") from exc
    if data.get("rules_digest") != rules_digest(rules):
        raise _fail("rules_digest não confere com as regras")
    return Connection(server_id, project, binding_id, device_id, transport, host, port, user,
                      keys, workspace, shared, group, rules, dict(data))


# ---------------------------------------------------------------- arquivos


def render_ssh_config(conns: Sequence[Connection]) -> str:
    out = [HEADER]
    for c in sorted((c for c in conns if c.is_ssh), key=lambda c: c.alias):
        out.append(f"\nHost {c.alias}\n  HostName {c.host}\n  Port {c.port}\n  User {c.user}\n"
                   f"  HostKeyAlias {c.alias}\n")
        out.extend(f"  {k} {v}\n" for k, v in SSH_OPTIONS)
    return "".join(out)


def render_known_hosts(conns: Sequence[Connection]) -> str:
    lines = [f"{c.alias} {key}\n"
             for c in sorted((c for c in conns if c.is_ssh), key=lambda c: c.alias)
             for key in c.host_keys]
    return "".join(lines)


def write_ssh_files(home: Home, conns: Sequence[Connection]) -> None:
    home.ssh_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(home.ssh_config, render_ssh_config(conns).encode("utf-8"))
    atomic_write_bytes(home.known_hosts, render_known_hosts(conns).encode("ascii"))
