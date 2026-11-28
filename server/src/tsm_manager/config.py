"""Configuração do Manager: projetos, regras, limites, banco, SSH, provisionador e TTLs.

Formato ``version: 2`` (JSON)::

    {
      "version": 2,
      "root": "/srv/ts",
      "database": "manager/manager.db",       # opcional; relativo a root, sempre sob root
      "shared_group": "tsm-readers",          # grupo de leitura do shared
      "workspace_group": "tsm-ws",            # grupo do conteúdo dos workspaces
      "ssh": {"host": "ts.example.net", "port": 22,
              "host_key_files": ["/etc/ssh/ssh_host_ed25519_key.pub"],
              "devices_group": "tsm-devices"},          # obrigatório com provisioner sudo
      "provisioner": {"mode": "sudo",                    # local | sudo
                      "helper": "/usr/local/libexec/tsm-provision",
                      "sudo": "/usr/bin/sudo", "timeout_s": 60,
                      "manager_group": "tsm-manager"},
      "auth": {"challenge_ttl_s": 60, "session_ttl_s": 1800, "invite_ttl_s": 86400,
               "invite_ttl_max_s": 604800, "pending_ttl_s": 604800,
               "ssh_keygen": "/usr/bin/ssh-keygen", "sshsig_timeout_s": 5},
      "test_faults": false,
      "projects": [{"id": "demo", "rules": {"allow": [], "ignore": []}, "limits": {}}]
    }

Usuários, dispositivos e vínculos ficam no banco (cadastro com convite e aprovação), não
na config. A ``version: 1``, com identidades de teste e vínculos na própria config, é
recusada com uma mensagem de migração.

``root`` relativo é resolvido a partir do diretório do arquivo de config; ``database``
relativo, a partir de ``root``. Um banco que resolva para fora de ``root`` é recusado: todo
o estado do servidor fica sob ``root``.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tsm_common.pathpolicy import DEFAULT_MAX_PATH_CHARS
from tsm_common.rules import ProjectRules, RulesError
from tsm_manager.adapters.sshsig import default_executable

CONFIG_VERSION = 2
PROVISIONER_MODES = ("local", "sudo")
DEFAULT_DATABASE = "manager/manager.db"
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
V1_MIGRATION = (
    "config.version 1 (identidade de teste) não é mais aceita; use a version 2: remova "
    "identities e projects[].bindings (usuários, dispositivos e vínculos ficam no banco: "
    "bootstrap-admin, convites e aprovação) e inclua workspace_group e provisioner")
_GROUP_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
DAY = 86_400

if TYPE_CHECKING:
    from tsm_manager.identity.base import AuthSettings


class ManagerConfigError(ValueError):
    """Configuração do Manager inválida."""


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 100 * 1024 * 1024
    max_files: int = 2000
    max_total_bytes: int = 1024 * 1024 * 1024
    max_path_chars: int = DEFAULT_MAX_PATH_CHARS

    def to_dict(self) -> dict[str, int]:
        return {
            "max_file_bytes": self.max_file_bytes,
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "max_path_chars": self.max_path_chars,
        }


@dataclass(frozen=True)
class BindingConfig:
    """Vínculo de um dispositivo a um projeto (lido do banco pela ``DbBindings``)."""

    id: str
    device: str     # UUID do dispositivo
    workspace: str  # conta do dispositivo: workspaces/<conta>/tree


@dataclass(frozen=True)
class ProjectConfig:
    id: str
    rules: ProjectRules
    limits: Limits


@dataclass(frozen=True)
class SshConfig:
    """Como os dispositivos chegam ao servidor (entregue pela ``/connection/config``)."""

    host: str
    port: int = 22
    host_key_files: tuple[Path, ...] = ()
    devices_group: str = "tsm-devices"


@dataclass(frozen=True)
class ProvisionerConfig:
    """``local``: só diretórios sob ``root`` (desenvolvimento e testes); ``sudo``: helper."""

    mode: str
    helper: str | None = None
    sudo: str = "/usr/bin/sudo"
    timeout_s: float = 60.0
    manager_group: str = "tsm-manager"


@dataclass(frozen=True)
class AuthConfig:
    challenge_ttl_s: int = 60
    session_ttl_s: int = 1800
    invite_ttl_s: int = DAY
    invite_ttl_max_s: int = 7 * DAY
    pending_ttl_s: int = 7 * DAY
    ssh_keygen: str = field(default_factory=default_executable)
    sshsig_timeout_s: float = 5.0

    def settings(self) -> AuthSettings:
        from tsm_manager.identity.base import AuthSettings

        return AuthSettings(challenge_ttl_s=self.challenge_ttl_s,
                            session_ttl_s=self.session_ttl_s,
                            invite_ttl_s=self.invite_ttl_s,
                            invite_ttl_max_s=self.invite_ttl_max_s,
                            pending_ttl_s=self.pending_ttl_s)


@dataclass(frozen=True)
class ManagerConfig:
    path: Path
    root: Path
    projects: Mapping[str, ProjectConfig]
    database: Path
    shared_group: str
    workspace_group: str
    provisioner: ProvisionerConfig
    auth: AuthConfig
    ssh: SshConfig | None = None
    test_faults: bool = False

    @property
    def backups(self) -> Path:
        """Cópias do banco feitas antes de cada migration."""
        return self.database.parent / "backups"


def _obj(value: Any, where: str, allowed: set[str], required: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ManagerConfigError(f"{where}: esperado um objeto JSON")
    missing = sorted(required - value.keys())
    if missing:
        raise ManagerConfigError(f"{where}: campo obrigatório ausente: {', '.join(missing)}")
    unknown = sorted(value.keys() - allowed)
    if unknown:
        raise ManagerConfigError(f"{where}: campo desconhecido: {', '.join(unknown)}")
    return value


def _text(obj: Mapping[str, Any], key: str, where: str, pattern: re.Pattern[str] | None = None,
          ) -> str:
    v = obj[key]
    if not isinstance(v, str) or not v:
        raise ManagerConfigError(f"{where}.{key}: esperado texto não vazio")
    if pattern is not None and not pattern.match(v):
        raise ManagerConfigError(f"{where}.{key}: valor inválido {v!r}")
    return v


def _limits(raw: Any, where: str) -> Limits:
    if raw is None:
        return Limits()
    fields = set(Limits().to_dict())
    obj = _obj(raw, where, fields, set())
    values = {}
    for k, v in obj.items():
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise ManagerConfigError(f"{where}.{k}: esperado inteiro positivo")
        values[k] = v
    return Limits(**values)


def load_manager_config(path: str | os.PathLike[str]) -> ManagerConfig:
    cfg_path = Path(path).resolve()
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManagerConfigError(f"config não encontrada: {cfg_path}") from exc
    except json.JSONDecodeError as exc:
        raise ManagerConfigError(f"{cfg_path}: JSON inválido: {exc}") from exc

    version = data.get("version") if isinstance(data, dict) else None
    if version == 1 and not isinstance(version, bool):
        raise ManagerConfigError(V1_MIGRATION)
    if version != CONFIG_VERSION or isinstance(version, bool):
        raise ManagerConfigError(f"config.version: suportada: {CONFIG_VERSION}")
    return _load(cfg_path, data)


def _database(top: Mapping[str, Any], root: Path) -> Path:
    raw = top.get("database", DEFAULT_DATABASE)
    if not isinstance(raw, str) or not raw:
        raise ManagerConfigError("config.database: esperado texto não vazio")
    root_real = root.resolve()
    path = Path(raw)
    resolved = (path if path.is_absolute() else root_real / path).resolve()
    if resolved == root_real or not resolved.is_relative_to(root_real):
        raise ManagerConfigError(f"config.database: {raw!r} fica fora de root ({root})")
    return resolved


def _int(obj: Mapping[str, Any], key: str, where: str, default: int, lo: int, hi: int) -> int:
    v = obj.get(key, default)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ManagerConfigError(f"{where}.{key}: esperado inteiro entre {lo} e {hi}")
    return v


def _number(obj: Mapping[str, Any], key: str, where: str, default: float, lo: float,
            hi: float) -> float:
    v = obj.get(key, default)
    if not isinstance(v, int | float) or isinstance(v, bool) or not lo <= v <= hi:
        raise ManagerConfigError(f"{where}.{key}: esperado número entre {lo:g} e {hi:g}")
    return float(v)


def _group(obj: Mapping[str, Any], key: str, where: str, default: str | None = None) -> str:
    v = obj.get(key, default)
    if not isinstance(v, str) or not _GROUP_RE.match(v):
        raise ManagerConfigError(f"{where}.{key}: nome de grupo inválido {v!r}")
    return v


def _absolute(obj: Mapping[str, Any], key: str, where: str, default: str | None = None
              ) -> str:
    v = obj.get(key, default)
    if not isinstance(v, str) or not v or not Path(v).is_absolute():
        raise ManagerConfigError(f"{where}.{key}: esperado caminho absoluto")
    return v


def valid_host(host: object) -> bool:
    """Nome DNS ou endereço IP, sem espaço nem controle, até 253 caracteres."""
    if not isinstance(host, str) or not 0 < len(host) <= 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return all(_HOST_LABEL_RE.match(label) for label in host.split("."))


def _ssh(raw: Any) -> SshConfig:
    where = "config.ssh"
    obj = _obj(raw, where, {"host", "port", "host_key_files", "devices_group"},
               {"host", "host_key_files"})
    if not valid_host(obj["host"]):
        raise ManagerConfigError(f"{where}.host: nome ou IP inválido")
    files = obj["host_key_files"]
    if not isinstance(files, list) or not files or not all(
            isinstance(f, str) and f and Path(f).is_absolute() for f in files):
        raise ManagerConfigError(f"{where}.host_key_files: esperada lista não vazia de "
                                 "caminhos absolutos")
    return SshConfig(obj["host"], _int(obj, "port", where, 22, 1, 65_535),
                     tuple(Path(f) for f in files),
                     _group(obj, "devices_group", where, "tsm-devices"))


def _provisioner(raw: Any) -> ProvisionerConfig:
    where = "config.provisioner"
    obj = _obj(raw, where, {"mode", "helper", "sudo", "timeout_s", "manager_group"}, {"mode"})
    mode = obj["mode"]
    if mode not in PROVISIONER_MODES:
        raise ManagerConfigError(f"{where}.mode: use {' ou '.join(PROVISIONER_MODES)}")
    helper = None
    if mode == "sudo" or "helper" in obj:
        helper = _absolute(obj, "helper", where)
    sudo = _absolute(obj, "sudo", where) if "sudo" in obj else ProvisionerConfig.sudo
    return ProvisionerConfig(mode, helper, sudo,
                             _number(obj, "timeout_s", where, 60.0, 1, 600),
                             _group(obj, "manager_group", where, "tsm-manager"))


def _auth(raw: Any) -> AuthConfig:
    where = "config.auth"
    fields = {"challenge_ttl_s", "session_ttl_s", "invite_ttl_s", "invite_ttl_max_s",
              "pending_ttl_s", "ssh_keygen", "sshsig_timeout_s"}
    obj = _obj({} if raw is None else raw, where, fields, set())
    d = AuthConfig()
    invite_max = _int(obj, "invite_ttl_max_s", where, d.invite_ttl_max_s, 60, 30 * DAY)
    return AuthConfig(
        challenge_ttl_s=_int(obj, "challenge_ttl_s", where, d.challenge_ttl_s, 10, 600),
        session_ttl_s=_int(obj, "session_ttl_s", where, d.session_ttl_s, 60, DAY),
        invite_ttl_s=_int(obj, "invite_ttl_s", where, min(d.invite_ttl_s, invite_max), 60,
                          invite_max),
        invite_ttl_max_s=invite_max,
        pending_ttl_s=_int(obj, "pending_ttl_s", where, d.pending_ttl_s, 3600, 30 * DAY),
        ssh_keygen=_absolute(obj, "ssh_keygen", where, d.ssh_keygen),
        sshsig_timeout_s=_number(obj, "sshsig_timeout_s", where, d.sshsig_timeout_s, 1, 60),
    )


def _load(cfg_path: Path, data: Mapping[str, Any]) -> ManagerConfig:
    top = _obj(data, "config",
               {"version", "root", "database", "shared_group", "workspace_group", "ssh",
                "provisioner", "auth", "test_faults", "projects"},
               {"version", "root", "shared_group", "workspace_group", "provisioner",
                "projects"})
    root = Path(_text(top, "root", "config"))
    if not root.is_absolute():
        root = (cfg_path.parent / root).resolve()
    database = _database(top, root)
    projects: dict[str, ProjectConfig] = {}
    if not isinstance(top["projects"], list) or not top["projects"]:
        raise ManagerConfigError("config.projects: esperada uma lista não vazia")
    for i, rp in enumerate(top["projects"]):
        where = f"projects[{i}]"
        p = _obj(rp, where, {"id", "rules", "limits"}, {"id"})
        pid = _text(p, "id", where, _ID_RE)
        if pid in projects:
            raise ManagerConfigError(f"{where}.id duplicado: {pid}")
        try:
            rules = ProjectRules.from_dict(p.get("rules"))
        except RulesError as exc:
            raise ManagerConfigError(f"{where}.rules: {exc}") from exc
        projects[pid] = ProjectConfig(pid, rules, _limits(p.get("limits"), f"{where}.limits"))
    provisioner = _provisioner(top["provisioner"])
    ssh = _ssh(top["ssh"]) if "ssh" in top else None
    if provisioner.mode == "sudo" and ssh is None:
        raise ManagerConfigError("config.ssh: obrigatório com provisioner.mode sudo")
    faults = top.get("test_faults", False)
    if not isinstance(faults, bool):
        raise ManagerConfigError("config.test_faults: esperado booleano")
    return ManagerConfig(
        cfg_path, root, projects, database,
        shared_group=_group(top, "shared_group", "config"),
        workspace_group=_group(top, "workspace_group", "config"),
        provisioner=provisioner, auth=_auth(top.get("auth")), ssh=ssh, test_faults=faults)
