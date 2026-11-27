"""Configuração do Manager: projetos, vínculos, regras, limites e identidades de teste.

Formato (JSON)::

    {
      "version": 1,
      "root": "/srv/ts",
      "database": "manager/manager.db",       # opcional; relativo a root, sempre sob root
      "shared_group": "tsm-readers",          # opcional (POSIX): grupo de leitura do shared
      "test_faults": false,                   # opcional: aceita falhas injetadas (só testes)
      "projects": [{
        "id": "demo",
        "rules": {"allow": [], "ignore": []},
        "limits": {"max_file_bytes": 104857600, "max_files": 2000,
                   "max_total_bytes": 1073741824, "max_path_chars": 200},
        "bindings": [{"id": "demo-pca", "device": "pca", "workspace": "pca"}]
      }],
      "identities": [
        {"name": "dev-a", "role": "developer", "device": "pca", "token_sha256": "<hex>"}
      ]
    }

``root`` relativo é resolvido a partir do diretório do arquivo de config; ``database``
relativo, a partir de ``root``. Um banco que resolva para fora de ``root`` é recusado: todo
o estado do servidor fica sob ``root``. As identidades são de teste e serão substituídas
pela identidade real.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tsm_common.pathpolicy import DEFAULT_MAX_PATH_CHARS
from tsm_common.rules import ProjectRules, RulesError

CONFIG_VERSION = 1
DEFAULT_DATABASE = "manager/manager.db"
ROLES = ("developer", "admin")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


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
    id: str
    device: str
    workspace: str  # nome do diretório em workspaces/


@dataclass(frozen=True)
class ProjectConfig:
    id: str
    rules: ProjectRules
    limits: Limits
    bindings: Mapping[str, BindingConfig]


@dataclass(frozen=True)
class Identity:
    name: str
    role: str
    device: str | None
    token_sha256: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


@dataclass(frozen=True)
class ManagerConfig:
    path: Path
    root: Path
    projects: Mapping[str, ProjectConfig]
    identities: tuple[Identity, ...]
    database: Path
    shared_group: str | None = None
    test_faults: bool = False
    extra: Mapping[str, Any] = field(default_factory=dict)

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

    top = _obj(data, "config",
               {"version", "root", "database", "shared_group", "test_faults", "projects",
                "identities"},
               {"version", "root", "projects", "identities"})
    if top["version"] != CONFIG_VERSION:
        raise ManagerConfigError(f"config.version: suportado apenas {CONFIG_VERSION}")
    root = Path(_text(top, "root", "config"))
    if not root.is_absolute():
        root = (cfg_path.parent / root).resolve()
    database = _database(top, root)

    projects: dict[str, ProjectConfig] = {}
    if not isinstance(top["projects"], list) or not top["projects"]:
        raise ManagerConfigError("config.projects: esperada uma lista não vazia")
    devices_in_use: dict[str, str] = {}
    for i, rp in enumerate(top["projects"]):
        where = f"projects[{i}]"
        p = _obj(rp, where, {"id", "rules", "limits", "bindings"}, {"id", "bindings"})
        pid = _text(p, "id", where, _ID_RE)
        if pid in projects:
            raise ManagerConfigError(f"{where}.id duplicado: {pid}")
        try:
            rules = ProjectRules.from_dict(p.get("rules"))
        except RulesError as exc:
            raise ManagerConfigError(f"{where}.rules: {exc}") from exc
        bindings: dict[str, BindingConfig] = {}
        workspaces: set[str] = set()
        if not isinstance(p["bindings"], list):
            raise ManagerConfigError(f"{where}.bindings: esperada uma lista")
        for j, rb in enumerate(p["bindings"]):
            bw = f"{where}.bindings[{j}]"
            b = _obj(rb, bw, {"id", "device", "workspace"}, {"id", "device", "workspace"})
            bid = _text(b, "id", bw, _ID_RE)
            if bid in bindings:
                raise ManagerConfigError(f"{bw}.id duplicado: {bid}")
            ws = _text(b, "workspace", bw, _DEVICE_RE)
            if ws in workspaces:
                raise ManagerConfigError(f"{bw}.workspace já usado por outro vínculo: {ws}")
            workspaces.add(ws)
            device = _text(b, "device", bw, _DEVICE_RE)
            key = f"{pid}/{device}"
            if key in devices_in_use:
                raise ManagerConfigError(f"{bw}: o dispositivo {device} já tem vínculo em {pid}")
            devices_in_use[key] = bid
            bindings[bid] = BindingConfig(bid, device, ws)
        projects[pid] = ProjectConfig(pid, rules, _limits(p.get("limits"), f"{where}.limits"),
                                      bindings)

    identities: list[Identity] = []
    tokens: set[str] = set()
    if not isinstance(top["identities"], list):
        raise ManagerConfigError("config.identities: esperada uma lista")
    for i, ri in enumerate(top["identities"]):
        where = f"identities[{i}]"
        it = _obj(ri, where, {"name", "role", "device", "token_sha256"},
                  {"name", "role", "token_sha256"})
        role = _text(it, "role", where)
        if role not in ROLES:
            raise ManagerConfigError(f"{where}.role: use {' ou '.join(ROLES)}")
        token = _text(it, "token_sha256", where, _HEX64_RE)
        if token in tokens:
            raise ManagerConfigError(f"{where}: token repetido")
        tokens.add(token)
        device = it.get("device")
        if device is not None and (not isinstance(device, str) or not _DEVICE_RE.match(device)):
            raise ManagerConfigError(f"{where}.device: valor inválido")
        identities.append(Identity(_text(it, "name", where), role, device, token))

    group = top.get("shared_group")
    if group is not None and (not isinstance(group, str) or not group):
        raise ManagerConfigError("config.shared_group: esperado texto não vazio")
    faults = top.get("test_faults", False)
    if not isinstance(faults, bool):
        raise ManagerConfigError("config.test_faults: esperado booleano")
    return ManagerConfig(cfg_path, root, projects, tuple(identities), database, group, faults)


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
