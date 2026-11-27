"""Configuração da PoC (por dispositivo, fora do repositório) e validação de ``ts-project.json``.

Formato (JSON)::

    {
      "version": 1,
      "device_id": "pca",
      "mutagen": {
        "data_directory": "pcA/mutagen-data",      # obrigatório: daemon isolado
        "executable": "...mutagen.exe",            # opcional: padrão = .tools fixado
        "ssh_path": "C:/Program Files/Git/usr/bin", # opcional: MUTAGEN_SSH_PATH
        "ssh_home": "ssh-home"                     # opcional: HOME gerenciado (config SSH)
      },
      "bindings": [{
        "id": "demo-pca", "project_id": "demo",
        "local": "...", "cache": "...",            # sempre locais
        "workspace": "alias:/srv/...", "shared": "alias:/srv/...",  # locais ou remotos
        "rules": {"allow": ["data/"], "ignore": ["*.bak"]}
      }]
    }

Na ``version: 2`` entram ``state_directory`` (estado local por vínculo: base,
armazenamento de conteúdo e lock) e ``manager`` (``url`` + ``token_file`` da
identidade de teste), além de ``git`` (opcional, executável do Git)::

    "state_directory": "pcA/state",
    "manager": {"url": "http://127.0.0.1:8740", "token_file": "pcA/manager-token"},
    "git": "C:/Program Files/Git/cmd/git.exe"

Configs ``version: 1`` continuam válidas para os comandos de transporte.

Caminhos locais relativos são resolvidos a partir do diretório do arquivo de config.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tsm_client.paths import Endpoint, PathError, canonical_local, endpoints_overlap, parse_endpoint
from tsm_client.rules import PROJECT_FILE, ProjectRules, RulesError
from tsm_client.sessions import Binding, SessionRuleError

CONFIG_VERSIONS = (1, 2)
PROJECT_FILE_VERSION = 1

_TOP_FIELDS = {"version", "device_id", "mutagen", "bindings"}
_TOP_FIELDS_V2 = _TOP_FIELDS | {"state_directory", "manager", "git"}
_MANAGER_FIELDS = {"url", "token_file"}
_MUTAGEN_FIELDS = {"data_directory", "executable", "ssh_path", "ssh_home"}
_BINDING_FIELDS = {"id", "project_id", "local", "cache", "workspace", "shared", "rules"}
_BINDING_REQUIRED = _BINDING_FIELDS - {"rules"}


class ConfigError(ValueError):
    """Configuração inválida ou pasta de projeto inconsistente."""


@dataclass(frozen=True)
class MutagenSettings:
    data_directory: Path
    executable: Path | None
    ssh_path: Path | None
    ssh_home: Path | None


@dataclass(frozen=True)
class ManagerSettings:
    url: str
    token_file: Path


@dataclass(frozen=True)
class Config:
    path: Path
    device_id: str
    mutagen: MutagenSettings
    bindings: tuple[Binding, ...]
    version: int = 1
    state_directory: Path | None = None
    manager: ManagerSettings | None = None
    git: str | None = None

    @property
    def collab_enabled(self) -> bool:
        return self.state_directory is not None and self.manager is not None


def _check_fields(obj: Any, where: str, allowed: set[str], required: set[str]) -> Mapping[str, Any]:
    if not isinstance(obj, dict):
        raise ConfigError(f"{where}: esperado um objeto JSON")
    missing = sorted(required - obj.keys())
    if missing:
        raise ConfigError(f"{where}: campo obrigatório ausente: {', '.join(missing)}")
    unknown = sorted(obj.keys() - allowed)
    if unknown:
        raise ConfigError(f"{where}: campo desconhecido: {', '.join(unknown)}")
    return obj


def _str(obj: Mapping[str, Any], key: str, where: str) -> str:
    value = obj[key]
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where}.{key}: esperado texto não vazio")
    return value


def _resolve_local(raw: str, base: Path) -> str:
    p = raw if os.path.isabs(raw) or raw.startswith(("\\\\", "//")) else str(base / raw)
    return canonical_local(p)


def _parse_endpoint_field(obj: Mapping[str, Any], key: str, base: Path, where: str) -> Endpoint:
    raw = _str(obj, key, where)
    try:
        if ":" not in raw and not raw.startswith(("\\", "/")):
            # caminho local relativo ao arquivo de config
            return Endpoint(None, _resolve_local(raw, base))
        return parse_endpoint(raw)
    except PathError as exc:
        raise ConfigError(f"{where}.{key}: {exc}") from exc


def _optional_path(obj: Mapping[str, Any], key: str, base: Path) -> Path | None:
    if obj.get(key) in (None, ""):
        return None
    try:
        return Path(_resolve_local(_str(obj, key, "mutagen"), base))
    except PathError as exc:
        raise ConfigError(f"mutagen.{key}: {exc}") from exc


def load_config(path: str | os.PathLike[str]) -> Config:
    cfg_path = Path(path)
    try:
        text = cfg_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"arquivo de configuração não encontrado: {cfg_path}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{cfg_path}: JSON inválido: {exc}") from exc

    base = cfg_path.resolve().parent
    version = data.get("version") if isinstance(data, dict) else None
    if version not in CONFIG_VERSIONS:
        raise ConfigError(f"config.version: suportadas {', '.join(map(str, CONFIG_VERSIONS))}")
    if version == 1:
        top = _check_fields(data, "config", _TOP_FIELDS, _TOP_FIELDS)
    else:
        top = _check_fields(data, "config", _TOP_FIELDS_V2,
                            _TOP_FIELDS | {"state_directory", "manager"})
    device_id = _str(top, "device_id", "config")

    m = _check_fields(top["mutagen"], "mutagen", _MUTAGEN_FIELDS, {"data_directory"})
    data_dir = _optional_path(m, "data_directory", base)
    assert data_dir is not None
    settings = MutagenSettings(
        data_directory=data_dir,
        executable=_optional_path(m, "executable", base),
        ssh_path=_optional_path(m, "ssh_path", base),
        ssh_home=_optional_path(m, "ssh_home", base),
    )

    raw_bindings = top["bindings"]
    if not isinstance(raw_bindings, list) or not raw_bindings:
        raise ConfigError("config.bindings: esperada uma lista não vazia")
    bindings: list[Binding] = []
    for i, rb in enumerate(raw_bindings):
        where = f"bindings[{i}]"
        b = _check_fields(rb, where, _BINDING_FIELDS, _BINDING_REQUIRED)
        try:
            rules = ProjectRules.from_dict(b.get("rules"))
        except RulesError as exc:
            raise ConfigError(f"{where}.rules: {exc}") from exc
        try:
            bindings.append(
                Binding(
                    id=_str(b, "id", where),
                    project_id=_str(b, "project_id", where),
                    local=_parse_endpoint_field(b, "local", base, where),
                    cache=_parse_endpoint_field(b, "cache", base, where),
                    workspace=_parse_endpoint_field(b, "workspace", base, where),
                    shared=_parse_endpoint_field(b, "shared", base, where),
                    rules=rules,
                )
            )
        except SessionRuleError as exc:
            raise ConfigError(f"{where}: {exc}") from exc

    ids = [b.id for b in bindings]
    if len(set(ids)) != len(ids):
        raise ConfigError(f"config.bindings: id duplicado em {ids}")

    state_dir: Path | None = None
    manager: ManagerSettings | None = None
    git: str | None = None
    if version == 2:
        try:
            state_dir = Path(_resolve_local(_str(top, "state_directory", "config"), base))
        except PathError as exc:
            raise ConfigError(f"config.state_directory: {exc}") from exc
        mg = _check_fields(top["manager"], "manager", _MANAGER_FIELDS, _MANAGER_FIELDS)
        url = _str(mg, "url", "manager").rstrip("/")
        if not url.startswith(("http://", "https://")):
            raise ConfigError("manager.url: use http:// ou https://")
        try:
            token_file = Path(_resolve_local(_str(mg, "token_file", "manager"), base))
        except PathError as exc:
            raise ConfigError(f"manager.token_file: {exc}") from exc
        manager = ManagerSettings(url, token_file)
        if top.get("git") not in (None, ""):
            git = _str(top, "git", "config")

    own_dirs = [("mutagen.data_directory", settings.data_directory),
                ("mutagen.ssh_home", settings.ssh_home), ("state_directory", state_dir)]
    for key, value in own_dirs:
        if value is None:
            continue
        own = Endpoint(None, str(value))
        for b in bindings:
            for ep in (b.local, b.cache, b.workspace, b.shared):
                if endpoints_overlap(own, ep):
                    raise ConfigError(
                        f"{key} ({value}) não pode se sobrepor a endpoints ({ep.url})"
                    )

    return Config(path=cfg_path.resolve(), device_id=device_id, mutagen=settings,
                  bindings=tuple(bindings), version=version, state_directory=state_dir,
                  manager=manager, git=git)


def verify_project_folder(binding: Binding) -> None:
    """Confere que a pasta local existe e tem ``ts-project.json`` do projeto do vínculo."""
    root = Path(binding.local.path)
    if not root.is_dir():
        raise ConfigError(f"a pasta local não existe: {root}")
    pf = root / PROJECT_FILE
    if not pf.is_file():
        raise ConfigError(f"{PROJECT_FILE} ausente na pasta local: {root}")
    try:
        data = json.loads(pf.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{pf}: JSON inválido: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{pf}: esperado um objeto JSON")
    if data.get("version") != PROJECT_FILE_VERSION:
        raise ConfigError(f"{pf}: version suportada = {PROJECT_FILE_VERSION}")
    if data.get("project_id") != binding.project_id:
        raise ConfigError(
            f"{pf}: project_id {data.get('project_id')!r} difere do vínculo "
            f"({binding.project_id!r})"
        )
