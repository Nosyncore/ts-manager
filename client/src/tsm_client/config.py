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

A ``version: 3`` mora no diretório do Client (``<home>/config.json``, ``tsm_client.home``) e
é escrita só pelo ``tsm`` (``enroll`` e ``bind``)::

    {"version": 3,
     "manager": {"url": "http://127.0.0.1:8740", "server_id": "<uuid>", "ca_file": null},
     "device": {"id": "<uuid>", "fingerprint": "SHA256:…"},
     "mutagen": {"executable": null, "ssh_path": "C:/Program Files/Git/usr/bin"},
     "git": null,
     "bindings": [{"id": "b-…", "project_id": "demo", "local": "D:/proj/demo",
                   "cache": "<home>/cache/demo"}]}

Workspace, shared, alias SSH, regras e grupo do workspace de cada vínculo vêm da última
``/connection/config`` (``<home>/state/connections/<vínculo>.json``); o daemon, o HOME do
ssh e o estado ficam em caminhos fixos do ``<home>``. As ``version: 1`` e ``2`` só são
lidas por ``--config`` e a ``version: 3`` só pelo ``<home>``.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tsm_client.adapters.manager import ManagerUrlError, check_url
from tsm_client.adapters.sshkeygen import default_ssh_path
from tsm_client.errors import RefusedError
from tsm_client.home import HOME_CONFIG_VERSION, Home, HomeError
from tsm_client.paths import Endpoint, PathError, canonical_local, endpoints_overlap, parse_endpoint
from tsm_client.rules import PROJECT_FILE, ProjectRules, RulesError
from tsm_client.sessions import Binding, SessionRuleError
from tsm_client.sshconfig import Connection, parse_connection
from tsm_common.fsutil import LockTimeout, atomic_write_json, file_lock
from tsm_common.sshkeys import is_fingerprint

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
    token_file: Path | None  # só na version 2 (identidade de teste)
    server_id: str | None = None
    ca_file: Path | None = None


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
    home: Home | None = None
    fingerprint: str | None = None

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

    check_own_dirs(settings, state_dir, bindings)
    return Config(path=cfg_path.resolve(), device_id=device_id, mutagen=settings,
                  bindings=tuple(bindings), version=version, state_directory=state_dir,
                  manager=manager, git=git)


def check_own_dirs(settings: MutagenSettings, state_dir: Path | None,
                    bindings: list[Binding]) -> None:
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


# ---------------------------------------------------------------- version 3 (<home>)

_V3_TOP = {"version", "manager", "device", "mutagen", "git", "bindings"}
_V3_MANAGER = {"url", "server_id", "ca_file"}
_V3_DEVICE = {"id", "fingerprint"}
_V3_MUTAGEN = {"executable", "ssh_path"}
_V3_BINDING = {"id", "project_id", "local", "cache"}
_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_BINDING_ID_RE = _PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")


@dataclass(frozen=True)
class HomeBinding:
    id: str
    project_id: str
    local: str
    cache: str


@dataclass
class HomeConfig:
    """Conteúdo de ``<home>/config.json`` (``version: 3``)."""

    manager_url: str
    server_id: str
    device_id: str
    fingerprint: str
    ca_file: str | None = None
    mutagen_executable: str | None = None
    ssh_path: str | None = None
    git: str | None = None
    bindings: list[HomeBinding] = field(default_factory=list)

    @property
    def ssh_dir(self) -> Path:
        return Path(self.ssh_path) if self.ssh_path else default_ssh_path()

    def binding_for(self, project_id: str) -> HomeBinding | None:
        return next((b for b in self.bindings if b.project_id == project_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {"version": HOME_CONFIG_VERSION,
                "manager": {"url": self.manager_url, "server_id": self.server_id,
                            "ca_file": self.ca_file},
                "device": {"id": self.device_id, "fingerprint": self.fingerprint},
                "mutagen": {"executable": self.mutagen_executable, "ssh_path": self.ssh_path},
                "git": self.git,
                "bindings": [{"id": b.id, "project_id": b.project_id, "local": b.local,
                              "cache": b.cache} for b in self.bindings]}

    @classmethod
    def from_dict(cls, data: Any) -> HomeConfig:
        top = _check_fields(data, "config", _V3_TOP, _V3_TOP - {"git"})
        if top["version"] != HOME_CONFIG_VERSION:
            raise ConfigError(f"config.version: esperada {HOME_CONFIG_VERSION}")
        mg = _check_fields(top["manager"], "manager", _V3_MANAGER, {"url", "server_id"})
        try:
            url = check_url(_str(mg, "url", "manager"))
        except ManagerUrlError as exc:
            raise ConfigError(f"manager.url: {exc}") from exc
        server_id = _str(mg, "server_id", "manager")
        dev = _check_fields(top["device"], "device", _V3_DEVICE, _V3_DEVICE)
        device_id = _str(dev, "id", "device")
        if not _ID_RE.match(server_id) or not _ID_RE.match(device_id):
            raise ConfigError("manager.server_id ou device.id inválido")
        fp = dev["fingerprint"]
        if not is_fingerprint(fp):
            raise ConfigError("device.fingerprint inválido")
        mu = _check_fields(top["mutagen"], "mutagen", _V3_MUTAGEN, set())
        raw_bindings = top["bindings"]
        if not isinstance(raw_bindings, list):
            raise ConfigError("config.bindings: esperada uma lista")
        bindings = []
        for i, rb in enumerate(raw_bindings):
            where = f"bindings[{i}]"
            b = _check_fields(rb, where, _V3_BINDING, _V3_BINDING)
            bid, pid = _str(b, "id", where), _str(b, "project_id", where)
            if not _BINDING_ID_RE.match(bid) or not _PROJECT_ID_RE.match(pid):
                raise ConfigError(f"{where}: id ou project_id inválido")
            bindings.append(HomeBinding(bid, pid, _abs(b, "local", where),
                                        _abs(b, "cache", where)))
        if len({b.id for b in bindings}) != len(bindings) or \
                len({b.project_id for b in bindings}) != len(bindings):
            raise ConfigError("config.bindings: vínculo ou projeto repetido")
        return cls(url, server_id, device_id, fp,
                   ca_file=_opt_abs(mg, "ca_file", "manager"),
                   mutagen_executable=_opt_abs(mu, "executable", "mutagen"),
                   ssh_path=_opt_abs(mu, "ssh_path", "mutagen"),
                   git=_opt_abs(top, "git", "config"), bindings=bindings)


def _abs(obj: Mapping[str, Any], key: str, where: str) -> str:
    try:
        return canonical_local(_str(obj, key, where))
    except PathError as exc:
        raise ConfigError(f"{where}.{key}: {exc}") from exc


def _opt_abs(obj: Mapping[str, Any], key: str, where: str) -> str | None:
    if obj.get(key) in (None, ""):
        return None
    value = _str(obj, key, where)
    if not os.path.isabs(value):
        raise ConfigError(f"{where}.{key}: caminho absoluto esperado")
    return value


def read_home_config(home: Home) -> HomeConfig:
    try:
        data = json.loads(home.config_path.read_text("utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"nenhum dispositivo cadastrado em {home.root}: rode "
                          "'tsm enroll' (ou use --home)") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"{home.config_path}: JSON inválido: {exc}") from exc
    return HomeConfig.from_dict(data)


def write_home_config(home: Home, hc: HomeConfig) -> None:
    try:
        with file_lock(home.config_lock, timeout=10):
            atomic_write_json(home.config_path, hc.to_dict())
    except LockTimeout as exc:
        raise RefusedError("outro comando do tsm está gravando a config") from exc


def read_connection(home: Home, hc: HomeConfig, hb: HomeBinding) -> Connection:
    path = home.connection_file(hb.id)
    try:
        data = json.loads(path.read_text("utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"vínculo {hb.id} sem configuração de conexão: rode "
                          f"'tsm bind --project {hb.project_id}'") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"{path}: JSON inválido: {exc}") from exc
    conn = parse_connection(data, server_id=hc.server_id, device_id=hc.device_id,
                            project_id=hb.project_id)
    if conn.binding_id != hb.id:
        raise ConfigError(f"{path}: pertence a outro vínculo ({conn.binding_id})")
    return conn


def home_connections(home: Home, hc: HomeConfig) -> list[Connection]:
    return [read_connection(home, hc, hb) for hb in hc.bindings]


def load_home_config(home: Home) -> Config:
    hc = read_home_config(home)
    settings = MutagenSettings(
        data_directory=home.mutagen_data,
        executable=Path(hc.mutagen_executable) if hc.mutagen_executable else None,
        ssh_path=hc.ssh_dir, ssh_home=home.ssh_home)
    bindings: list[Binding] = []
    for hb in hc.bindings:
        try:
            home.check_outside(Path(hb.local))
        except HomeError as exc:
            raise ConfigError(str(exc)) from exc
        bindings.append(read_connection(home, hc, hb).binding(hb.local, hb.cache))
    check_own_dirs(settings, home.state, bindings)
    manager = ManagerSettings(hc.manager_url, None, hc.server_id,
                              Path(hc.ca_file) if hc.ca_file else None)
    return Config(path=home.config_path, device_id=hc.device_id, mutagen=settings,
                  bindings=tuple(bindings), version=HOME_CONFIG_VERSION,
                  state_directory=home.state, manager=manager, git=hc.git, home=home,
                  fingerprint=hc.fingerprint)


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
