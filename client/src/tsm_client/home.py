"""Diretório do Client (``<home>``): config, HOME gerenciado do ssh, daemon e estado.

Resolução: ``--home`` > ``TSM_HOME`` > padrão (``%LOCALAPPDATA%\\tsm`` no Windows;
``$XDG_DATA_HOME/tsm`` ou ``~/.local/share/tsm`` em POSIX). Layout::

    <home>/
      .tsm-home                  marca de diretório criado pelo tsm
      config.json                config version 3
      config.lock                lock das gravações da config
      ssh/                       HOME gerenciado do ssh e do ssh-keygen
        .ssh/id_ed25519(.pub)    chave do dispositivo
        .ssh/config              aliases tsm-<vínculo>
        .ssh/known_hosts         só chaves vindas da /connection/config
      mutagen-data/              daemon isolado
      state/                     estado dos vínculos, session.json, refused, connections/
      cache/<projeto>/           cache padrão dos vínculos

A ACL só do usuário (herdável) é aplicada a um ``<home>`` novo ou vazio; um diretório que
não é do tsm é recusado, para que nunca se troque a ACL de uma pasta alheia.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from tsm_client.adapters.acl import Acl
from tsm_client.paths import Endpoint, PathError, canonical_local, endpoints_overlap

ENV_HOME = "TSM_HOME"
MARKER = ".tsm-home"
HOME_CONFIG_VERSION = 3


class HomeError(ValueError):
    """``<home>`` inválido, alheio ou sobreposto a uma pasta de vínculo."""


@dataclass(frozen=True)
class Home:
    root: Path

    @property
    def config_path(self) -> Path:
        return self.root / "config.json"

    @property
    def config_lock(self) -> Path:
        return self.root / "config.lock"

    @property
    def ssh_home(self) -> Path:
        return self.root / "ssh"

    @property
    def ssh_dir(self) -> Path:
        return self.ssh_home / ".ssh"

    @property
    def key_path(self) -> Path:
        return self.ssh_dir / "id_ed25519"

    @property
    def pub_path(self) -> Path:
        return self.ssh_dir / "id_ed25519.pub"

    @property
    def ssh_config(self) -> Path:
        return self.ssh_dir / "config"

    @property
    def known_hosts(self) -> Path:
        return self.ssh_dir / "known_hosts"

    @property
    def mutagen_data(self) -> Path:
        return self.root / "mutagen-data"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def session_file(self) -> Path:
        return self.state / "session.json"

    @property
    def refused_file(self) -> Path:
        return self.state / "refused"

    @property
    def connections_dir(self) -> Path:
        return self.state / "connections"

    def connection_file(self, binding_id: str) -> Path:
        return self.connections_dir / f"{binding_id}.json"

    def default_cache(self, project_id: str) -> Path:
        return self.root / "cache" / project_id

    def check_outside(self, path: Path) -> None:
        """Uma pasta local de vínculo não pode conter o ``<home>`` nem estar dentro dele."""
        if endpoints_overlap(Endpoint(None, str(self.root)), Endpoint(None, str(path))):
            raise HomeError(f"a pasta {path} não pode se sobrepor ao diretório do tsm "
                            f"({self.root})")


def default_home(environ: Mapping[str, str] | None = None,
                 platform: str | None = None) -> Path:
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    if plat == "win32":
        base = env.get("LOCALAPPDATA")
        if not base:
            raise HomeError("LOCALAPPDATA não definido: use --home ou TSM_HOME")
        return Path(base) / "tsm"
    if env.get("XDG_DATA_HOME"):
        return Path(env["XDG_DATA_HOME"]) / "tsm"
    if not env.get("HOME"):
        raise HomeError("HOME não definido: use --home ou TSM_HOME")
    return Path(env["HOME"]) / ".local" / "share" / "tsm"


def resolve_home(value: str | None, environ: Mapping[str, str] | None = None) -> Home:
    env = os.environ if environ is None else environ
    raw = value if value is not None else env.get(ENV_HOME) or None
    path = Path(raw) if raw is not None else default_home(env)
    try:
        return Home(Path(canonical_local(str(path) if raw is None else raw)))
    except PathError as exc:
        raise HomeError(f"diretório do tsm inválido: {exc}") from exc


def home_state(home: Home) -> str:
    """``absent``, ``empty``, ``ours`` ou ``foreign``."""
    root = home.root
    if not root.exists():
        return "absent"
    if not root.is_dir():
        return "foreign"
    if (root / MARKER).is_file():
        return "ours"
    if home.config_path.is_file():
        try:
            data = json.loads(home.config_path.read_text("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return "foreign"
        if isinstance(data, dict) and data.get("version") == HOME_CONFIG_VERSION:
            return "ours"
        return "foreign"
    return "empty" if not any(root.iterdir()) else "foreign"


def prepare_home(home: Home, acl: Acl) -> None:
    """Cria (ou confere) o ``<home>`` e aplica a ACL só do usuário."""
    if home.root.exists() and not home.root.is_dir():
        raise HomeError(f"o caminho do tsm não é um diretório: {home.root}")
    state = home_state(home)
    if state == "foreign":
        raise HomeError(f"{home.root} não é um diretório do tsm e não está vazio: "
                        "use outro --home")
    if state in ("absent", "empty"):
        home.root.mkdir(parents=True, exist_ok=True)
        acl.restrict_dir(home.root)
        (home.root / MARKER).write_text("tsm\n", encoding="utf-8")
    for d in (home.ssh_dir, home.mutagen_data, home.state):
        d.mkdir(parents=True, exist_ok=True)
    acl.restrict_dir(home.ssh_dir)
