"""Configuração de conexão de um dispositivo aprovado (``GET /connection/config``).

É a única fonte, para o Client, de host, porta, conta, chaves de host, caminhos e regras.
As chaves de host vêm de ``ssh.host_key_files``, lidas e validadas uma vez na
inicialização do ``serve``: só ``ssh-ed25519``, normalizadas sem comentário. O Client monta
a linha do ``known_hosts`` com o alias que ele mesmo gera.

``transport``:

- ``ssh`` (provisionador ``sudo``): o Client sincroniza pela conta SSH do dispositivo;
- ``local`` (provisionador ``local``, desenvolvimento e testes): não há conta; os caminhos
  são do mesmo computador, e ``ssh`` vem ``null``.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from tsm_common.rules import rules_digest
from tsm_common.sshkeys import PublicKeyError, parse_public_key
from tsm_manager.config import ProjectConfig, SshConfig
from tsm_manager.db.repository import Binding, Device
from tsm_manager.layout import ProjectLayout

TRANSPORTS = ("ssh", "local")
_MAX_HOST_KEY_BYTES = 16 * 1024


class HostKeyError(ValueError):
    """Arquivo de chave de host ausente, ilegível ou fora do formato aceito."""


def _read_host_key(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HostKeyError(f"chave de host ilegível: {path}") from exc
    if len(raw) > _MAX_HOST_KEY_BYTES:
        raise HostKeyError(f"arquivo de chave de host grande demais: {path}")
    lines = [ln for ln in raw.decode("utf-8", "replace").splitlines() if ln.strip()]
    if not lines:
        raise HostKeyError(f"arquivo de chave de host vazio: {path}")
    if len(lines) != 1:
        raise HostKeyError(f"esperada uma linha por arquivo de chave de host: {path}")
    try:
        return parse_public_key(lines[0].strip()).openssh
    except PublicKeyError as exc:
        raise HostKeyError(f"chave de host recusada (só ssh-ed25519): {path}: {exc}") \
            from exc


def load_host_keys(files: Iterable[Path]) -> tuple[str, ...]:
    """Chaves de host normalizadas, sem repetição, na ordem da config."""
    keys: list[str] = []
    for path in files:
        key = _read_host_key(Path(path))
        if key not in keys:
            keys.append(key)
    if not keys:
        raise HostKeyError("nenhuma chave de host configurada")
    return tuple(keys)


def connection_config(*, server_id: str, project: ProjectConfig, layout: ProjectLayout,
                      binding: Binding, device: Device, ssh: SshConfig | None,
                      host_keys: tuple[str, ...], workspace_group: str,
                      transport: str) -> dict[str, Any]:
    if transport not in TRANSPORTS:
        raise ValueError(f"transporte desconhecido: {transport!r}")
    ssh_block = None
    if transport == "ssh":
        if ssh is None or not host_keys:
            raise ValueError("transporte ssh exige host e chaves de host")
        ssh_block = {"host": ssh.host, "port": ssh.port, "user": device.ssh_account,
                     "host_keys": list(host_keys)}
    return {
        "server_id": server_id,
        "project_id": project.id,
        "binding_id": binding.id,
        "device_id": device.id,
        "transport": transport,
        "ssh": ssh_block,
        "paths": {"workspace": str(layout.sync_root(binding.workspace)),
                  "shared": str(layout.shared)},
        "workspace_group": workspace_group,
        "rules": {"allow": list(project.rules.allow), "ignore": list(project.rules.ignore)},
        "rules_digest": rules_digest(project.rules),
    }
