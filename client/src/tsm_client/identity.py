"""Identidade do dispositivo: chave Ed25519, fingerprint e ``server_id`` fixado.

- O fingerprint é calculado aqui, a partir da chave pública (``tsm_common.sshkeys``); nunca
  é aceito do Manager.
- O ``server_id`` é fixado no cadastro. Uma resposta de desafio, de ``/me`` ou de
  ``/connection/config`` com outro ``server_id`` é recusada antes de assinar ou gravar.
- A mensagem assinada é a canônica de ``tsm_common.authmsg``, com o fingerprint local e o
  propósito que o Client espera (não o devolvido pelo Manager).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tsm_client.adapters.acl import Acl
from tsm_client.adapters.manager import ManagerProtocolError
from tsm_client.adapters.sshkeygen import KeygenError, SshKeygen
from tsm_client.errors import RefusedError
from tsm_client.home import Home
from tsm_common.authmsg import AuthMessage, AuthMessageError, parse_expires
from tsm_common.sshkeys import PublicKeyError, parse_public_key

_SERVER_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


class ServerMismatch(RefusedError):
    """O Manager respondeu com outro ``server_id``: não é o Manager do cadastro."""


@dataclass(frozen=True)
class DeviceKey:
    private: Path
    public_line: str
    fingerprint: str


def load_device_key(home: Home) -> DeviceKey | None:
    priv, pub = home.key_path, home.pub_path
    if not priv.exists() and not pub.exists():
        return None
    if not (priv.is_file() and pub.is_file()):
        raise KeygenError(f"chave do dispositivo incompleta em {home.ssh_dir}: "
                          "restaure os dois arquivos (id_ed25519 e id_ed25519.pub)")
    try:
        key = parse_public_key(pub.read_text("utf-8").strip())
    except (OSError, UnicodeDecodeError, PublicKeyError) as exc:
        raise KeygenError(f"chave pública do dispositivo inválida: {pub}") from exc
    return DeviceKey(priv, key.openssh, key.fingerprint)


def ensure_device_key(home: Home, keygen: SshKeygen, acl: Acl) -> tuple[DeviceKey, bool]:
    """Chave do dispositivo (gerada se faltar, com a ACL só do usuário); ``(chave, nova)``."""
    existing = load_device_key(home)
    if existing is not None:
        return existing, False
    home.ssh_dir.mkdir(parents=True, exist_ok=True)
    keygen.generate(home.key_path)
    acl.restrict_file(home.key_path)
    key = load_device_key(home)
    assert key is not None
    return key, True


def valid_id(value: object, what: str) -> str:
    if not isinstance(value, str) or not _SERVER_ID_RE.match(value):
        raise ManagerProtocolError(f"{what} ausente ou inválido na resposta do Manager")
    return value


def valid_server_id(value: object) -> str:
    return valid_id(value, "server_id")


def check_server_id(expected: str, got: object) -> str:
    value = valid_server_id(got)
    if value != expected:
        raise ServerMismatch(f"o Manager respondeu com outro server_id ({value}); o "
                             f"cadastro é do servidor {expected}. Confira a URL do Manager")
    return value


class ChallengeSigner:
    def __init__(self, keygen: SshKeygen, key: DeviceKey) -> None:
        self.keygen = keygen
        self.key = key

    def message(self, response: Mapping[str, Any], purpose: str) -> bytes:
        try:
            return AuthMessage(
                valid_server_id(response.get("server_id")), purpose,
                str(response.get("challenge_id")), str(response.get("nonce")),
                self.key.fingerprint, parse_expires(str(response.get("expires_at"))),
            ).to_bytes()
        except AuthMessageError as exc:
            raise ManagerProtocolError(f"desafio fora do formato: {exc}") from exc

    def answer(self, response: Mapping[str, Any], purpose: str) -> str:
        return self.keygen.sign(self.key.private, self.message(response, purpose))
