"""Chave pública OpenSSH de dispositivo: parse estrito e fingerprint.

Só ``ssh-ed25519`` é aceita. A linha não pode ter opções (``restrict``, ``command=…``),
mais de uma linha nem caracteres de controle; o blob decodificado precisa ter exatamente o
tamanho de uma chave Ed25519 e declarar o mesmo tipo da linha. O fingerprint é o do
``ssh-keygen -l`` (``SHA256:`` + base64 sem padding do SHA-256 do blob), calculado aqui e
nunca aceito do outro lado.

Usado pelo Manager (cadastro, desafios) e pelo Client (fingerprint mostrado ao dev).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
import unicodedata
from dataclasses import dataclass

KEY_TYPE = "ssh-ed25519"
ED25519_KEY_SIZE = 32
ED25519_BLOB_SIZE = 4 + len(KEY_TYPE) + 4 + ED25519_KEY_SIZE  # 51
MAX_LINE_CHARS = 1024

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


class PublicKeyError(ValueError):
    """Chave pública recusada."""


@dataclass(frozen=True)
class PublicKey:
    openssh: str          # forma normalizada: "ssh-ed25519 <base64>"
    blob: bytes
    fingerprint: str
    comment: str | None = None


def fingerprint_of_blob(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def is_fingerprint(value: object) -> bool:
    return isinstance(value, str) and bool(_FINGERPRINT_RE.match(value))


def _has_control(text: str) -> bool:
    return any(unicodedata.category(c) == "Cc" for c in text)


def _read_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise PublicKeyError("blob da chave truncado")
    (size,) = struct.unpack_from(">I", blob, offset)
    start = offset + 4
    if start + size > len(blob):
        raise PublicKeyError("blob da chave truncado")
    return blob[start:start + size], start + size


def _decode_blob(text: str) -> bytes:
    if not _B64_RE.match(text) or len(text) % 4:
        raise PublicKeyError("base64 da chave inválido")
    try:
        blob = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PublicKeyError("base64 da chave inválido") from exc
    if base64.b64encode(blob).decode("ascii") != text:
        raise PublicKeyError("base64 da chave não canônico")
    return blob


def _check_blob(blob: bytes) -> None:
    if len(blob) != ED25519_BLOB_SIZE:
        raise PublicKeyError(f"blob da chave com {len(blob)} bytes "
                             f"(esperado {ED25519_BLOB_SIZE})")
    kind, offset = _read_string(blob, 0)
    if kind != KEY_TYPE.encode("ascii"):
        raise PublicKeyError("tipo declarado no blob difere de ssh-ed25519")
    key, offset = _read_string(blob, offset)
    if len(key) != ED25519_KEY_SIZE or offset != len(blob):
        raise PublicKeyError("chave Ed25519 com tamanho inválido")


def parse_public_key(text: str) -> PublicKey:
    """Uma linha ``ssh-ed25519 <base64> [comentário]`` → ``PublicKey`` normalizada."""
    if not isinstance(text, str):
        raise PublicKeyError("chave pública deve ser texto")
    if len(text) > MAX_LINE_CHARS:
        raise PublicKeyError("chave pública longa demais")
    line = text.strip(" \t")
    for ending in ("\r\n", "\n"):
        if line.endswith(ending):
            line = line[: -len(ending)]
            break
    if _has_control(line) or " " in line or " " in line:
        raise PublicKeyError("chave pública com caracteres de controle ou várias linhas")
    parts = line.strip(" ").split(" ", 2)
    if not parts[0]:
        raise PublicKeyError("chave pública vazia")
    if parts[0] != KEY_TYPE:
        raise PublicKeyError(f"só chaves {KEY_TYPE} são aceitas (sem opções antes do tipo)")
    if len(parts) < 2 or not parts[1]:
        raise PublicKeyError("chave pública sem o blob")
    blob = _decode_blob(parts[1])
    _check_blob(blob)
    comment = parts[2].strip(" ") if len(parts) == 3 else None
    openssh = f"{KEY_TYPE} {parts[1]}"
    return PublicKey(openssh, blob, fingerprint_of_blob(blob), comment or None)
