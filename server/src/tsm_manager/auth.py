"""Identidade de teste: token fixo → identidade da config.

O token nunca é guardado em claro: a config tem só o SHA-256, e a comparação é feita em
tempo constante contra todas as identidades. Será substituída pelo challenge-response
Ed25519 com sessões temporárias.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from tsm_manager.bindings import BindingSource
from tsm_manager.config import BindingConfig, Identity, ManagerConfig


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def authenticate(cfg: ManagerConfig, authorization: str | None) -> Identity | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    digest = token_sha256(authorization[len("Bearer "):].strip())
    found = None
    for ident in cfg.identities:  # percorre todas: tempo não depende de qual casa
        if hmac.compare_digest(digest, ident.token_sha256):
            found = ident
    return found


def can_read(identity: Identity, bindings: BindingSource) -> bool:
    if identity.is_admin:
        return True
    return identity.device is not None and bindings.for_device(identity.device) is not None


def owns_binding(identity: Identity, binding: BindingConfig) -> bool:
    return identity.device is not None and identity.device == binding.device
