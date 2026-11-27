"""Contratos compartilhados entre Client e Manager: ``revision.json`` e resultados da API."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from tsm_common.manifest import tree_digest

RESERVED_DIR = ".tsm"
REVISION_FILE = f"{RESERVED_DIR}/revision.json"
REVISION_FORMAT = 1

# status devolvidos pela publicação e pelo rollback
PUBLISHED = "published"
NO_CHANGE = "no_change"
CONFLICT = "conflict"
STALE_BASE = "stale_base"
WORKSPACE_MISMATCH = "workspace_mismatch"
RULES_MISMATCH = "rules_mismatch"
REJECTED = "rejected"
IDEMPOTENCY_MISMATCH = "idempotency_mismatch"
FORBIDDEN = "forbidden"
UNAUTHORIZED = "unauthorized"
NOT_FOUND = "not_found"
BUSY = "busy"

# identidade e acessos: as mensagens nunca dizem se um convite, fingerprint ou usuário existe
SESSION_EXPIRED = "session_expired"
PENDING_APPROVAL = "pending_approval"
RATE_LIMITED = "rate_limited"
INVALID_INVITE = "invalid_invite"
INVALID_REQUEST = "invalid_request"
INVALID_STATE = "invalid_state"
FINGERPRINT_MISMATCH = "fingerprint_mismatch"
KEY_IN_USE = "key_in_use"
LAST_ADMIN = "last_admin"
PROVISIONING_FAILED = "provisioning_failed"

HTTP_STATUS = {
    SESSION_EXPIRED: 401,
    PENDING_APPROVAL: 403,
    RATE_LIMITED: 429,
    INVALID_INVITE: 422,
    INVALID_REQUEST: 422,
    INVALID_STATE: 409,
    FINGERPRINT_MISMATCH: 409,
    KEY_IN_USE: 409,
    LAST_ADMIN: 409,
    PROVISIONING_FAILED: 502,
    PUBLISHED: 200,
    NO_CHANGE: 200,
    CONFLICT: 409,
    STALE_BASE: 409,
    WORKSPACE_MISMATCH: 409,
    RULES_MISMATCH: 409,
    REJECTED: 422,
    IDEMPOTENCY_MISMATCH: 422,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    BUSY: 503,
}

CONFLICT_KINDS = ("content", "binary", "delete_modify", "add_add", "other")

OP_PUT = "put"
OP_DELETE = "delete"


class RevisionFormatError(ValueError):
    """``revision.json`` ausente, ilegível ou fora do formato."""


@dataclass(frozen=True)
class RevisionInfo:
    project_id: str
    revision: int
    commit: str
    files: dict[str, str]  # caminho → sha256

    @property
    def tree_digest(self) -> str:
        return tree_digest(self.files)

    def to_json(self) -> str:
        data = {
            "format": REVISION_FORMAT,
            "project_id": self.project_id,
            "revision": self.revision,
            "commit": self.commit,
            "tree_digest": self.tree_digest,
            "files": dict(sorted(self.files.items())),
        }
        return json.dumps(data, indent=1, ensure_ascii=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> RevisionInfo:
        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RevisionFormatError(f"JSON inválido: {exc}") from exc
        if not isinstance(data, dict) or data.get("format") != REVISION_FORMAT:
            raise RevisionFormatError("formato não suportado")
        try:
            info = cls(
                project_id=str(data["project_id"]),
                revision=int(data["revision"]),
                commit=str(data["commit"]),
                files={str(k): str(v) for k, v in dict(data["files"]).items()},
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RevisionFormatError(f"campo ausente ou inválido: {exc}") from exc
        if data.get("tree_digest") != info.tree_digest:
            raise RevisionFormatError("tree_digest não confere com files")
        return info
