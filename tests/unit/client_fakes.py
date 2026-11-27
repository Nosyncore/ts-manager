"""Fakes dos unitários do Client (sem importar o Manager).

- ``FakeKeygen``: "gera" uma chave pública válida e assina de forma determinística;
- ``RecordingAcl``: registra os alvos da ACL;
- ``ScriptedTransport``: Manager falso de roteiro, por método e caminho, que registra as
  requisições (cabeçalhos e corpo).
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from tsm_common.authmsg import NAMESPACE
from tsm_common.sshkeys import parse_public_key

SERVER_ID = "5e1f0000-0000-4000-8000-00000000c0de"
DEVICE_ID = "d0000000-0000-4000-8000-000000000001"
USER_ID = "u0000000-0000-4000-8000-000000000001"
NONCE = "A" * 43
EXPIRES = "2026-11-27T12:01:00Z"
TOKEN = "tsm-s-" + "t" * 43
TOKEN2 = "tsm-s-" + "u" * 43


def fake_key(n: int, comment: str | None = None) -> str:
    raw = hashlib.sha256(f"chave-{n}".encode()).digest()
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + raw
    line = f"ssh-ed25519 {base64.b64encode(blob).decode()}"
    return f"{line} {comment}" if comment else line


def fingerprint(n: int) -> str:
    return parse_public_key(fake_key(n)).fingerprint


def fake_signature(public_key: str, message: bytes, namespace: str = NAMESPACE) -> str:
    digest = hashlib.sha256(public_key.encode() + b"\0" + namespace.encode() + b"\0"
                            + message).hexdigest()
    return f"fake-sshsig:{digest}"


class FakeKeygen:
    def __init__(self, n: int = 1) -> None:
        self.n = n
        self.generated: list[Path] = []
        self.signed: list[bytes] = []

    def generate(self, private: Path) -> str:
        self.generated.append(private)
        private.write_text("PRIVADA\n")
        private.with_name(private.name + ".pub").write_text(fake_key(self.n, "tsm") + "\n")
        return fake_key(self.n)

    def sign(self, private: Path, message: bytes, namespace: str = NAMESPACE) -> str:
        self.signed.append(message)
        return fake_signature(fake_key(self.n), message, namespace)


class RecordingAcl:
    def __init__(self) -> None:
        self.dirs: list[Path] = []
        self.files: list[Path] = []

    def restrict_dir(self, path: Path) -> None:
        self.dirs.append(Path(path))

    def restrict_file(self, path: Path) -> None:
        self.files.append(Path(path))


def challenge_body(purpose: str = "login", server_id: str = SERVER_ID) -> dict[str, Any]:
    return {"challenge_id": "c-1", "nonce": NONCE, "expires_at": EXPIRES,
            "server_id": server_id, "purpose": purpose}


def session_body(token: str = TOKEN, scope: str = "full",
                 device_id: str = DEVICE_ID) -> dict[str, Any]:
    return {"token": token, "scope": scope, "expires_at": EXPIRES, "user_id": USER_ID,
            "device_id": device_id}


class ScriptedTransport:
    """Respostas por ``(método, caminho sem query)``; a última se repete."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], deque] = defaultdict(deque)
        self.requests: list[dict[str, Any]] = []
        self.fail: Exception | None = None

    def on(self, method: str, path: str, status: int, body: Any = None,
           headers: dict[str, str] | None = None) -> ScriptedTransport:
        self.routes[(method, path)].append((status, body if body is not None else {},
                                            headers or {}))
        return self

    def login_ok(self, scope: str = "full", token: str = TOKEN) -> ScriptedTransport:
        self.on("POST", "/auth/challenge", 200, challenge_body())
        return self.on("POST", "/auth/verify", 200, session_body(token, scope))

    def __call__(self, method: str, url: str, headers: dict[str, str], data: bytes | None,
                 timeout: float):
        if self.fail:
            raise self.fail
        path = url.split("://", 1)[1].split("/", 1)[1]
        path = "/" + path
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)
        self.requests.append({"method": method, "path": path, "query": query,
                              "headers": dict(headers),
                              "body": json.loads(data) if data else None})
        queue = self.routes.get((method, path))
        if not queue:
            return 404, {}, json.dumps({"status": "not_found"}).encode()
        status, body, hdrs = queue[0] if len(queue) == 1 else queue.popleft()
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return status, hdrs, raw

    def paths(self) -> list[str]:
        return [f"{r['method']} {r['path']}" for r in self.requests]
