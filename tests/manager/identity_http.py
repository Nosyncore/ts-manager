"""Lado do Client nos testes de integração da identidade: HTTP real e assinatura real.

Cada ``Device`` tem uma chave Ed25519 gerada pelo ``ssh-keygen`` real (assinador de teste)
e sai de um endereço de loopback próprio (``127.0.0.N``), como dispositivos distintos: o
rate limit do Manager conta por endereço do par da conexão.
"""

from __future__ import annotations

import http.client
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.sshsig_signer import SigningDevice, keygen_path

KEYGEN = keygen_path()


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: Any

    @property
    def code(self) -> str | None:
        return self.body.get("status") if isinstance(self.body, dict) else None


class Http:
    def __init__(self, port: int, source: str = "127.0.0.1") -> None:
        self.port = port
        self.source = source

    def request(self, method: str, path: str, *, token: str | None = None,
                body: Any = None) -> Response:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120,
                                          source_address=(self.source, 0))
        try:
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            data = json.dumps(body).encode() if body is not None else None
            conn.request(method, path, body=data, headers=headers)
            r = conn.getresponse()
            raw = r.read()
            payload = json.loads(raw) if raw else None
            return Response(r.status, {k.lower(): v for k, v in r.getheaders()}, payload)
        finally:
            conn.close()

    def get(self, path: str, token: str | None = None) -> Response:
        return self.request("GET", path, token=token)

    def post(self, path: str, body: Any = None, token: str | None = None) -> Response:
        return self.request("POST", path, token=token, body=body if body is not None else {})


@dataclass
class Device:
    """Um dispositivo do teste: chave real, endereço próprio e o token atual."""

    http: Http
    signer: SigningDevice
    name: str
    token: str | None = None
    device_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, port: int, home: Path, n: int, name: str) -> Device:
        return cls(Http(port, f"127.0.0.{10 + n}"), SigningDevice(KEYGEN, home), name)

    @property
    def fingerprint(self) -> str:
        return self.signer.fingerprint

    def challenge(self, purpose: str) -> dict[str, Any]:
        body = ({"purpose": "register", "public_key": self.signer.public}
                if purpose == "register" else
                {"purpose": "login", "fingerprint": self.fingerprint})
        r = self.http.post("/auth/challenge", body)
        assert r.status == 200, r
        return r.body

    def register(self, invite: str, *, display_name: str | None = None) -> Response:
        ch = self.challenge("register")
        body = {"invite": invite, "device_name": f"pc de {self.name}",
                "challenge_id": ch["challenge_id"], "signature": self.signer.answer(ch)}
        if display_name is not None:
            body["display_name"] = display_name
        r = self.http.post("/auth/register", body)
        if r.status == 201:
            self.device_id = r.body["device_id"]
        return r

    def login(self) -> Response:
        ch = self.challenge("login")
        r = self.http.post("/auth/verify", {"challenge_id": ch["challenge_id"],
                                            "signature": self.signer.answer(ch)})
        if r.status == 200:
            self.token = r.body["token"]
        return r

    def get(self, path: str) -> Response:
        return self.http.get(path, self.token)

    def post(self, path: str, body: Any = None) -> Response:
        return self.http.post(path, body, self.token)
