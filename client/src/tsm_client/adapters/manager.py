"""Cliente HTTP do Manager com ``urllib`` da stdlib: sem dependências de terceiros.

Respostas 4xx/5xx do Manager com corpo JSON (conflito, recusa, base desatualizada) são
resultados normais e voltam como ``Response``; só falhas de rede viram exceção.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote


class ManagerUnavailable(ConnectionError):
    """Manager inacessível (rede, processo parado, timeout)."""


class ManagerProtocolError(RuntimeError):
    """Resposta fora do formato esperado."""


@dataclass(frozen=True)
class Response:
    http_status: int
    body: dict[str, Any]

    @property
    def status(self) -> str:
        return str(self.body.get("status", "ok" if self.http_status == 200 else "error"))

    @property
    def ok(self) -> bool:
        return self.http_status == 200


class ManagerClient:
    def __init__(self, url: str, token: str, *, timeout: float = 120.0) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Any = None,
                 timeout: float | None = None) -> Response:
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        except (TimeoutError, urllib.error.URLError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ManagerUnavailable(f"Manager inacessível em {self.url}: {reason}") from exc
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManagerProtocolError(f"resposta não JSON (HTTP {status})") from exc
        if not isinstance(parsed, dict):
            raise ManagerProtocolError(f"resposta inesperada (HTTP {status})")
        return Response(status, parsed)

    @staticmethod
    def _p(s: str) -> str:
        return quote(s, safe="")

    def health(self, timeout: float = 5.0) -> Response:
        return self._request("GET", "/health", timeout=timeout)

    def project(self, project_id: str, timeout: float | None = None) -> Response:
        return self._request("GET", f"/projects/{self._p(project_id)}", timeout=timeout)

    def publish(self, project_id: str, binding_id: str, body: dict[str, Any]) -> Response:
        return self._request(
            "POST", f"/projects/{self._p(project_id)}/bindings/{self._p(binding_id)}/publish",
            body)

    def revisions(self, project_id: str, limit: int = 20) -> Response:
        return self._request("GET", f"/projects/{self._p(project_id)}/revisions?limit={limit}")

    def revision(self, project_id: str, number: int) -> Response:
        return self._request("GET", f"/projects/{self._p(project_id)}/revisions/{number}")

    def rollback(self, project_id: str, body: dict[str, Any]) -> Response:
        return self._request("POST", f"/projects/{self._p(project_id)}/rollback", body)

    def audit(self, project_id: str, limit: int = 50) -> Response:
        return self._request("GET", f"/projects/{self._p(project_id)}/audit?limit={limit}")
