"""Cliente HTTP do Manager com ``urllib`` da stdlib: sem dependências de terceiros.

Respostas 4xx/5xx do Manager com corpo JSON (conflito, recusa, base desatualizada) são
resultados normais e voltam como ``Response``; só falhas de rede viram exceção.

- URL: ``http://`` só para host de loopback; ``https://`` com o repositório de CAs do
  sistema ou um arquivo de CA. Sem usuário, query nem fragmento na URL.
- Sem proxy do ambiente e sem seguir redirecionamentos: o ``urllib`` repassaria o
  ``Authorization`` ao destino de um redirecionamento.
- Autenticação plugável (``auth``): a sessão por challenge-response (``tsm_client.login``),
  que pode pedir uma repetição da requisição. A repetição reenvia exatamente o mesmo corpo.
  Sem ``auth``, só as rotas públicas (desafio, cadastro, verificação) servem.
- 429 vira ``RateLimited`` (repita depois).
"""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit


class ManagerUnavailable(ConnectionError):
    """Manager inacessível (rede, processo parado, timeout)."""


class RateLimited(ManagerUnavailable):
    """O Manager limitou as requisições (429): repita depois."""

    def __init__(self, retry_after: int | None) -> None:
        wait = f" em {retry_after} s" if retry_after else " mais tarde"
        super().__init__(f"Manager ocupado com tentativas de autenticação: repita{wait}")
        self.retry_after = retry_after


class ManagerProtocolError(RuntimeError):
    """Resposta fora do formato esperado."""


class ManagerUrlError(ValueError):
    """URL do Manager inválida ou insegura."""


@dataclass(frozen=True)
class Response:
    http_status: int
    body: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def status(self) -> str:
        return str(self.body.get("status", "ok" if self.http_status < 300 else "error"))

    @property
    def ok(self) -> bool:
        return 200 <= self.http_status < 300

    @property
    def message(self) -> str:
        return str(self.body.get("message") or self.status)


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url: str) -> str:
    """Valida e normaliza a URL do Manager (sem barra final)."""
    if not isinstance(url, str) or not url:
        raise ManagerUrlError("URL do Manager vazia")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ManagerUrlError(f"URL do Manager deve começar com http:// ou https://: {url}")
    host = parts.hostname
    if not host:
        raise ManagerUrlError(f"URL do Manager sem host: {url}")
    if parts.username is not None or parts.password is not None or parts.query \
            or parts.fragment:
        raise ManagerUrlError("URL do Manager não pode ter usuário, senha, query ou fragmento")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ManagerUrlError(f"porta inválida na URL do Manager: {url}") from exc
    if parts.scheme == "http" and not _is_loopback(host):
        raise ManagerUrlError(f"http:// só é aceito para o próprio computador (loopback); "
                              f"use https:// para {host}")
    return url.rstrip("/")


# ---------------------------------------------------------------- transporte

Transport = Callable[[str, str, dict[str, str], bytes | None, float],
                     tuple[int, dict[str, str], bytes]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    def __init__(self, *, ca_file: Path | None = None) -> None:
        handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)

    def __call__(self, method: str, url: str, headers: dict[str, str], data: bytes | None,
                 timeout: float) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()) if exc.headers else {}, exc.read()


# ---------------------------------------------------------------- autenticação


class Auth(Protocol):
    def header(self, client: ManagerClient) -> str | None: ...

    def retry(self, client: ManagerClient, resp: Response) -> bool: ...

    def check(self, client: ManagerClient, resp: Response) -> None: ...


# ---------------------------------------------------------------- cliente


class ManagerClient:
    def __init__(self, url: str, auth: Auth | None = None, *, timeout: float = 120.0,
                 transport: Transport | None = None, ca_file: Path | None = None) -> None:
        if isinstance(auth, str):
            raise TypeError("auth: use a sessão do dispositivo, não um token fixo")
        self.url = check_url(url)
        self.auth: Auth | None = auth
        self.timeout = timeout
        self.transport: Transport = transport or UrllibTransport(ca_file=ca_file)

    # ------------------------------------------------------------ base

    def _send(self, method: str, path: str, data: bytes | None, timeout: float | None,
              authorization: str | None) -> Response:
        headers = {"Accept": "application/json"}
        if authorization:
            headers["Authorization"] = authorization
        if data is not None:
            headers["Content-Type"] = "application/json"
        try:
            status, resp_headers, raw = self.transport(method, self.url + path, headers, data,
                                                       timeout or self.timeout)
        except (TimeoutError, urllib.error.URLError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ManagerUnavailable(f"Manager inacessível em {self.url}: {reason}") from exc
        if 300 <= status < 400:
            raise ManagerProtocolError(f"o Manager respondeu com redirecionamento (HTTP "
                                       f"{status}), que não é seguido")
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManagerProtocolError(f"resposta não JSON (HTTP {status})") from exc
        if not isinstance(parsed, dict):
            raise ManagerProtocolError(f"resposta inesperada (HTTP {status})")
        resp = Response(status, parsed, {k.lower(): v for k, v in resp_headers.items()})
        if status == 429:
            retry_after = resp.headers.get("retry-after", "")
            raise RateLimited(int(retry_after) if retry_after.isdigit() else None)
        return resp

    def _request(self, method: str, path: str, body: Any = None,
                 timeout: float | None = None, *, auth: bool = True) -> Response:
        data = None if body is None else json.dumps(body).encode("utf-8")
        authn = self.auth if auth else None
        resp = self._send(method, path, data, timeout,
                          authn.header(self) if authn else None)
        if authn is not None and not resp.ok and authn.retry(self, resp):
            resp = self._send(method, path, data, timeout, authn.header(self))
        if authn is not None:
            authn.check(self, resp)
        return resp

    @staticmethod
    def _p(s: str) -> str:
        return quote(s, safe="")

    # ------------------------------------------------------------ projeto

    def health(self, timeout: float = 5.0) -> Response:
        return self._request("GET", "/health", timeout=timeout, auth=False)

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

    # ------------------------------------------------------------ identidade

    def challenge(self, body: dict[str, Any]) -> Response:
        return self._request("POST", "/auth/challenge", body, timeout=30, auth=False)

    def register(self, body: dict[str, Any]) -> Response:
        return self._request("POST", "/auth/register", body, timeout=30, auth=False)

    def verify(self, body: dict[str, Any]) -> Response:
        return self._request("POST", "/auth/verify", body, timeout=30, auth=False)

    def logout(self, authorization: str) -> Response:
        data = json.dumps({}).encode()
        return self._send("POST", "/auth/logout", data, 30, authorization)

    def me(self) -> Response:
        return self._request("GET", "/me", timeout=30)

    def connection_config(self, project_id: str) -> Response:
        return self._request("GET", f"/connection/config?project={self._p(project_id)}",
                             timeout=30)

    def admin(self, method: str, path: str, body: Any = None) -> Response:
        return self._request(method, f"/admin/{path}", body, timeout=120)
