"""Sessão do Client no Manager: login por challenge-response e repetição controlada.

- O token fica em ``<home>/state/session.json`` (ACL só do usuário) e nunca aparece em
  saída, log ou mensagem de erro. O login é feito no primeiro uso; a expiração é descoberta
  pelo 401 ``session_expired`` (o relógio do Client não é usado).
- No máximo **uma** repetição por requisição, com o mesmo corpo:
  - 401 ``session_expired`` → novo login e repetição;
  - 403 ``pending_approval`` com sessão ``pending`` vinda do cache → novo login (a sessão
    nunca ganha privilégio no Manager) e repetição.
- 401 ``unauthorized`` → apaga o token e falha com ``IdentityRefused``, sem novo login: em
  loopback todos os Clients dividem o rate limit do Manager, e um login a cada comando de um
  dispositivo revogado gastaria as fichas de falha de todos.
- Login recusado → ``IdentityRefused`` e o marcador ``state/refused``. Com o marcador, os
  comandos falham sem tentar o login; só ``whoami`` e ``enroll`` tentam de novo.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from tsm_client.adapters.acl import Acl
from tsm_client.adapters.manager import ManagerClient, ManagerProtocolError, Response
from tsm_client.errors import RefusedError
from tsm_client.home import Home
from tsm_client.identity import ChallengeSigner, check_server_id
from tsm_common import protocol as P
from tsm_common.fsutil import atomic_write_bytes, atomic_write_json

SCOPES = ("pending", "full")
_TOKEN_RE = re.compile(r"^tsm-s-[A-Za-z0-9_-]{16,128}$")


class IdentityRefused(Exception):
    """Identidade rejeitada, revogada, expirada ou bloqueada (código de saída 6)."""


class IdentityPending(Exception):
    """Dispositivo ainda aguardando aprovação (código de saída 6)."""


class SessionError(RefusedError):
    """A sessão recém-emitida foi recusada (relógio ou TTL do Manager)."""


class ManagerRefused(RefusedError):
    """Recusa do Manager numa operação de identidade ou de administração."""

    def __init__(self, resp: Response, what: str) -> None:
        super().__init__(f"{what}: {resp.message} ({resp.status}, HTTP {resp.http_status})")
        self.status = resp.status
        self.http_status = resp.http_status
        self.body = resp.body


REFUSED_MESSAGE = ("identidade recusada pelo Manager (dispositivo rejeitado, revogado ou "
                   "expirado, ou usuário bloqueado). Fale com o admin; 'tsm whoami' tenta "
                   "de novo")


def refusal(resp: Response, what: str) -> Exception:
    """Exceção para uma resposta de recusa (fora das tratadas pela sessão)."""
    if resp.http_status == 401:
        return IdentityRefused(REFUSED_MESSAGE)
    if resp.status == P.PENDING_APPROVAL:
        return IdentityPending("dispositivo aguardando aprovação do admin")
    return ManagerRefused(resp, what)


class SessionStore:
    def __init__(self, home: Home, acl: Acl,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.home = home
        self.acl = acl
        self.now = now

    def load(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self.home.session_file.read_text("utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            self.clear()
            return None
        if (not isinstance(data, dict) or not _TOKEN_RE.match(str(data.get("token", "")))
                or data.get("scope") not in SCOPES):
            self.clear()
            return None
        return data

    def save(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.home.session_file, data)
        self.acl.restrict_file(self.home.session_file)

    def clear(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.home.session_file.unlink()

    def refused(self) -> str | None:
        try:
            return self.home.refused_file.read_text("utf-8").strip() or "recusado"
        except FileNotFoundError:
            return None

    def mark_refused(self, reason: str) -> None:
        stamp = self.now().isoformat(timespec="seconds")
        atomic_write_bytes(self.home.refused_file, f"{stamp} {reason}\n".encode())

    def clear_refused(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.home.refused_file.unlink()


class SessionAuth:
    def __init__(self, store: SessionStore, signer: ChallengeSigner, *, server_id: str,
                 device_id: str | None, honor_refused: bool = True) -> None:
        # device_id None: só na recuperação do cadastro, que descobre o id pelo login
        self.store = store
        self.signer = signer
        self.server_id = server_id
        self.device_id = device_id
        self.honor_refused = honor_refused
        self._session: dict[str, Any] | None = None
        self._from_cache = False

    # ------------------------------------------------------------ estado

    def current(self) -> dict[str, Any] | None:
        if self._session is None:
            cached = self.store.load()
            if cached and cached.get("server_id") == self.server_id \
                    and cached.get("device_id") == self.device_id:
                self._session, self._from_cache = cached, True
        return self._session

    @property
    def scope(self) -> str | None:
        s = self.current()
        return s["scope"] if s else None

    def drop(self) -> None:
        self.store.clear()
        self._session, self._from_cache = None, False

    # ------------------------------------------------------------ login

    def login(self, client: ManagerClient) -> dict[str, Any]:
        if self.honor_refused and self.store.refused():
            raise IdentityRefused(REFUSED_MESSAGE)
        fingerprint = self.signer.key.fingerprint
        ch = client.challenge({"purpose": "login", "fingerprint": fingerprint})
        if not ch.ok:
            raise refusal(ch, "desafio de login")
        check_server_id(self.server_id, ch.body.get("server_id"))
        signature = self.signer.answer(ch.body, "login")
        r = client.verify({"challenge_id": ch.body.get("challenge_id"),
                           "signature": signature})
        if r.http_status == 401:
            self.drop()
            self.store.mark_refused("login recusado")
            raise IdentityRefused(REFUSED_MESSAGE)
        if not r.ok:
            raise refusal(r, "login")
        token, scope = r.body.get("token"), r.body.get("scope")
        if not isinstance(token, str) or not _TOKEN_RE.match(token) or scope not in SCOPES:
            raise ManagerProtocolError("sessão fora do formato na resposta do login")
        if self.device_id is None and isinstance(r.body.get("device_id"), str):
            self.device_id = r.body["device_id"]
        if r.body.get("device_id") != self.device_id:
            raise ManagerProtocolError("o login devolveu outro dispositivo")
        session = {"token": token, "scope": scope, "expires_at": r.body.get("expires_at"),
                   "server_id": self.server_id, "device_id": self.device_id}
        self.store.save(session)
        self.store.clear_refused()
        self._session, self._from_cache = session, False
        return session

    def ensure_full(self, client: ManagerClient) -> None:
        """Garante sessão ``full``: refaz o login se a do cache for ``pending``."""
        s = self.current() or self.login(client)
        if s["scope"] == "pending":
            self.drop()
            s = self.login(client)
        if s["scope"] != "full":
            raise IdentityPending("dispositivo aguardando aprovação do admin")

    # ------------------------------------------------------------ protocolo do ManagerClient

    def header(self, client: ManagerClient) -> str | None:
        s = self.current() or self.login(client)
        return f"Bearer {s['token']}"

    def retry(self, client: ManagerClient, resp: Response) -> bool:
        if resp.http_status == 401 and resp.status == P.SESSION_EXPIRED:
            self.drop()
            self.login(client)
            return True
        if (resp.http_status == 403 and resp.status == P.PENDING_APPROVAL and self._from_cache
                and self.scope == "pending"):
            self.drop()
            self.login(client)
            return True
        return False

    def check(self, client: ManagerClient, resp: Response) -> None:
        if resp.http_status == 401:
            self.drop()
            if resp.status == P.SESSION_EXPIRED:
                raise SessionError("a sessão expirou logo após o login; repita o comando")
            raise IdentityRefused(REFUSED_MESSAGE)
        if resp.http_status == 403 and resp.status == P.PENDING_APPROVAL:
            raise IdentityPending("dispositivo aguardando aprovação do admin")
