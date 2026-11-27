"""``tsm admin``: convites, solicitações, dispositivos e usuários (rotas ``/admin``).

Fino sobre a API: a autorização é do Manager (sessão ``full`` de admin). Uma recusa vira
``ManagerRefused`` (ou ``IdentityRefused``/``IdentityPending`` pela sessão). Uma revogação
ou bloqueio com o helper falhando responde 200 com ``ssh: pending``: a mudança já vale na
API, e o ``recover`` do Manager conclui o lado SSH.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from tsm_client.adapters.manager import ManagerClient
from tsm_client.config import ConfigError
from tsm_client.login import refusal

_DURATION_RE = re.compile(r"^(\d+)([smhd]?)$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int:
    """``30m``, ``24h``, ``7d`` ou segundos → segundos."""
    m = _DURATION_RE.match(text.strip().lower()) if isinstance(text, str) else None
    if not m or int(m.group(1)) <= 0:
        raise ConfigError(f"duração inválida: {text!r} (use 30m, 24h, 7d ou segundos)")
    return int(m.group(1)) * _UNITS[m.group(2)]


def _p(value: str) -> str:
    return quote(value, safe="")


class AdminService:
    def __init__(self, client: ManagerClient) -> None:
        self.client = client

    def _call(self, method: str, path: str, what: str, body: Any = None) -> dict[str, Any]:
        r = self.client.admin(method, path, body)
        if not r.ok:
            raise refusal(r, what)
        return r.body

    # ------------------------------------------------------------ convites

    def invite_create(self, project: str, *, role: str = "developer",
                      for_user: str | None = None, ttl_s: int | None = None
                      ) -> dict[str, Any]:
        body: dict[str, Any] = {"project": project, "role": role,
                                "kind": "new_device" if for_user else "new_user"}
        if for_user:
            body["user_id"] = for_user
        if ttl_s is not None:
            body["ttl_s"] = ttl_s
        return self._call("POST", "invites", "criar convite", body)

    def invite_list(self) -> list[dict[str, Any]]:
        return self._call("GET", "invites", "listar convites")["invites"]

    def invite_revoke(self, invite_id: str) -> dict[str, Any]:
        return self._call("POST", f"invites/{_p(invite_id)}/revoke", "revogar convite")

    # ------------------------------------------------------------ solicitações

    def requests_list(self) -> list[dict[str, Any]]:
        return self._call("GET", "requests", "listar solicitações")["requests"]

    def approve(self, device_id: str, fingerprint: str) -> dict[str, Any]:
        return self._call("POST", f"requests/{_p(device_id)}/approve", "aprovar",
                          {"fingerprint": fingerprint})

    def reject(self, device_id: str) -> dict[str, Any]:
        return self._call("POST", f"requests/{_p(device_id)}/reject", "rejeitar")

    # ------------------------------------------------------------ dispositivos e usuários

    def devices_list(self) -> list[dict[str, Any]]:
        return self._call("GET", "devices", "listar dispositivos")["devices"]

    def device_revoke(self, device_id: str) -> dict[str, Any]:
        return self._call("POST", f"devices/{_p(device_id)}/revoke", "revogar dispositivo")

    def users_list(self) -> list[dict[str, Any]]:
        return self._call("GET", "users", "listar usuários")["users"]

    def user_block(self, user_id: str) -> dict[str, Any]:
        return self._call("POST", f"users/{_p(user_id)}/block", "bloquear usuário")

    def user_unblock(self, user_id: str) -> dict[str, Any]:
        return self._call("POST", f"users/{_p(user_id)}/unblock", "desbloquear usuário")


def ssh_pending(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Resultados de provisionamento que ficaram pendentes numa revogação ou bloqueio."""
    items = result.get("devices") if "devices" in result else [result]
    return [d for d in items or [] if isinstance(d, dict) and d.get("ssh") == "pending"]
