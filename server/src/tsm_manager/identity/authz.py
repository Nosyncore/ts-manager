"""Autorização das rotas da API: quem pode o quê, por escopo de sessão e role.

``check`` é pura: recebe o ``Principal`` já reconferido (``sessions.authenticate``) e os
fatos sobre o projeto, e devolve ``None`` (permitido) ou o status da recusa.

- sem sessão → ``unauthorized``;
- sessão ``pending`` → só ``me`` e ``logout``; o resto, ``pending_approval``;
- leitura do projeto: membro ou admin; quem não é membro recebe ``not_found`` (o projeto
  não é revelado);
- ``connection_config``: só com vínculo do próprio dispositivo no projeto (também admin:
  sem vínculo não há conta SSH);
- publicar: só o dono do vínculo; quem enxerga o projeto e não é dono recebe ``forbidden``;
- rollback, auditoria e ``/admin/*``: só admin.

Bootstrap, promoção, rebaixamento e ``purge`` não são operações da API: só a CLI do
servidor (ator local em ``accounts``/``invites``).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tsm_common import protocol as P
from tsm_manager.identity.base import IdentityContext, IdentityError, Principal


class Operation(StrEnum):
    ME = "me"
    LOGOUT = "logout"
    CONNECTION_CONFIG = "connection_config"
    PROJECT_READ = "project_read"
    PUBLISH = "publish"
    ADMIN = "admin"


_PENDING_ALLOWED = {Operation.ME, Operation.LOGOUT}
_MESSAGES = {
    P.UNAUTHORIZED: "não autenticado",
    P.PENDING_APPROVAL: "dispositivo aguardando aprovação",
    P.NOT_FOUND: "projeto não encontrado",
    P.FORBIDDEN: "operação não permitida",
}


def check(principal: Principal | None, op: Operation, *, member: bool = False,
          owns_binding: bool = False) -> str | None:
    if principal is None:
        return P.UNAUTHORIZED
    if not principal.is_full:
        return None if op in _PENDING_ALLOWED else P.PENDING_APPROVAL
    if op in _PENDING_ALLOWED:
        return None
    sees_project = member or principal.is_admin
    if op is Operation.CONNECTION_CONFIG:
        return None if owns_binding else P.NOT_FOUND
    if op is Operation.PROJECT_READ:
        return None if sees_project else P.NOT_FOUND
    if op is Operation.PUBLISH:
        if owns_binding:
            return None
        return P.FORBIDDEN if sees_project else P.NOT_FOUND
    return None if principal.is_admin else P.FORBIDDEN


def require(principal: Principal | None, op: Operation, *, member: bool = False,
            owns_binding: bool = False) -> None:
    code = check(principal, op, member=member, owns_binding=owns_binding)
    if code is not None:
        raise IdentityError(code, _MESSAGES[code])


@dataclass(frozen=True)
class Access:
    member: bool              # usuário com vínculo de dispositivo ativo no projeto
    binding_id: str | None    # vínculo do dispositivo da sessão no projeto


def project_access(ctx: IdentityContext, principal: Principal | None,
                   project_id: str) -> Access:
    if principal is None:
        return Access(False, None)
    with ctx.repo.read() as tx:
        member = tx.user_has_active_binding(principal.user_id, project_id)
        binding = tx.binding_for(project_id, principal.device_id)
        device = tx.get_device(principal.device_id)
    active = device is not None and device.status == "active"
    return Access(member, binding.id if binding and active else None)


def owns(principal: Principal | None, binding_device: str) -> bool:
    return principal is not None and principal.device_id == binding_device
