"""Identidades reais para os testes de integração, criadas pelos serviços de domínio.

Faz o papel do operador da CLI do servidor sobre o banco e a raiz de um Manager: convites
(``invites.create``/``create_bootstrap``), cadastro com prova de posse
(``challenges.issue_register`` → assinatura pelo ``ssh-keygen`` real → ``accounts.register``
com o verificador real) e aprovação com fingerprint (``ProvisioningService.approve``, com o
provisionador do Manager: ``LocalProvisioner`` nos testes locais). Não existe atalho de
autenticação: o dispositivo criado é o mesmo que um ``tsm enroll`` aprovado deixaria no banco.

Na colaboração o lado do Client é o próprio ``tsm``; daqui saem só ``invite``,
``bootstrap_invite`` e ``approve``. Nos testes do ``ProjectService``, ``device`` cria o
dispositivo inteiro e devolve o vínculo e o ``Requester``.
"""

from __future__ import annotations

import dataclasses
import itertools
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from tests.sshsig_signer import SigningDevice, keygen_path
from tsm_manager.bindings import DbBindings
from tsm_manager.config import BindingConfig
from tsm_manager.identity import accounts, challenges, invites, sessions
from tsm_manager.identity.base import Actor
from tsm_manager.project import Requester
from tsm_manager.services import IdentityServices

OPERATOR = Actor.operator()
KEYGEN = keygen_path()


@dataclass
class SeedDevice:
    name: str
    user_id: str
    device_id: str
    signer: SigningDevice
    binding: BindingConfig
    requester: Requester

    @property
    def fingerprint(self) -> str:
        return self.signer.fingerprint

    @property
    def account(self) -> str:
        return self.binding.workspace


class Seed:
    def __init__(self, ids: IdentityServices, keys: Path) -> None:
        self.ids = ids
        self.keys = keys
        self._n = itertools.count(1)

    @property
    def ctx(self):
        return self.ids.ctx

    def shifted(self, seconds: float) -> Seed:
        """A mesma semente com o relógio deslocado (negativo = passado).

        Serve para gravar registros que o Manager em execução já vê vencidos (um desafio
        emitido há mais que o TTL), sem esperar o tempo passar.
        """
        base = self.ctx.clock
        ctx = dataclasses.replace(self.ctx, clock=lambda: base() + timedelta(seconds=seconds))
        return Seed(dataclasses.replace(self.ids, ctx=ctx), self.keys)

    def bootstrap_invite(self, project: str = "demo") -> str:
        return invites.create_bootstrap(self.ctx, OPERATOR, project_id=project).code

    def invite(self, project: str = "demo", *, role: str = "developer",
               for_user: str | None = None) -> str:
        kind = invites.NEW_DEVICE if for_user else invites.NEW_USER
        return invites.create(self.ctx, OPERATOR, project_id=project, kind=kind, role=role,
                              for_user=for_user).code

    def approve(self, device_id: str, fingerprint: str) -> BindingConfig:
        b = self.ids.provisioning.approve(OPERATOR, device_id, fingerprint)
        return BindingConfig(b.id, b.device_id, b.workspace)

    def register(self, name: str, code: str, *, display_name: str | None = None
                 ) -> tuple[SigningDevice, accounts.Registration]:
        signer = SigningDevice(KEYGEN, self.keys / f"{next(self._n)}-{name}")
        ch = challenges.issue_register(self.ctx, signer.public)
        reg = accounts.register(self.ctx, invite_code=code, display_name=display_name,
                                device_name=f"pc de {name}", challenge_id=ch.challenge_id,
                                signature=signer.sign(ch.message()))
        return signer, reg

    def device(self, name: str, *, project: str = "demo", admin: bool = False) -> SeedDevice:
        """Usuário novo com um dispositivo ativo e vinculado ao projeto."""
        code = self.bootstrap_invite(project) if admin else self.invite(project)
        signer, reg = self.register(name, code, display_name=name)
        binding = self.approve(reg.device_id, signer.fingerprint)
        return SeedDevice(name, reg.user_id, reg.device_id, signer, binding,
                          Requester(name, reg.user_id, reg.device_id, admin))

    def login(self, dev: SeedDevice) -> str:
        """Token de sessão pelo challenge-response do domínio."""
        ch = challenges.issue_login(self.ctx, dev.fingerprint)
        return sessions.login(self.ctx, ch.challenge_id, dev.signer.sign(ch.message())).token

    def bindings(self, project: str = "demo") -> DbBindings:
        return DbBindings(self.ctx.repo, project)
