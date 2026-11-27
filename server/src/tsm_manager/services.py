"""Montagem do Manager a partir da config: um banco e um ``ProjectService`` por projeto.

Na config ``version: 2`` o Manager ganha a identidade real (``IdentityServices``): domínio
de identidade sobre o banco, verificador SSHSIG, provisionador do modo configurado e
``ProvisioningService``; os vínculos dos projetos vêm do banco. Na ``version: 1`` (identidade
de teste, será removida) nada disso existe e os vínculos vêm da config.

Não verifica o esquema: quem abre o Manager (``serve``, ``init-project``, ``recover``,
``verify`` e os comandos de identidade) chama ``db.require_current`` antes.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from tsm_manager.adapters.sshsig import SshKeygenVerifier, work_dir_for
from tsm_manager.bindings import DbBindings
from tsm_manager.config import ManagerConfig
from tsm_manager.db import Repository, server_id, utcnow
from tsm_manager.db.connection import Database
from tsm_manager.faults import Faults
from tsm_manager.identity.base import Clock, IdentityContext, RandomSource, SignatureVerifier
from tsm_manager.project import ProjectService, open_project
from tsm_manager.provisioning.provisioner import (
    AccountPolicy,
    LocalProvisioner,
    Provisioner,
    SudoProvisioner,
)
from tsm_manager.provisioning.service import ProvisioningService


@dataclass
class IdentityServices:
    ctx: IdentityContext
    provisioner: Provisioner
    provisioning: ProvisioningService
    policy: AccountPolicy
    transport: str                          # "ssh" (helper sob sudo) ou "local"
    host_keys: tuple[str, ...] = field(default=())  # carregadas pelo serve

    @property
    def repo(self) -> Repository:
        return self.ctx.repo


def account_policy(cfg: ManagerConfig) -> AccountPolicy:
    assert cfg.provisioner is not None and cfg.workspace_group and cfg.shared_group
    devices = cfg.ssh.devices_group if cfg.ssh else AccountPolicy.devices_group
    return AccountPolicy(devices_group=devices, shared_group=cfg.shared_group,
                         workspace_group=cfg.workspace_group,
                         manager_group=cfg.provisioner.manager_group)


def build_provisioner(cfg: ManagerConfig, policy: AccountPolicy) -> Provisioner:
    assert cfg.provisioner is not None
    if cfg.provisioner.mode == "sudo":
        assert cfg.provisioner.helper is not None
        return SudoProvisioner(cfg.provisioner.helper, sudo=cfg.provisioner.sudo,
                               timeout_s=cfg.provisioner.timeout_s)
    return LocalProvisioner(cfg.root, policy)


def build_identity(cfg: ManagerConfig, db: Database, *,
                   verifier: SignatureVerifier | None = None,
                   provisioner: Provisioner | None = None, clock: Clock = utcnow,
                   random: RandomSource = secrets.token_bytes) -> IdentityServices:
    assert cfg.is_v2 and cfg.auth is not None and cfg.provisioner is not None
    if verifier is None:
        verifier = SshKeygenVerifier(cfg.auth.ssh_keygen, work_dir_for(cfg.database),
                                     timeout_s=cfg.auth.sshsig_timeout_s)
    ctx = IdentityContext(repo=Repository(db), server_id=server_id(db), verifier=verifier,
                          projects=frozenset(cfg.projects), settings=cfg.auth.settings(),
                          clock=clock, random=random)
    policy = account_policy(cfg)
    provisioner = provisioner or build_provisioner(cfg, policy)
    transport = "ssh" if cfg.provisioner.mode == "sudo" else "local"
    return IdentityServices(ctx, provisioner, ProvisioningService(ctx, provisioner, policy),
                            policy, transport)


class Manager:
    def __init__(self, cfg: ManagerConfig, *, db: Database | None = None,
                 faults: Faults | None = None, git_executable: str = "git",
                 verifier: SignatureVerifier | None = None,
                 provisioner: Provisioner | None = None, clock: Clock = utcnow,
                 random: RandomSource = secrets.token_bytes) -> None:
        self.cfg = cfg
        self.db = db or Database(cfg.database)
        faults = faults or Faults.from_env(cfg.test_faults)
        self.identity: IdentityServices | None = None
        if cfg.is_v2:
            self.identity = build_identity(cfg, self.db, verifier=verifier,
                                           provisioner=provisioner, clock=clock,
                                           random=random)
        self.projects: dict[str, ProjectService] = {
            pid: open_project(cfg.root, p, self.db, shared_group=cfg.shared_group,
                              git_executable=git_executable, faults=faults,
                              bindings=DbBindings(self.identity.repo, pid)
                              if self.identity else None)
            for pid, p in cfg.projects.items()
        }

    @property
    def server_id(self) -> str:
        return server_id(self.db)

    def recover_all(self) -> list[str]:
        notes = []
        for pid, svc in self.projects.items():
            if svc.initialized:
                notes += [f"{pid}: {n}" for n in svc.recover()]
        return notes

    def close(self) -> None:
        self.db.close()
