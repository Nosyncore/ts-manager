"""Execução das operações de provisionamento registradas pelo domínio de identidade.

Ordem (design §5):

- aprovação: ``begin_approval`` → helper ``create-device`` → ``inspect-device`` confere →
  ``complete_approval``. O estado ``active`` só é gravado depois da conta conferida. Se a
  criação ou a conferência falhar, a aprovação volta a ``pending`` e a conta é desativada
  na hora; se nem isso der certo, uma ``disable`` fica agendada para o ``recover``. Um
  dispositivo fora de ``active`` nunca fica com SSH;
- revogação, bloqueio, desbloqueio e expurgo: o domínio muda o banco primeiro (API recusa
  já na requisição seguinte) e grava a operação; o helper executa e o ``inspect`` confere.
  Uma falha mantém a operação ``pending`` com o erro, e o ``recover`` repete.

Antes de executar, o estado é reconferido: ``create`` só com o dispositivo em
``provisioning`` e o usuário ativo; ``enable`` só com dispositivo e usuário ativos. Assim,
uma repetição atrasada nunca reabre o SSH de um dispositivo revogado ou de um usuário
bloqueado de novo. Todos os verbos do helper são idempotentes.
"""

from __future__ import annotations

from dataclasses import dataclass

from tsm_common import protocol as P
from tsm_manager.db.repository import Binding, Device, ProvisioningOp, User
from tsm_manager.identity import accounts
from tsm_manager.identity.base import Actor, IdentityContext, IdentityError
from tsm_manager.provisioning.provisioner import (
    GATE_MODE,
    HOME_MODE,
    TREE_MODE,
    AccountPolicy,
    DirInfo,
    Inspection,
    Provisioner,
    ProvisionError,
)

STATE_CHANGED = "estado mudou"


@dataclass(frozen=True)
class OpResult:
    op_id: int
    action: str
    device_id: str
    status: str            # done | failed | pending
    error: str | None = None


@dataclass(frozen=True)
class _Target:
    op: ProvisioningOp
    device: Device
    user: User
    project_id: str


class ProvisioningService:
    def __init__(self, ctx: IdentityContext, provisioner: Provisioner,
                 policy: AccountPolicy | None = None) -> None:
        self.ctx = ctx
        self.provisioner = provisioner
        self.policy = policy or AccountPolicy()

    # ------------------------------------------------------------ casos de uso

    def approve(self, actor: Actor, device_id: str, fingerprint: str) -> Binding:
        ticket = accounts.begin_approval(self.ctx, actor, device_id, fingerprint=fingerprint)
        result, binding = self._create(self._target(ticket.op_id))
        if binding is None:
            raise IdentityError(P.PROVISIONING_FAILED,
                                f"provisionamento falhou: {result.error}")
        return binding

    def revoke(self, actor: Actor, device_id: str, *,
               allow_last_admin: bool = False) -> OpResult:
        op_id = accounts.revoke(self.ctx, actor, device_id, allow_last_admin=allow_last_admin)
        return self.run_op(op_id)

    def block(self, actor: Actor, user_id: str) -> list[OpResult]:
        return [self.run_op(op_id) for op_id in accounts.block_user(self.ctx, actor, user_id)]

    def unblock(self, actor: Actor, user_id: str) -> list[OpResult]:
        return [self.run_op(op_id)
                for op_id in accounts.unblock_user(self.ctx, actor, user_id)]

    def purge(self, actor: Actor, device_id: str) -> OpResult:
        return self.run_op(accounts.purge(self.ctx, actor, device_id))

    def recover(self) -> list[OpResult]:
        """Repete as operações pendentes, em ordem de criação."""
        with self.ctx.repo.read() as tx:
            pending = [op.id for op in tx.pending_ops()]
        return [self.run_op(op_id) for op_id in pending]

    def run_op(self, op_id: int) -> OpResult:
        target = self._target(op_id)
        op, device = target.op, target.device
        if op.status != "pending":
            return OpResult(op.id, op.action, device.id, op.status, op.error)
        if op.action == "create":
            return self._create(target)[0]
        if device.ssh_account is None:
            return self._abandon(op, "dispositivo sem conta")
        if op.action == "enable" and not (device.status == "active"
                                          and target.user.status == "active"):
            return self._abandon(op, STATE_CHANGED)
        account, project = device.ssh_account, target.project_id
        try:
            match op.action:
                case "disable":
                    self.provisioner.disable_device(account)
                    problem = self.disabled_problem(
                        self.provisioner.inspect_device(account, project))
                case "enable":
                    self.provisioner.enable_device(account, device.public_key)
                    problem = self.enabled_problem(
                        self.provisioner.inspect_device(account, project), device)
                case _:
                    self.provisioner.delete_device(account, project)
                    problem = self.deleted_problem(
                        self.provisioner.inspect_device(account, project))
        except ProvisionError as exc:
            problem = str(exc)
        if problem is not None:
            accounts.finish_operation(self.ctx, op.id, error=problem)
            return OpResult(op.id, op.action, device.id, "pending", problem)
        accounts.finish_operation(self.ctx, op.id)
        return OpResult(op.id, op.action, device.id, "done")

    # ------------------------------------------------------------ criação

    def _create(self, target: _Target) -> tuple[OpResult, Binding | None]:
        op, device = target.op, target.device
        if device.status != "provisioning" or device.ssh_account is None:
            return self._abandon(op, STATE_CHANGED), None
        account = device.ssh_account
        if target.user.status != "active":
            problem: str | None = "usuário bloqueado"
        else:
            try:
                self.provisioner.create_device(account, target.project_id,
                                               device.public_key)
                problem = self.created_problem(
                    self.provisioner.inspect_device(account, target.project_id), device)
            except ProvisionError as exc:
                problem = str(exc)
        if problem is not None:
            accounts.fail_approval(self.ctx, device.id, op.id, problem)
            self._disable_now_or_later(account, device.id, problem)
            return OpResult(op.id, op.action, device.id, "failed", problem), None
        binding = accounts.complete_approval(self.ctx, device.id, op.id)
        return OpResult(op.id, op.action, device.id, "done"), binding

    def _disable_now_or_later(self, account: str, device_id: str, reason: str) -> None:
        try:
            self.provisioner.disable_device(account)
        except ProvisionError:
            accounts.schedule_disable(self.ctx, device_id, reason)

    # ------------------------------------------------------------ conferências (também do verify)

    def created_problem(self, insp: Inspection, device: Device) -> str | None:
        account = device.ssh_account
        p = self.policy
        missing = sorted(p.device_groups - insp.groups)
        checks = [
            (not insp.exists, "conta não existe"),
            (insp.expired, "conta expirada"),
            (bool(missing), f"grupos ausentes: {', '.join(missing)}"),
            (insp.key_fingerprint != device.fingerprint, "chave instalada difere"),
            (insp.home is None or insp.home.owner != account or insp.home.mode != HOME_MODE,
             "home fora do esperado"),
            (insp.gate != DirInfo(account, p.manager_group, GATE_MODE),
             "portão do workspace fora do esperado"),
            (insp.tree != DirInfo(account, p.workspace_group, TREE_MODE),
             "tree do workspace fora do esperado"),
        ]
        return next((message for failed, message in checks if failed), None)

    @staticmethod
    def disabled_problem(insp: Inspection) -> str | None:
        if insp.key_fingerprint is not None:
            return "chave ainda instalada"
        if insp.exists and not insp.expired:
            return "conta não expirada"
        if insp.processes:
            return f"processos ativos: {insp.processes}"
        return None

    @staticmethod
    def enabled_problem(insp: Inspection, device: Device) -> str | None:
        if not insp.exists:
            return "conta não existe"
        if insp.expired:
            return "conta expirada"
        if insp.key_fingerprint != device.fingerprint:
            return "chave instalada difere"
        return None

    @staticmethod
    def deleted_problem(insp: Inspection) -> str | None:
        if insp.exists:
            return "conta ainda existe"
        if insp.gate is not None:
            return "workspace ainda existe"
        if insp.key_fingerprint is not None:
            return "chave ainda instalada"
        return None

    # ------------------------------------------------------------ apoio

    def _abandon(self, op: ProvisioningOp, reason: str) -> OpResult:
        accounts.finish_operation(self.ctx, op.id, error=reason, abandon=True)
        return OpResult(op.id, op.action, op.device_id, "failed", reason)

    def _target(self, op_id: int) -> _Target:
        with self.ctx.repo.read() as tx:
            op = tx.get_op(op_id)
            device = tx.get_device(op.device_id) if op else None
            user = tx.get_user(device.user_id) if device else None
            invite = tx.get_invite(device.invite_id) if device and device.invite_id else None
        if op is None or device is None or user is None or invite is None:
            raise IdentityError(P.NOT_FOUND, "operação não encontrada")
        return _Target(op, device, user, invite.project_id)
