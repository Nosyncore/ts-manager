"""Conferência banco × contas × vínculos (``tsm-manager verify``).

Para cada dispositivo com conta atribuída, o ``inspect-device`` do provisionador é comparado
com o estado que o banco exige, usando as mesmas conferências do ``ProvisioningService``:

- dispositivo ``active`` de usuário ``active``: conta criada e conferida (grupos, chave,
  home, portão e ``tree/``);
- expurgado (``delete`` concluída): conta, chave e workspace removidos;
- qualquer outro caso com conta (revogado, usuário bloqueado, aprovação que falhou): sem
  chave, conta expirada e sem processos;
- dispositivo com operação pendente: só a pendência é informada (rode ``recover``).

Vínculos: o dispositivo existe, o ``workspace`` é a conta dele, e todo dispositivo ``active``
tem vínculo no projeto do convite. Contas no sistema sem dispositivo no banco não são
procuradas: o helper não tem verbo de listagem.
"""

from __future__ import annotations

from tsm_manager.provisioning.provisioner import Provisioner, ProvisionError
from tsm_manager.provisioning.service import ProvisioningService


def verify_accounts(service: ProvisioningService) -> list[str]:
    ctx, provisioner = service.ctx, service.provisioner
    with ctx.repo.read() as tx:
        devices = tx.list_devices()
        users = {u.id: u for u in tx.list_users()}
        projects = {d.id: (tx.get_invite(d.invite_id).project_id
                           if tx.get_invite(d.invite_id) else None) for d in devices}
        ops = {d.id: tx.ops_for_device(d.id) for d in devices}
        bindings = tx.list_bindings()
    problems: list[str] = []
    by_id = {d.id: d for d in devices}
    for d in devices:
        project = projects[d.id]
        if d.ssh_account is None or project is None:
            continue
        label = f"dispositivo {d.id} ({d.ssh_account})"
        pending = sorted({op.action for op in ops[d.id] if op.status == "pending"})
        if pending:
            problems.append(f"{label}: operação pendente ({', '.join(pending)}); "
                            "rode recover")
            continue
        problem = _account_problem(service, provisioner, d, project,
                                   active=d.status == "active"
                                   and users[d.user_id].status == "active",
                                   deleted=any(op.action == "delete" and op.status == "done"
                                               for op in ops[d.id]))
        if problem:
            problems.append(f"{label}: {problem}")
    bound = set()
    for b in bindings:
        device = by_id.get(b.device_id)
        bound.add((b.project_id, b.device_id))
        if device is None:
            problems.append(f"vínculo {b.id}: dispositivo inexistente")
        elif device.ssh_account != b.workspace:
            problems.append(f"vínculo {b.id}: workspace {b.workspace} difere da conta "
                            f"{device.ssh_account}")
    for d in devices:
        if d.status == "active" and (projects[d.id], d.id) not in bound:
            problems.append(f"dispositivo {d.id}: ativo sem vínculo em {projects[d.id]}")
    return problems


def _account_problem(service: ProvisioningService, provisioner: Provisioner, device,
                     project: str, *, active: bool, deleted: bool) -> str | None:
    try:
        insp = provisioner.inspect_device(device.ssh_account, project)
    except ProvisionError as exc:
        return f"inspect falhou: {exc}"
    if deleted:
        return service.deleted_problem(insp)
    if active:
        return service.created_problem(insp, device)
    return service.disabled_problem(insp)
