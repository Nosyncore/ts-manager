"""Conferência banco × contas × vínculos com o ``LocalProvisioner`` real em ``tmp_path``."""

from __future__ import annotations

import json

import pytest

from tests.unit.test_provisioning_service import (
    ADMIN,
    OPERATOR,
    Flaky,
    approved,
    device,
    pending,
)
from tsm_manager.layout import ProjectLayout
from tsm_manager.provisioning.provisioner import LocalProvisioner
from tsm_manager.provisioning.service import ProvisioningService
from tsm_manager.provisioning.verify import verify_accounts


@pytest.fixture
def prov(ctx, tmp_path) -> Flaky:
    ProjectLayout(tmp_path, "demo").workspaces.mkdir(parents=True)
    return Flaky(LocalProvisioner(tmp_path), ctx)


@pytest.fixture
def svc(ctx, prov) -> ProvisioningService:
    service = ProvisioningService(ctx, prov)
    pending(ctx)  # semeia o admin "adm"; a conta dele é criada aqui
    adm = device(ctx, "dev-adm")
    prov.inner.create_device(adm.ssh_account, "demo", adm.public_key)
    _bind(ctx, adm)
    return service


def _bind(ctx, d):
    from tsm_manager.db.repository import Binding

    with ctx.repo.write() as tx:
        if tx.binding_for("demo", d.id) is None:
            tx.insert_binding(Binding(f"b-{d.id}", "demo", d.id, d.ssh_account, "t"))


def test_consistent_state_has_no_problems(svc, ctx):
    approved(svc, ctx, "u2", 81)
    did, _ = approved(svc, ctx, "u3", 82)
    svc.revoke(ADMIN, did)
    assert verify_accounts(svc) == []


def test_active_device_without_account(svc, ctx, prov, tmp_path):
    did, account = approved(svc, ctx, "u2", 81)
    (tmp_path / "manager" / "local-accounts" / f"{account}.json").unlink()
    problems = verify_accounts(svc)
    assert problems == [f"dispositivo {did} ({account}): conta não existe"]


def test_revoked_device_with_key_still_installed(svc, ctx, prov, tmp_path):
    did, account = approved(svc, ctx, "u2", 81)
    svc.revoke(ADMIN, did)
    state_file = tmp_path / "manager" / "local-accounts" / f"{account}.json"
    state = json.loads(state_file.read_text("utf-8"))
    state["key"], state["expired"] = device(ctx, did).public_key, False
    state_file.write_text(json.dumps(state), "utf-8")
    assert verify_accounts(svc) == [f"dispositivo {did} ({account}): chave ainda instalada"]


def test_pending_operation_is_reported(svc, ctx, prov):
    did, account = approved(svc, ctx, "u2", 81)
    prov.failing("disable_device")
    svc.revoke(ADMIN, did)
    assert verify_accounts(svc) == [
        f"dispositivo {did} ({account}): operação pendente (disable); rode recover"]


def test_purged_device_must_be_gone(svc, ctx, prov, tmp_path):
    did, account = approved(svc, ctx, "u2", 81)
    svc.revoke(ADMIN, did)
    svc.purge(OPERATOR, did)
    assert verify_accounts(svc) == []
    ProjectLayout(tmp_path, "demo").account_gate(account).mkdir()
    assert verify_accounts(svc) == [f"dispositivo {did} ({account}): workspace ainda existe"]


def test_binding_problems(svc, ctx):
    did, _ = approved(svc, ctx, "u2", 81)
    with ctx.repo.write() as tx:
        tx.conn.execute("UPDATE workspace_bindings SET workspace = 'tsm-d-000000000000' "
                        "WHERE device_id = ?", (did,))
    problems = verify_accounts(svc)
    assert any("difere da conta" in p for p in problems)
    with ctx.repo.write() as tx:
        tx.conn.execute("DELETE FROM workspace_bindings WHERE device_id = ?", (did,))
    assert verify_accounts(svc) == [f"dispositivo {did}: ativo sem vínculo em demo"]


def test_inspect_failure_is_a_problem(svc, ctx, prov):
    did, account = approved(svc, ctx, "u2", 81)
    prov.failing("inspect_device", times=2)  # o do admin e o do novo dispositivo
    problems = verify_accounts(svc)
    assert len(problems) == 2 and all("inspect falhou" in p for p in problems)
    assert problems[1] == (f"dispositivo {did} ({account}): inspect falhou: "
                           "system: inspect_device quebrou")
