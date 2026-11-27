"""Fonte de vínculos sobre o banco (``workspace_bindings``), com escopo por projeto."""

from __future__ import annotations

from tests.unit.identity_fakes import seed_user
from tsm_manager.bindings import BindingSource, DbBindings
from tsm_manager.config import BindingConfig


def test_bindings_from_the_database(ctx):
    seed_user(ctx, "u1", project="demo")
    seed_user(ctx, "u1", did="dev-u1-b", project="outro")
    seed_user(ctx, "u2")
    demo = DbBindings(ctx.repo, "demo")
    with ctx.repo.read() as tx:
        workspace = tx.get_binding("b-dev-u1").workspace
    assert demo.get("b-dev-u1") == BindingConfig("b-dev-u1", "dev-u1", workspace)
    assert demo.for_device("dev-u1") == demo.get("b-dev-u1")
    assert demo.get("b-dev-u1-b") is None          # vínculo de outro projeto
    assert demo.for_device("dev-u1-b") is None
    assert demo.for_device("dev-u2") is None
    assert demo.get("nada") is None
    assert DbBindings(ctx.repo, "outro").for_device("dev-u1-b").id == "b-dev-u1-b"


def test_db_bindings_satisfy_the_interface(ctx):
    source: BindingSource = DbBindings(ctx.repo, "demo")
    assert source.get("x") is None
