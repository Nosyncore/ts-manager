"""CLI do Manager: ``migrate`` e recusa de banco ausente ou desatualizado."""

from __future__ import annotations

import io
import json

import pytest

from tsm_manager.cli import EXIT_CONFIG, EXIT_FAIL, EXIT_OK, EXIT_PROBLEMS, run
from tsm_manager.db import Database, upgrade
from tsm_manager.db.migrate import packaged_migrations


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "manager.json"
    p.write_text(json.dumps({
        "version": 2, "root": "srv", "shared_group": "tsm-readers",
        "workspace_group": "tsm-ws", "provisioner": {"mode": "local"},
        "projects": [{"id": "demo"}],
    }), encoding="utf-8")
    return p


def tsm_manager(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(list(args), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def db_path(cfg):
    return cfg.parent / "srv" / "manager" / "manager.db"


def test_migrate_creates_and_is_idempotent(cfg):
    code, out, _ = tsm_manager("migrate", "--config", str(cfg))
    assert code == EXIT_OK
    assert "aplicada: 0001" in out and "aplicada: 0002" in out and "server_id" in out
    assert db_path(cfg).is_file()
    code, out, _ = tsm_manager("migrate", "--config", str(cfg))
    assert code == EXIT_OK and "aplicada" not in out
    code, out, _ = tsm_manager("migrate", "--status", "--config", str(cfg))
    assert code == EXIT_OK and "versão 2 de 2" in out
    assert not (db_path(cfg).parent / "backups").exists()  # banco novo: nada a copiar


def test_status_without_database_does_not_create_it(cfg):
    code, out, _ = tsm_manager("migrate", "--status", "--config", str(cfg))
    assert code == EXIT_PROBLEMS and "ausente" in out
    assert not db_path(cfg).exists()


@pytest.mark.parametrize("command", [
    ["serve"], ["recover"], ["verify"], ["init-project", "--project", "demo", "--from", "."],
])
def test_commands_refuse_missing_database(cfg, command):
    code, _, err = tsm_manager(command[0], "--config", str(cfg), *command[1:])
    assert code == EXIT_FAIL and "tsm-manager migrate" in err
    assert not db_path(cfg).exists()


def test_outdated_database_is_refused_then_upgraded_with_backup(cfg):
    db = Database(db_path(cfg))
    upgrade(db, migrations=packaged_migrations()[:1])
    db.close()
    code, _, err = tsm_manager("serve", "--config", str(cfg))
    assert code == EXIT_FAIL and "versão 1, esperada 2" in err
    code, out, _ = tsm_manager("migrate", "--status", "--config", str(cfg))
    assert code == EXIT_PROBLEMS and "pendente: 0002_state" in out
    code, out, _ = tsm_manager("migrate", "--config", str(cfg))
    assert code == EXIT_OK and "aplicada: 0002" in out and "aplicada: 0001" not in out
    backups = list((db_path(cfg).parent / "backups").glob("manager-v0001-*.db"))
    assert len(backups) == 1


def test_migrate_reports_incompatible_database(cfg):
    assert tsm_manager("migrate", "--config", str(cfg))[0] == EXIT_OK
    db = Database(db_path(cfg))
    with db.transaction() as conn:
        conn.execute("INSERT INTO schema_migrations VALUES (3, 'futura', 'x', 'agora')")
    db.close()
    for args in (["migrate"], ["migrate", "--status"], ["verify"]):
        code, _, err = tsm_manager(*args, "--config", str(cfg))
        assert code == EXIT_FAIL and "downgrade" in err, args


def test_commands_with_current_database(cfg):
    assert tsm_manager("migrate", "--config", str(cfg))[0] == EXIT_OK
    code, out, _ = tsm_manager("verify", "--config", str(cfg))
    assert code == EXIT_PROBLEMS and "demo: não inicializado" in out
    code, out, _ = tsm_manager("recover", "--config", str(cfg))
    assert code == EXIT_OK and "recover: ok" in out
    code, _, err = tsm_manager("init-project", "--config", str(cfg), "--project", "nope",
                               "--from", ".")
    assert code == EXIT_CONFIG and "desconhecido" in err
    code, _, err = tsm_manager("serve", "--config", str(cfg), "--host", "0.0.0.0")
    assert code == EXIT_CONFIG and "loopback" in err


def test_invalid_config(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert tsm_manager("migrate", "--config", str(bad))[0] == EXIT_CONFIG


@pytest.mark.parametrize("command", [["migrate"], ["serve"], ["verify"], ["requests", "list"]])
def test_version_1_config_is_refused_with_migration_message(tmp_path, command):
    old = tmp_path / "old.json"
    old.write_text(json.dumps({
        "version": 1, "root": "srv", "projects": [{"id": "demo", "bindings": []}],
        "identities": []}), encoding="utf-8")
    code, _, err = tsm_manager(command[0], *command[1:], "--config", str(old))
    assert code == EXIT_CONFIG
    assert "version 1" in err and "não é mais aceita" in err and "bootstrap-admin" in err
    assert not (tmp_path / "srv").exists()


def test_token_command_no_longer_exists(capsys):
    with pytest.raises(SystemExit) as exc:
        tsm_manager("token", "--quiet")
    assert exc.value.code == EXIT_CONFIG
    assert "token" in capsys.readouterr().err
