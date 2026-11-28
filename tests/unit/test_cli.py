import io
import json

import pytest

from tests.transport_config import BindingSpec, transport_config
from tsm_client.adapters.mutagen import MutagenAdapter
from tsm_client.cli import EXIT_CONFIG, EXIT_MUTAGEN, EXIT_OK, EXIT_REFUSED, build_parser, run
from tsm_client.service import TransportService

from .fakes import DAEMON_DOWN, FakeRunner, fail, ok


def session_json(name, binding, role, ident, *, status="watching", paused=False, spec=None,
                 alpha="C:\\a", beta="C:\\b", managed=True):
    labels = {"tsm-binding": binding, "tsm-role": role}
    if managed:
        labels["tsm-managed"] = "true"
    if spec:
        labels["tsm-spec"] = spec
    return {"identifier": ident, "name": name, "labels": labels if managed or spec else {},
            "status": status, "paused": paused, "mode": "one-way-replica",
            "alpha": {"protocol": "local", "path": alpha, "connected": True},
            "beta": {"protocol": "local", "path": beta, "connected": True}}


@pytest.fixture
def env(tmp_path):
    work = tmp_path / "pcA" / "work"
    work.mkdir(parents=True)
    (work / "ts-project.json").write_text('{"project_id": "demo", "version": 1}', encoding="utf-8")
    cfg = transport_config(tmp_path, device_id="pca", data_directory="pcA/mutagen-data",
                           executable=tmp_path / "m.exe", bindings=[BindingSpec(
                               "demo-pca", "pcA/work", "pcA/cache", "server/ws/devA",
                               "server/shared")])
    runner = FakeRunner()
    state = {"sessions": []}
    runner.on("sync", "list", respond=lambda argv: ok(json.dumps(state["sessions"]))(argv))
    services = []

    def factory(c):
        s = TransportService(c, MutagenAdapter(tmp_path / "m.exe", runner, sleep=lambda s: None))
        services.append(s)
        return s

    def call(*args):
        out, err = io.StringIO(), io.StringIO()
        code = run(list(args), config=cfg, service_factory=factory, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    return {"tmp": tmp_path, "runner": runner, "state": state, "call": call, "cfg": cfg,
            "services": services}


def verbs(runner):
    return [c[0][1:3] for c in runner.calls]


def specs_of(env):
    env["call"]("status")
    return env["services"][-1].specs()


def test_parser_requires_command_and_has_no_config_file_option():
    assert build_parser().parse_args(["up"]).home is None  # padrão: TSM_HOME ou o local
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--home", "y"])
    for argv in (["--config", "x", "up"], ["-c", "x", "status"]):
        with pytest.raises(SystemExit) as exc:
            run(argv)
        assert exc.value.code == EXIT_CONFIG


def test_up_creates_two_sessions(env):
    env["runner"].on("sync", "create", respond=ok("Created session sync_New1\n"))
    code, out, err = env["call"]("up")
    assert code == EXIT_OK, err
    assert verbs(env["runner"]).count(["sync", "create"]) == 2
    assert "tsm-demo-pca-up: created" in out and "tsm-demo-pca-down: created" in out
    assert ["daemon", "start"] in verbs(env["runner"])


def test_up_is_idempotent(env):
    up, down = specs_of(env)
    env["state"]["sessions"] = [
        session_json(up.name, "demo-pca", "upload", "sync_U1", spec=up.spec_hash,
                     alpha=up.alpha.path, beta=up.beta.path),
        session_json(down.name, "demo-pca", "download", "sync_D1", spec=down.spec_hash,
                     paused=True, alpha=down.alpha.path, beta=down.beta.path),
    ]
    code, out, _ = env["call"]("up")
    assert code == EXIT_OK
    assert ["sync", "create"] not in verbs(env["runner"])
    assert "unchanged" in out and "resumed" in out
    assert env["runner"].args() == ["sync", "resume", "sync_D1"]


def test_up_refuses_changed_configuration(env):
    up, down = specs_of(env)
    env["state"]["sessions"] = [session_json(up.name, "demo-pca", "upload", "sync_U1",
                                             spec="000000000000")]
    code, _, err = env["call"]("up")
    assert code == EXIT_REFUSED and "configuração mudou" in err
    assert ["sync", "create"] not in verbs(env["runner"])


def test_up_refuses_overlap_with_alien_session(env):
    up, _ = specs_of(env)
    env["state"]["sessions"] = [session_json(up.name, "", "", "sync_X", managed=False,
                                             alpha=str(env["tmp"] / "x"), beta=up.alpha.path)]
    code, _, err = env["call"]("up")
    assert code == EXIT_CONFIG and "sobreposição" in err
    assert ["sync", "create"] not in verbs(env["runner"])


def test_up_requires_project_file(env):
    (env["tmp"] / "pcA" / "work" / "ts-project.json").unlink()
    code, _, err = env["call"]("up")
    assert code == EXIT_CONFIG and "ts-project.json" in err
    assert env["runner"].calls == []


def test_status_daemon_stopped(env):
    env["runner"].on("sync", "list", respond=fail(DAEMON_DOWN))
    code, out, _ = env["call"]("status")
    assert code == EXIT_OK and "parado" in out
    code, out, _ = env["call"]("status", "--json")
    assert json.loads(out)["daemon"] == "stopped"


def test_status_lists_only_own_bindings(env):
    up, _ = specs_of(env)
    env["state"]["sessions"] = [
        session_json(up.name, "demo-pca", "upload", "sync_U1", status="halted-on-root-emptied"),
        session_json("tsm-x-up", "outro", "upload", "sync_O1"),
    ]
    code, out, _ = env["call"]("status", "--json")
    data = json.loads(out)
    assert [s["identifier"] for s in data["sessions"]] == ["sync_U1", None]
    assert data["sessions"][0]["status"] == "halted-on-root-emptied"
    assert data["sessions"][1]["status"] == "absent"
    code, out, _ = env["call"]("status")
    assert "salvaguarda" in out and "ausente" in out


def test_flush_by_role(env):
    env["state"]["sessions"] = [session_json("a", "demo-pca", "upload", "sync_U1"),
                                session_json("b", "demo-pca", "download", "sync_D1")]
    code, _, _ = env["call"]("flush", "--role", "upload")
    assert code == EXIT_OK
    assert env["runner"].args() == ["sync", "flush", "sync_U1"]
    env["call"]("flush")
    assert env["runner"].args() == ["sync", "flush", "sync_U1", "sync_D1"]


def test_pause_skips_already_paused_and_foreign(env):
    env["state"]["sessions"] = [session_json("a", "demo-pca", "upload", "sync_U1"),
                                session_json("b", "demo-pca", "download", "sync_D1", paused=True),
                                session_json("c", "outro", "upload", "sync_O1")]
    assert env["call"]("pause")[0] == EXIT_OK
    assert env["runner"].args() == ["sync", "pause", "sync_U1"]


def test_resume_refuses_halted_without_confirmation(env):
    env["state"]["sessions"] = [
        session_json("a", "demo-pca", "upload", "sync_U1", status="halted-on-root-deletion"),
        session_json("b", "demo-pca", "download", "sync_D1", paused=True)]
    code, _, err = env["call"]("resume")
    assert code == EXIT_REFUSED and "--confirm-halted" in err
    assert ["sync", "resume"] not in verbs(env["runner"])
    code, _, _ = env["call"]("resume", "--confirm-halted")
    assert code == EXIT_OK
    assert env["runner"].args() == ["sync", "resume", "sync_U1", "sync_D1"]


def test_teardown_only_own_sessions(env):
    env["state"]["sessions"] = [session_json("a", "demo-pca", "upload", "sync_U1"),
                                session_json("c", "outro", "upload", "sync_O1")]
    code, out, _ = env["call"]("teardown", "--stop-daemon")
    assert code == EXIT_OK
    assert ["sync", "terminate", "sync_U1"] in [c[0][1:] for c in env["runner"].calls]
    assert env["runner"].args() == ["daemon", "stop"]


def test_teardown_with_daemon_stopped_is_noop(env):
    env["runner"].on("sync", "list", respond=fail(DAEMON_DOWN))
    assert env["call"]("teardown")[0] == EXIT_OK


def test_mutagen_error_exit_code(env):
    env["runner"].on("daemon", "start", respond=fail("Error: boom\n"))
    code, _, err = env["call"]("up")
    assert code == EXIT_MUTAGEN and "boom" in err


def test_invalid_home_config_exit_code(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.json").write_text("{}", encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    code = run(["--home", str(home), "status"], out=out, err=err)
    assert code == EXIT_CONFIG and "configuração ou uso inválido" in err.getvalue()


def test_identity_commands_need_the_home(env):
    code, _, err = env["call"]("whoami")
    assert code == EXIT_CONFIG and "diretório do tsm" in err


def test_doctor_missing_executable(env):
    code, out, _ = env["call"]("doctor")
    assert code == EXIT_MUTAGEN and "ausente" in out
