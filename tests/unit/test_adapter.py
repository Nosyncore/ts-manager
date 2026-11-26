import json
from pathlib import Path

import pytest

from tsm_client.adapters.mutagen import (
    DaemonUnavailable,
    MutagenAdapter,
    MutagenError,
    MutagenNotFound,
    MutagenOutputError,
    MutagenTimeout,
    SessionCannotSync,
    SessionNotFound,
    SessionState,
    Status,
    SubprocessRunner,
    Timeouts,
    mutagen_env,
)
from tsm_client.paths import Endpoint, canonical_local
from tsm_client.rules import ProjectRules
from tsm_client.sessions import Binding, build_specs

from .fakes import DAEMON_DOWN, FakeRunner, fail, ok

EXE = Path("C:/tools/mutagen.exe")


@pytest.fixture
def runner():
    return FakeRunner()


@pytest.fixture
def adapter(runner):
    return MutagenAdapter(EXE, runner, sleep=lambda s: None)


@pytest.fixture
def specs(tmp_path):
    def L(*p):
        return Endpoint(None, canonical_local(str(tmp_path.joinpath(*p))))

    b = Binding("demo-pca", "demo", L("work"), L("cache"),
                Endpoint("tsm-test-a", "/srv/ts/projects/demo/workspaces/dev-a"),
                Endpoint("tsm-test-a", "/srv/ts/projects/demo/shared"), ProjectRules())
    return build_specs(b)


def load(fixtures_dir, name):
    return (fixtures_dir / "mutagen" / name).read_text(encoding="utf-8")


# ---------- env ----------


def test_env_isolates_and_strips_inherited_mutagen_vars(tmp_path):
    base = {"PATH": "x", "MUTAGEN_DAEMON_LOG": "1", "mutagen_ssh_path": "evil",
            "SSH_AUTH_SOCK": "sock"}
    env = mutagen_env(tmp_path / "data", ssh_path=tmp_path / "git", ssh_home=tmp_path / "home",
                      base=base)
    assert env["MUTAGEN_DATA_DIRECTORY"] == str(tmp_path / "data")
    assert env["MUTAGEN_DISABLE_AUTOSTART"] == "1"
    assert env["MUTAGEN_SSH_PATH"] == str(tmp_path / "git")
    assert env["HOME"] == str(tmp_path / "home")
    assert "MUTAGEN_DAEMON_LOG" not in env and "mutagen_ssh_path" not in env
    assert "SSH_AUTH_SOCK" not in env
    assert env["PATH"] == "x"


def test_env_without_ssh_options_keeps_home(tmp_path):
    env = mutagen_env(tmp_path, base={"HOME": "h", "SSH_AUTH_SOCK": "s"})
    assert env["HOME"] == "h" and env["SSH_AUTH_SOCK"] == "s"
    assert "MUTAGEN_SSH_PATH" not in env


# ---------- argv golden ----------


def test_create_argv_golden(specs):
    up, down = specs
    args = MutagenAdapter.create_args(up)
    assert args[:4] == ["sync", "create", "--no-global-configuration", "--name=tsm-demo-pca-up"]
    labels = [a for a in args if a.startswith("--label=")]
    assert labels == sorted(labels)
    assert "--label=tsm-managed=true" in labels
    assert "--label=tsm-role=upload" in labels
    assert f"--label=tsm-spec={up.spec_hash}" in labels
    assert "--mode=one-way-replica" in args
    assert "--default-file-mode-beta=0640" in args
    assert args[-2:] == [up.alpha.url, "tsm-test-a:/srv/ts/projects/demo/workspaces/dev-a"]
    assert "--paused" not in args
    assert "--paused" in MutagenAdapter.create_args(down, paused=True)


def test_create_parses_identifier(adapter, runner, specs):
    runner.on("sync", "create",
              respond=ok("Creating session...\r   \rCreated session sync_AbC123\n"))
    assert adapter.create(specs[0]) == "sync_AbC123"
    argv, timeout = runner.calls[-1]
    assert argv[0] == str(EXE)
    assert timeout == Timeouts().create


def test_create_without_identifier_is_output_error(adapter, runner, specs):
    runner.on("sync", "create", respond=ok("???"))
    with pytest.raises(MutagenOutputError):
        adapter.create(specs[0])


@pytest.mark.parametrize(("verb", "method"), [("pause", "pause"), ("resume", "resume"),
                                              ("terminate", "terminate"), ("flush", "flush")])
def test_operations_use_identifiers(adapter, runner, verb, method):
    getattr(adapter, method)(["sync_A1", "sync_B2"])
    assert runner.args() == ["sync", verb, "sync_A1", "sync_B2"]


def test_flush_skip_wait(adapter, runner):
    adapter.flush(["sync_A1"], skip_wait=True)
    assert runner.args() == ["sync", "flush", "--skip-wait", "sync_A1"]
    assert runner.calls[-1][1] == Timeouts().flush


def test_operations_with_no_ids_do_nothing(adapter, runner):
    adapter.pause([])
    assert runner.calls == []


@pytest.mark.parametrize("bad", ["tsm-demo-up", "-x", "sync_A1 sync_B", ""])
def test_operations_reject_non_identifiers(adapter, runner, bad):
    with pytest.raises(MutagenError, match="identificador"):
        adapter.pause([bad])
    assert runner.calls == []


def test_list_argv_and_parsing(adapter, runner, fixtures_dir):
    runner.on("sync", "list", respond=ok(load(fixtures_dir, "list_watching.json")))
    sessions = adapter.list_sessions()
    assert runner.args() == ["sync", "list", "--template={{json .}}",
                             "--label-selector=tsm-managed=true"]
    (s,) = sessions
    assert s.status is Status.WATCHING and not s.paused
    assert s.name == "probe-up" and s.labels["tsm-managed"] == "true"
    assert s.mode == "one-way-replica"
    assert s.alpha.endpoint == Endpoint(None, "C:\\tsm-fixture\\a")
    assert s.alpha.connected and s.beta.files == 2
    assert s.successful_cycles == 4


def test_list_without_selector(adapter, runner, fixtures_dir):
    runner.on("sync", "list", respond=ok("[]"))
    assert adapter.list_sessions(label_selector=None) == []
    assert not any(a.startswith("--label-selector") for a in runner.args())


@pytest.mark.parametrize(
    ("fixture", "status", "paused", "halted"),
    [("list_paused.json", Status.DISCONNECTED, True, False),
     ("list_halted_root_emptied.json", Status.HALTED_ON_ROOT_EMPTIED, False, True)],
)
def test_real_fixtures(adapter, runner, fixtures_dir, fixture, status, paused, halted):
    runner.on("sync", "list", respond=ok(load(fixtures_dir, fixture)))
    (s,) = adapter.list_sessions()
    assert s.status is status and s.paused is paused and s.status.halted is halted


def test_unknown_status_does_not_crash(fixtures_dir):
    d = json.loads(load(fixtures_dir, "list_watching.json"))[0]
    d["status"] = "something-new"
    s = SessionState.from_json(d)
    assert s.status is Status.UNKNOWN and s.raw_status == "something-new"


def test_problems_and_conflicts_parsed(fixtures_dir):
    d = json.loads(load(fixtures_dir, "list_watching.json"))[0]
    d["beta"]["transitionProblems"] = [{"path": "Spells.lua", "error": "collision"}]
    d["alpha"]["scanProblems"] = [{"path": "x", "error": "y"}, "junk"]
    d["conflicts"] = [{}, {}]
    d["lastError"] = "boom"
    s = SessionState.from_json(d)
    assert [p.path for p in s.problems] == ["x", "Spells.lua"]
    assert s.conflicts == 2 and s.last_error == "boom"


def test_real_ssh_fixture(adapter, runner, fixtures_dir):
    runner.on("sync", "list", respond=ok(load(fixtures_dir, "list_ssh_watching.json")))
    (s,) = adapter.list_sessions()
    assert s.status is Status.WATCHING
    assert s.alpha.endpoint == Endpoint(None, "C:\\tsm-fixture\\pcA\\work")
    assert s.beta.endpoint == Endpoint("tsm-test-a", "/srv/ts/projects/demo/workspaces/dev-a")
    assert s.beta.connected
    assert s.labels["tsm-role"] == "upload"


def test_ssh_endpoint_parsed():
    s = SessionState.from_json({
        "identifier": "sync_X", "status": "watching",
        "alpha": {"protocol": "local", "path": "C:\\w"},
        "beta": {"protocol": "ssh", "host": "tsm-test-a", "path": "/srv/ts/w"},
    })
    assert s.beta.endpoint == Endpoint("tsm-test-a", "/srv/ts/w")


@pytest.mark.parametrize("out", ["{nope", '{"a": 1}', '[{"no-identifier": 1}]'])
def test_list_bad_output(adapter, runner, out):
    runner.on("sync", "list", respond=ok(out))
    with pytest.raises(MutagenOutputError):
        adapter.list_sessions()


# ---------- erros ----------


@pytest.mark.parametrize(
    ("stderr", "exc"),
    [
        (DAEMON_DOWN, DaemonUnavailable),
        ('Error: unable to locate requested sessions: specification "x" did not match any '
         "sessions\n", SessionNotFound),
        ("Forcing...\rError: unable to flush session: session is not currently able to "
         "synchronize\n", SessionCannotSync),
        ("Error: unable to flush session: session is paused\n", SessionCannotSync),
        ("Error: something else\n", MutagenError),
    ],
)
def test_error_mapping(adapter, runner, stderr, exc):
    runner.on("sync", "pause", respond=fail(stderr))
    with pytest.raises(exc) as info:
        adapter.pause(["sync_A1"])
    assert type(info.value) is exc
    assert info.value.returncode == 1
    assert not str(info.value).startswith("Error:")


def test_error_without_stderr_mentions_exit_code(adapter, runner):
    runner.on("version", respond=fail("", rc=3))
    with pytest.raises(MutagenError, match="3"):
        adapter.version()


def test_timeout_propagates(adapter, runner):
    runner.on("sync", "flush", respond=lambda argv: MutagenTimeout("t", argv=argv))
    with pytest.raises(MutagenTimeout):
        adapter.flush(["sync_A1"])


# ---------- daemon ----------


def test_daemon_running(adapter, runner):
    runner.on("sync", "list", respond=fail(DAEMON_DOWN))
    assert adapter.daemon_running() is False
    runner.on("sync", "list", respond=ok("[]"))
    assert adapter.daemon_running() is True


def test_daemon_start_waits_until_ready(adapter, runner):
    state = {"n": 0}

    def flaky(argv):
        state["n"] += 1
        return fail(DAEMON_DOWN)(argv) if state["n"] < 3 else ok("[]")(argv)

    runner.on("sync", "list", respond=flaky)
    adapter.daemon_start()
    assert runner.args(0) == ["daemon", "start"]
    assert state["n"] == 3


def test_daemon_start_times_out(runner):
    t = {"now": 0.0}

    def clock():
        t["now"] += 5
        return t["now"]

    adapter = MutagenAdapter(EXE, runner, sleep=lambda s: None, clock=clock)
    runner.on("sync", "list", respond=fail(DAEMON_DOWN))
    with pytest.raises(DaemonUnavailable, match="pronto"):
        adapter.daemon_start()


def test_daemon_stop_tolerates_stopped(adapter, runner):
    runner.on("daemon", "stop", respond=fail(DAEMON_DOWN))
    adapter.daemon_stop()


def test_version(adapter, runner):
    runner.on("version", respond=ok("0.18.1\n"))
    assert adapter.version() == "0.18.1"


# ---------- runner real (sem Mutagen) ----------


def test_subprocess_runner_missing_executable(tmp_path):
    r = SubprocessRunner({})
    with pytest.raises(MutagenNotFound):
        r([str(tmp_path / "nao-existe.exe")], timeout=5)


def test_subprocess_runner_runs_and_times_out(tmp_path):
    import os
    import sys

    r = SubprocessRunner(dict(os.environ))
    res = r([sys.executable, "-c", "import sys; print('x'); sys.exit(2)"], timeout=30)
    assert res.returncode == 2 and res.stdout.strip() == "x"
    with pytest.raises(MutagenTimeout):
        r([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
