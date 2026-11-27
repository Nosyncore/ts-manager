"""Helper de provisionamento (``server/helper/tsm-provision``) com sistema falso.

O ``FakeSystem`` simula contas, grupos, ``/etc/shadow``, processos e o sistema de arquivos
(com symlinks), e registra cada comando e cada alteração. Assim, a lista exata de comandos
de cada verbo, a idempotência e as recusas são verificadas sem root.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import posixpath
import sys
import time
from dataclasses import dataclass, field

import pytest

from tests.conftest import FIXTURES, REPO_ROOT
from tsm_common.sshkeys import parse_public_key

HELPER_PATH = REPO_ROOT / "server" / "helper" / "tsm-provision"


def _load_helper():
    loader = importlib.machinery.SourceFileLoader("tsm_provision_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


H = _load_helper()

KEYS = json.loads((FIXTURES / "sshkeys" / "vectors.json").read_text("utf-8"))
KEY_A = " ".join(KEYS["ed25519"][0]["line"].split()[:2])
KEY_B = " ".join(KEYS["ed25519"][1]["line"].split()[:2])
FP_A = KEYS["ed25519"][0]["fingerprint"]
ACCOUNT = "tsm-d-0123456789ab"
WS = "/srv/ts/projects/demo/workspaces"
GATE = f"{WS}/{ACCOUNT}"
KEYS_DIR = "/etc/tsm/authorized_keys"
CONFIG = {"root": "/srv/ts", "account_prefix": "tsm-d-", "devices_group": "tsm-devices",
          "shared_group": "tsm-readers", "workspace_group": "tsm-ws",
          "manager_group": "tsm-manager", "keys_dir": KEYS_DIR, "projects": ["demo"],
          "process_wait_s": 2}
GIDS = {"root": 0, "tsm-manager": 1001, "tsm-devices": 1100, "tsm-readers": 1101,
        "tsm-ws": 1102}


@dataclass
class Node:
    kind: str
    uid: int = 0
    gid: int = 0
    mode: int = 0o755
    data: bytes = b""


@dataclass
class FakeSystem:
    config: dict = field(default_factory=lambda: dict(CONFIG))
    root: bool = True
    nodes: dict = field(default_factory=dict)
    users: dict = field(default_factory=dict)
    groups: dict = field(default_factory=dict)
    shadow: dict = field(default_factory=dict)
    procs: dict = field(default_factory=dict)
    stubborn: set = field(default_factory=set)
    fail: dict = field(default_factory=dict)
    calls: list = field(default_factory=list)
    clock: float = 0.0
    next_id: int = 2000

    def __post_init__(self) -> None:
        for path in ("/", "/srv", "/srv/ts", "/srv/ts/projects", "/srv/ts/projects/demo",
                     "/etc", "/etc/tsm", "/home"):
            self.nodes[path] = Node("dir")
        self.nodes[WS] = Node("dir", 1001, 1001, 0o711)
        for name, gid in GIDS.items():
            self.groups[name] = [gid, set()]
        self.users["root"] = H.PwEntry("root", 0, 0, "/root")
        self.users["tsm-manager"] = H.PwEntry("tsm-manager", 1001, 1001, "/home/tsm-manager")

    # --------------------------------------------------------- comandos

    @property
    def changes(self) -> list:
        return [c for c in self.calls
                if not (c[0] == "run" and c[1][0] in (H.PGREP, H.LOGGER))]

    def is_root(self) -> bool:
        return self.root

    def read_config(self, path: str) -> str:
        assert path == H.CONFIG_PATH
        return json.dumps(self.config)

    def run(self, argv, stdin=None):
        self.calls.append(("run", list(argv)))
        name = posixpath.basename(argv[0])
        if name in self.fail:
            return self.fail[name], b""
        return getattr(self, "_" + name)(argv[1:])

    def _useradd(self, args):
        account = args[-1]
        if account in self.users:
            return 9, b""
        groups = args[args.index("--groups") + 1].split(",")
        self.next_id += 1
        uid = gid = self.next_id
        self.groups[account] = [gid, set()]
        for g in groups:
            self.groups[g][1].add(account)
        home = f"/home/{account}"
        self.users[account] = H.PwEntry(account, uid, gid, home)
        self.nodes[home] = Node("dir", uid, gid, 0o750)
        self.shadow[account] = None
        return 0, b""

    def _usermod(self, args):
        account = args[-1]
        if account not in self.users:
            return 6, b""
        if args[0] == "--append":
            for g in args[2].split(","):
                self.groups[g][1].add(account)
        elif args[0] == "--expiredate":
            self.shadow[account] = int(args[1]) if args[1] else None
        return 0, b""

    def _userdel(self, args):
        account = args[-1]
        user = self.users.pop(account, None)
        if user is None:
            return 6, b""
        self.groups.pop(account, None)
        for _, members in self.groups.values():
            members.discard(account)
        self.remove_tree(user.home, record=False)
        self.shadow.pop(account, None)
        return 0, b""

    def _pkill(self, args):
        account = args[-1]
        had = self.procs.get(account, 0)
        if account not in self.stubborn:
            self.procs[account] = 0
        return (0 if had else 1), b""

    def _pgrep(self, args):
        count = self.procs.get(args[-1], 0)
        return (0, "\n".join(str(4000 + i) for i in range(count)).encode()) if count \
            else (1, b"")

    def _logger(self, args):
        return 0, b""

    # --------------------------------------------------------- arquivos

    def lstat(self, path):
        node = self.nodes.get(path)
        return None if node is None else H.Stat(node.kind, node.uid, node.gid, node.mode)

    def mkdir(self, path, mode):
        self.calls.append(("mkdir", path, mode))
        parent = self.nodes.get(posixpath.dirname(path))
        if path in self.nodes or parent is None or parent.kind != "dir":
            raise OSError("mkdir")
        self.nodes[path] = Node("dir", 0, 0, mode)

    def set_owner_mode(self, path, uid, gid, mode):
        self.calls.append(("set", path, uid, gid, oct(mode)))
        node = self.nodes.get(path)
        if node is None or node.kind != "dir":
            raise OSError("ELOOP")
        node.uid, node.gid, node.mode = uid, gid, mode

    def read_file(self, path):
        node = self.nodes.get(path)
        if node is None:
            return None
        if node.kind != "file":
            raise OSError("ELOOP")
        return node.data

    def write_file(self, path, data, mode):
        self.calls.append(("write", path, data, oct(mode)))
        parent = self.nodes.get(posixpath.dirname(path))
        if parent is None or parent.kind != "dir":
            raise OSError("ENOENT")
        self.nodes[path] = Node("file", 0, 0, mode, data)

    def remove_file(self, path):
        self.calls.append(("rm", path))
        self.nodes.pop(path, None)

    def remove_tree(self, path, record=True):
        if record:
            self.calls.append(("rmtree", path))
        for p in [p for p in self.nodes if p == path or p.startswith(path + "/")]:
            del self.nodes[p]

    def getpwnam(self, name):
        return self.users.get(name)

    def getgrnam(self, name):
        group = self.groups.get(name)
        return None if group is None else group[0]

    def user_groups(self, name):
        user = self.users.get(name)
        if user is None:
            return []
        names = {g for g, (_, members) in self.groups.items() if name in members}
        names |= {g for g, (gid, _) in self.groups.items() if gid == user.gid}
        return sorted(names)

    def user_name(self, uid):
        return next((u.name for u in self.users.values() if u.uid == uid), str(uid))

    def group_name(self, gid):
        return next((g for g, (i, _) in self.groups.items() if i == gid), str(gid))

    def shadow_expire(self, name):
        return self.shadow.get(name)

    def today(self):
        return 20_000

    def monotonic(self):
        return self.clock

    def sleep(self, seconds):
        self.clock += seconds


@dataclass
class Result:
    code: int
    out: dict
    err: str


def call(system: FakeSystem, *argv: str, key: str | bytes | None = None) -> Result:
    data = key.encode() if isinstance(key, str) else key
    stdout, stderr = io.StringIO(), io.StringIO()
    code = H.main(list(argv), io.BytesIO(data or b""), stdout, stderr, system=system)
    lines = stdout.getvalue().splitlines()
    assert len(lines) == 1
    return Result(code, json.loads(lines[0]), stderr.getvalue())


@pytest.fixture
def system() -> FakeSystem:
    return FakeSystem()


def created(system: FakeSystem, key: str = KEY_A) -> FakeSystem:
    assert call(system, "create-device", ACCOUNT, "demo", key=key + "\n").code == 0
    system.calls.clear()
    return system


# ------------------------------------------------------------------ config


def test_config_is_parsed():
    cfg = H.parse_config(json.dumps(CONFIG))
    assert cfg.device_groups == ("tsm-devices", "tsm-readers", "tsm-ws")
    assert cfg.process_wait_s == 2.0
    assert H.parse_config(json.dumps({k: v for k, v in CONFIG.items()
                                      if k != "process_wait_s"})).process_wait_s == 10.0


@pytest.mark.parametrize("change", [
    {"root": "srv/ts"}, {"root": "/srv/../etc"}, {"root": "/srv/ts/"}, {"root": 1},
    {"keys_dir": "/etc/tsm/a b"}, {"account_prefix": "tsm-d"}, {"account_prefix": "Tsm-"},
    {"devices_group": "Root"}, {"manager_group": "a;b"}, {"projects": []},
    {"projects": ["../x"]}, {"projects": "demo"}, {"process_wait_s": 0},
    {"process_wait_s": True}, {"process_wait_s": 500}, {"extra": 1},
])
def test_invalid_config_is_a_system_failure(change):
    raw = {**CONFIG, **change}
    with pytest.raises(H.Failure):
        H.parse_config(json.dumps(raw))


@pytest.mark.parametrize("text", ["{", "[]"])
def test_malformed_config_text(text):
    with pytest.raises(H.Failure):
        H.parse_config(text)


def test_missing_config_field():
    raw = {k: v for k, v in CONFIG.items() if k != "keys_dir"}
    with pytest.raises(H.Failure):
        H.parse_config(json.dumps(raw))


# ------------------------------------------------------------------ validação de argumentos


@pytest.mark.parametrize("account", [
    "tsm-d-0123456789ab; rm -rf /", "../../etc/passwd", "root", "tsm-d-0123456789AB",
    "tsm-d-0123", "tsm-d-0123456789abc", "tsm-x-0123456789ab", "tsm-d-0123456789a\n",
    "-tsm-d-0123456789ab", "tsm-d-0123456789ab/../x", "",
])
def test_invalid_account_is_refused_without_effect(system, account):
    for verb, extra in (("create-device", ["demo"]), ("disable-device", []),
                        ("delete-device", ["demo"]), ("inspect-device", ["demo"])):
        result = call(system, verb, account, *extra, key=KEY_A)
        assert (result.code, result.out["error"]) == (2, "invalid")
    assert system.changes == []
    logged = [c[1] for c in system.calls if c[0] == "run" and c[1][0] == H.LOGGER]
    assert all(line[-1].split()[1] == "-" for line in logged)


@pytest.mark.parametrize("project", ["outro", "../demo", "Demo", "demo;id", "/srv"])
def test_project_outside_the_list_is_refused(system, project):
    assert call(system, "create-device", ACCOUNT, project, key=KEY_A).code == 2
    assert system.changes == []


def test_account_must_match_the_configured_prefix(system):
    system.config["account_prefix"] = "tsm-x-"
    assert call(system, "inspect-device", ACCOUNT, "demo").code == 2


@pytest.mark.parametrize("argv", [
    [], ["useradd"], ["create-device", ACCOUNT], ["disable-device", ACCOUNT, "demo"],
    ["inspect-device", ACCOUNT, "demo", "extra"], ["--help"],
])
def test_unknown_verb_or_wrong_arguments(system, argv):
    result = call(system, *argv)
    assert (result.code, result.out["error"]) == (2, "invalid")
    assert result.err == "tsm-provision: invalid\n"
    assert system.changes == []


def test_must_run_as_root(system):
    system.root = False
    assert call(system, "inspect-device", ACCOUNT, "demo").code == 4
    assert system.changes == []


def test_unreadable_config_is_a_system_failure(system, monkeypatch):
    def broken(path):
        raise PermissionError(path)

    monkeypatch.setattr(system, "read_config", broken)
    assert call(system, "inspect-device", ACCOUNT, "demo").out["error"] == "system"


# ------------------------------------------------------------------ chaves


@pytest.mark.parametrize("vector", KEYS["ed25519"])
def test_key_parsing_matches_the_common_parser(vector):
    line = " ".join(vector["line"].split()[:2])
    expected = parse_public_key(vector["line"])
    assert H.parse_key((line + "\n").encode()) == (expected.openssh, expected.fingerprint)
    assert H.parse_key(line.encode())[1] == vector["fingerprint"]


_B64_A = KEY_A.split()[1]

BAD_KEYS = {
    "rsa": KEYS["other"][0]["line"].encode(),
    "ecdsa": " ".join(KEYS["other"][1]["line"].split()[:2]).encode(),
    "comentário": (KEY_A + " dev@pc\n").encode(),
    "opções": f"restrict {KEY_A}\n".encode(),
    "duas linhas": f"{KEY_A}\n{KEY_B}\n".encode(),
    "crlf": f"{KEY_A}\r\n".encode(),
    "espaço antes": f" {KEY_A}".encode(),
    "vazia": b"",
    "longa": b"ssh-ed25519 " + b"A" * 2000,
    "não ascii": "ssh-ed25519 AAAAé".encode(),
    "base64 sem múltiplo de 4": f"ssh-ed25519 {_B64_A[:-1]}".encode(),
    "base64 não canônico": f"ssh-ed25519 {_B64_A[:-2]}{'B' if _B64_A[-2] != 'B' else 'C'}="
    .encode(),
    "blob truncado": f"ssh-ed25519 {_B64_A[:-8]}".encode(),
    "tipo trocado": ("ssh-ed25519 " + __import__("base64").b64encode(
        b"\x00\x00\x00\x0bssh-ed25518\x00\x00\x00\x20" + b"\x01" * 32).decode()).encode(),
}


@pytest.mark.parametrize("name", sorted(BAD_KEYS))
def test_invalid_keys_are_refused(system, name):
    with pytest.raises(H.Invalid):
        H.parse_key(BAD_KEYS[name])
    assert call(system, "create-device", ACCOUNT, "demo", key=BAD_KEYS[name]).code == 2
    assert system.changes == []


# ------------------------------------------------------------------ create-device


def test_create_runs_the_exact_commands(system):
    result = call(system, "create-device", ACCOUNT, "demo", key=KEY_A + "\n")
    assert (result.code, result.out) == (0, {"ok": True, "account": ACCOUNT,
                                             "created": True})
    uid = system.users[ACCOUNT].uid
    assert system.changes == [
        ("run", [H.USERADD, "--user-group", "--create-home", "--shell", "/bin/sh",
                 "--password", "*", "--groups", "tsm-devices,tsm-readers,tsm-ws", ACCOUNT]),
        ("set", f"/home/{ACCOUNT}", uid, uid, "0o700"),
        ("mkdir", GATE, 0o750),
        ("set", GATE, uid, 1001, "0o750"),
        ("mkdir", f"{GATE}/tree", 0o750),
        ("set", f"{GATE}/tree", uid, 1102, "0o750"),
        ("mkdir", KEYS_DIR, 0o755),
        ("set", KEYS_DIR, 0, 0, "0o755"),
        ("write", f"{KEYS_DIR}/{ACCOUNT}", (KEY_A + "\n").encode(), "0o644"),
    ]
    assert system.calls[-1] == ("run", [H.LOGGER, "-t", "tsm-provision", "--",
                                        f"create-device {ACCOUNT} ok"])


@pytest.fixture
def created_system(system) -> FakeSystem:
    return created(system)


def test_create_is_idempotent(created_system):
    result = call(created_system, "create-device", ACCOUNT, "demo", key=KEY_A)
    assert (result.code, result.out["created"]) == (0, False)
    assert created_system.changes[0] == ("run", [H.USERMOD, "--expiredate", "", ACCOUNT])
    assert [c[0] for c in created_system.changes[1:]] == ["set"] * 4


def test_create_after_a_failed_attempt_clears_the_expiration(created_system):
    call(created_system, "disable-device", ACCOUNT)
    assert call(created_system, "create-device", ACCOUNT, "demo", key=KEY_A).code == 0
    assert created_system.shadow[ACCOUNT] is None
    assert created_system.nodes[f"{KEYS_DIR}/{ACCOUNT}"].data == (KEY_A + "\n").encode()


def test_create_with_another_key_is_a_conflict(created_system):
    result = call(created_system, "create-device", ACCOUNT, "demo", key=KEY_B)
    assert (result.code, result.out["error"]) == (3, "conflict")
    assert created_system.changes == []


def test_create_completes_a_partial_account(system):
    system._useradd(["--groups", "tsm-devices", ACCOUNT])
    result = call(system, "create-device", ACCOUNT, "demo", key=KEY_A)
    assert (result.code, result.out["created"]) == (0, False)
    assert ("run", [H.USERMOD, "--append", "--groups", "tsm-readers,tsm-ws", ACCOUNT]) \
        in system.changes
    assert system.nodes[f"{KEYS_DIR}/{ACCOUNT}"].data == (KEY_A + "\n").encode()


@pytest.mark.parametrize("setup", ["missing", "link", "writable", "parent_link"])
def test_create_requires_a_safe_workspaces_directory(system, setup):
    if setup == "missing":
        del system.nodes[WS]
    elif setup == "link":
        system.nodes[WS] = Node("link")
    elif setup == "writable":
        system.nodes[WS].mode = 0o777
    else:
        system.nodes["/srv/ts/projects/demo"] = Node("link")
    result = call(system, "create-device", ACCOUNT, "demo", key=KEY_A)
    assert (result.code, result.out["error"]) == (4, "system")
    assert system.changes == []


def test_planted_symlink_gate_is_not_followed(system):
    system.nodes[GATE] = Node("link")
    result = call(system, "create-device", ACCOUNT, "demo", key=KEY_A)
    assert result.code == 4
    assert not any(c[0] == "set" and c[1] == GATE for c in system.calls)
    assert f"{KEYS_DIR}/{ACCOUNT}" not in system.nodes


def test_planted_symlink_key_file_is_refused(system):
    system.nodes[KEYS_DIR] = Node("dir")
    system.nodes[f"{KEYS_DIR}/{ACCOUNT}"] = Node("link")
    system._useradd(["--groups", "tsm-devices,tsm-readers,tsm-ws", ACCOUNT])
    assert call(system, "create-device", ACCOUNT, "demo", key=KEY_A).code == 4
    assert not any(c[0] == "write" for c in system.calls)


@pytest.mark.parametrize("group", ["tsm-ws", "tsm-manager", "tsm-devices"])
def test_create_requires_the_fixed_groups(system, group):
    del system.groups[group]
    assert call(system, "create-device", ACCOUNT, "demo", key=KEY_A).code == 4
    assert system.changes == []


def test_useradd_failure_is_a_system_failure(system):
    system.fail["useradd"] = 1
    result = call(system, "create-device", ACCOUNT, "demo", key=KEY_A)
    assert (result.code, result.out["detail"]) == (4, "useradd falhou (1)")


def test_account_missing_after_useradd(system, monkeypatch):
    monkeypatch.setattr(system, "_useradd", lambda args: (0, b""))
    assert call(system, "create-device", ACCOUNT, "demo", key=KEY_A).code == 4


# ------------------------------------------------------------------ disable / enable


def test_disable_removes_key_expires_and_kills(created_system):
    created_system.procs[ACCOUNT] = 3
    result = call(created_system, "disable-device", ACCOUNT)
    assert (result.code, result.out) == (0, {"ok": True, "account": ACCOUNT, "exists": True})
    assert created_system.changes == [
        ("rm", f"{KEYS_DIR}/{ACCOUNT}"),
        ("run", [H.USERMOD, "--expiredate", "1", ACCOUNT]),
        ("run", [H.PKILL, "-KILL", "-u", ACCOUNT]),
    ]
    assert created_system.shadow[ACCOUNT] == 1
    assert created_system.procs[ACCOUNT] == 0


def test_disable_fails_when_processes_survive(created_system):
    created_system.procs[ACCOUNT] = 1
    created_system.stubborn.add(ACCOUNT)
    result = call(created_system, "disable-device", ACCOUNT)
    assert (result.code, result.out["detail"]) == (4, "1 processo(s) da conta não terminaram")
    assert created_system.clock >= 2


def test_disable_of_missing_account_is_ok(system):
    result = call(system, "disable-device", ACCOUNT)
    assert (result.code, result.out["exists"]) == (0, False)
    assert system.changes == [("rm", f"{KEYS_DIR}/{ACCOUNT}")]


def test_pgrep_failure_is_a_system_failure(created_system):
    created_system.fail["pgrep"] = 3
    assert call(created_system, "disable-device", ACCOUNT).code == 4


def test_enable_reinstalls_key_and_clears_expiration(created_system):
    call(created_system, "disable-device", ACCOUNT)
    created_system.calls.clear()
    result = call(created_system, "enable-device", ACCOUNT, key=KEY_A)
    assert result.code == 0
    assert created_system.changes == [
        ("set", KEYS_DIR, 0, 0, "0o755"),
        ("write", f"{KEYS_DIR}/{ACCOUNT}", (KEY_A + "\n").encode(), "0o644"),
        ("run", [H.USERMOD, "--expiredate", "", ACCOUNT]),
    ]
    assert created_system.shadow[ACCOUNT] is None


def test_enable_of_missing_account_is_a_conflict(system):
    assert call(system, "enable-device", ACCOUNT, key=KEY_A).code == 3
    assert system.changes == []


# ------------------------------------------------------------------ delete


def test_delete_disables_removes_account_and_workspace(created_system):
    (created_system.nodes.setdefault(f"{GATE}/tree/a.txt", Node("file")))
    result = call(created_system, "delete-device", ACCOUNT, "demo")
    assert result.code == 0
    assert created_system.changes == [
        ("rm", f"{KEYS_DIR}/{ACCOUNT}"),
        ("run", [H.USERMOD, "--expiredate", "1", ACCOUNT]),
        ("run", [H.PKILL, "-KILL", "-u", ACCOUNT]),
        ("run", [H.USERDEL, "--remove", ACCOUNT]),
        ("rmtree", GATE),
    ]
    assert ACCOUNT not in created_system.users and ACCOUNT not in created_system.groups
    assert not any(p.startswith(GATE) for p in created_system.nodes)


def test_delete_is_idempotent_and_unlinks_a_planted_gate(system):
    system.nodes[GATE] = Node("link")
    assert call(system, "delete-device", ACCOUNT, "demo").code == 0
    assert system.changes == [("rm", f"{KEYS_DIR}/{ACCOUNT}"), ("rm", GATE)]
    assert call(system, "delete-device", ACCOUNT, "demo").code == 0


# ------------------------------------------------------------------ inspect


def test_inspect_after_create(created_system):
    created_system.procs[ACCOUNT] = 2
    result = call(created_system, "inspect-device", ACCOUNT, "demo")
    assert result.out == {
        "ok": True, "account": ACCOUNT, "exists": True, "expired": False,
        "groups": sorted([ACCOUNT, "tsm-devices", "tsm-readers", "tsm-ws"]),
        "key_fingerprint": FP_A, "processes": 2,
        "home": {"owner": ACCOUNT, "group": ACCOUNT, "mode": "0o700"},
        "gate": {"owner": ACCOUNT, "group": "tsm-manager", "mode": "0o750"},
        "tree": {"owner": ACCOUNT, "group": "tsm-ws", "mode": "0o750"},
    }
    assert created_system.changes == []


def test_inspect_after_disable_and_for_missing_account(created_system):
    call(created_system, "disable-device", ACCOUNT)
    out = call(created_system, "inspect-device", ACCOUNT, "demo").out
    assert (out["expired"], out["key_fingerprint"], out["processes"]) == (True, None, 0)
    other = "tsm-d-ffffffffffff"
    out = call(created_system, "inspect-device", other, "demo").out
    assert (out["exists"], out["groups"], out["gate"], out["home"]) == (False, [], None, None)


def test_inspect_reports_an_invalid_installed_key(created_system):
    created_system.nodes[f"{KEYS_DIR}/{ACCOUNT}"].data = b"restrict lixo\n"
    assert call(created_system, "inspect-device", ACCOUNT, "demo").out[
        "key_fingerprint"] == "invalid"


# ------------------------------------------------------------------ robustez


def test_unexpected_errors_do_not_leak(system, monkeypatch):
    def boom(name):
        raise RuntimeError("segredo interno")

    monkeypatch.setattr(system, "getpwnam", boom)
    result = call(system, "inspect-device", ACCOUNT, "demo")
    assert result.out == {"ok": False, "error": "system", "detail": "erro interno"}
    assert "segredo" not in result.err


def test_logger_failure_does_not_change_the_result(system, monkeypatch):
    original = system.run

    def run(argv, stdin=None):
        if argv[0] == H.LOGGER:
            raise OSError("sem logger")
        return original(argv, stdin)

    monkeypatch.setattr(system, "run", run)
    assert call(system, "inspect-device", ACCOUNT, "demo").code == 0


def test_main_reads_at_most_the_key_limit(system):
    result = call(system, "create-device", ACCOUNT, "demo", key=b"A" * 5000)
    assert result.code == 2


# ------------------------------------------------------------------ sistema real (portável)


def test_real_system_files(tmp_path):
    real = H.RealSystem()
    d = str(tmp_path / "d")
    real.mkdir(d, 0o750)
    assert real.lstat(d).kind == "dir"
    assert real.lstat(str(tmp_path / "nada")) is None
    f = tmp_path / "d" / "f"
    f.write_bytes(b"conteudo")
    assert real.lstat(str(f)).kind == "file"
    assert real.read_file(str(f)) == b"conteudo"
    assert real.read_file(str(tmp_path / "nada")) is None
    real.remove_file(str(f))
    real.remove_file(str(f))
    real.mkdir(os.path.join(d, "sub"), 0o750)
    real.remove_tree(d)
    assert not os.path.exists(d)
    cfg = tmp_path / "provision.json"
    cfg.write_text("{}", encoding="utf-8")
    assert real.read_config(str(cfg)) == "{}"


def test_real_system_shadow_and_clock(tmp_path, monkeypatch):
    shadow = tmp_path / "shadow"
    shadow.write_text(f"root:*:19000:0:99999:7:::\n{ACCOUNT}:*:19000:0:99999:7::1:\n"
                      "outra:*:19000:0:99999:7:::\n", encoding="utf-8")
    monkeypatch.setattr(H, "SHADOW_PATH", str(shadow))
    real = H.RealSystem()
    assert real.shadow_expire(ACCOUNT) == 1
    assert real.shadow_expire("outra") is None
    assert real.shadow_expire("nenhuma") is None
    assert real.today() == int(time.time() // 86400)
    before = real.monotonic()
    real.sleep(0)
    assert real.monotonic() >= before


def test_real_system_runs_without_shell():
    rc, out = H.RealSystem().run([sys.executable, "-c", "print('ok')"])
    assert (rc, out.strip()) == (0, b"ok")


@pytest.mark.skipif(os.name == "nt", reason="contas POSIX")
def test_real_system_accounts():
    real = H.RealSystem()
    me = real.user_name(os.getuid())
    assert real.getpwnam(me).uid == os.getuid()
    assert real.getpwnam("tsm-d-000000000000") is None
    assert real.getgrnam(real.group_name(os.getgid())) == os.getgid()
    assert real.getgrnam("tsm-grupo-inexistente") is None
    assert real.user_groups("tsm-d-000000000000") == []
    assert real.group_name(os.getgid()) in real.user_groups(me)
