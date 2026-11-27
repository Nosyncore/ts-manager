"""Helper ``tsm-provision`` executado como root no contêiner ``linux/arm64`` (Ubuntu 24.04).

O helper é copiado para ``/usr/local/libexec/tsm-provision`` (``root:root 0755``) com a
config em ``/etc/tsm/provision.json`` e uma raiz própria (``/srv/tsp``), fora do volume
das suítes de colaboração. Os argumentos vão por ``docker exec`` direto, sem shell. Sudo,
sudoers e login SSH com as contas criadas ficam com os testes da imagem completa.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from tests.conftest import FIXTURES, REPO_ROOT
from tests.integration_ssh.conftest import MgrContainer, docker

pytestmark = [pytest.mark.ssh, pytest.mark.timeout(1800)]

HELPER = "/usr/local/libexec/tsm-provision"
ROOT = "/srv/tsp"
WS = f"{ROOT}/projects/demo/workspaces"
KEYS_DIR = "/etc/tsm/authorized_keys"
A = "tsm-d-0123456789ab"
B = "tsm-d-0123456789ac"
_KEYS = json.loads((FIXTURES / "sshkeys" / "vectors.json").read_text("utf-8"))
KEY_A = " ".join(_KEYS["ed25519"][0]["line"].split()[:2])
FP_A = _KEYS["ed25519"][0]["fingerprint"]
KEY_B = " ".join(_KEYS["ed25519"][1]["line"].split()[:2])
CONFIG = {"root": ROOT, "account_prefix": "tsm-d-", "devices_group": "tsm-devices",
          "shared_group": "tsm-readers", "workspace_group": "tsm-ws",
          "manager_group": "tsm-manager", "keys_dir": KEYS_DIR, "projects": ["demo"],
          "process_wait_s": 10}

_CLEAN = f"""
for u in $(getent passwd | cut -d: -f1 | grep '^tsm-d-'); do
  pkill -KILL -u "$u" 2>/dev/null || true
  userdel -r "$u" 2>/dev/null || true
done
rm -rf {ROOT} {KEYS_DIR}
"""


@dataclass
class Run:
    code: int
    out: dict


class Box:
    def __init__(self, c: MgrContainer) -> None:
        self.c = c

    def helper(self, *argv: str, key: str | None = None, user: str = "root") -> Run:
        proc = docker("exec", "-i", "-u", user, self.c.name, HELPER, *argv,
                      input=(key + "\n") if key is not None else "", check=False)
        lines = proc.stdout.strip().splitlines()
        return Run(proc.returncode, json.loads(lines[-1]) if lines else {})

    def sh(self, script: str, *, user: str = "root", check: bool = True) -> str:
        return self.c.sh(script, user=user, check=check).stdout

    def stat(self, *paths: str) -> list[str]:
        return self.sh("stat -c '%U:%G %a %F' " + " ".join(paths)).splitlines()

    def snapshot(self) -> str:
        return self.sh(f"cat /etc/passwd /etc/group /etc/shadow; ls -la /home /etc /tmp; "
                       f"find {ROOT} /etc/tsm -printf '%p %u:%g %m %y\\n' | sort")


@pytest.fixture
def box(mgr_container: MgrContainer) -> Iterator[Box]:
    c = mgr_container
    c.sh("install -d -o root -g root -m 0755 /usr/local/libexec")
    docker("cp",str(REPO_ROOT / "server" / "helper" / "tsm-provision"), f"{c.name}:{HELPER}")
    c.sh(f"""set -e
chown root:root {HELPER} && chmod 0755 {HELPER}
groupadd -f tsm-devices && groupadd -f tsm-ws
usermod -aG tsm-ws tsm-manager
{_CLEAN}
install -d -o root -g root -m 0755 {ROOT} {ROOT}/projects
install -d -o tsm-manager -g tsm-manager -m 0755 {ROOT}/projects/demo
install -d -o tsm-manager -g tsm-manager -m 0711 {WS}
""")
    c.sh("cat > /etc/tsm/provision.json && chown root:root /etc/tsm/provision.json "
         "&& chmod 0644 /etc/tsm/provision.json", input=json.dumps(CONFIG))
    yield Box(c)
    c.sh(_CLEAN)


def test_helper_header_and_runtime(box):
    head = box.sh(f"head -1 {HELPER}; /usr/bin/python3 --version")
    assert head.splitlines() == ["#!/usr/bin/python3 -I", head.splitlines()[1]]
    assert head.splitlines()[1].startswith("Python 3.12")


def test_create_device_and_idempotency(box):
    first = box.helper("create-device", A, "demo", key=KEY_A)
    assert (first.code, first.out) == (0, {"ok": True, "account": A, "created": True})
    passwd = box.sh(f"getent passwd {A}").strip().split(":")
    assert (passwd[5], passwd[6]) == (f"/home/{A}", "/bin/sh")
    assert set(box.sh(f"id -nG {A}").split()) == {A, "tsm-devices", "tsm-readers", "tsm-ws"}
    shadow = box.sh(f"getent shadow {A}").strip().split(":")
    assert (shadow[1], shadow[7]) == ("*", "")
    assert box.stat(f"/home/{A}", f"{WS}/{A}", f"{WS}/{A}/tree", KEYS_DIR,
                    f"{KEYS_DIR}/{A}") == [
        f"{A}:{A} 700 directory",
        f"{A}:tsm-manager 750 directory",
        f"{A}:tsm-ws 750 directory",
        "root:root 755 directory",
        "root:root 644 regular file",
    ]
    assert box.sh(f"cat {KEYS_DIR}/{A}") == KEY_A + "\n"
    inspect = box.helper("inspect-device", A, "demo").out
    assert inspect == {
        "ok": True, "account": A, "exists": True, "expired": False,
        "groups": sorted([A, "tsm-devices", "tsm-readers", "tsm-ws"]),
        "key_fingerprint": FP_A, "processes": 0,
        "home": {"owner": A, "group": A, "mode": "0o700"},
        "gate": {"owner": A, "group": "tsm-manager", "mode": "0o750"},
        "tree": {"owner": A, "group": "tsm-ws", "mode": "0o750"},
    }
    before = box.snapshot()
    again = box.helper("create-device", A, "demo", key=KEY_A)
    assert (again.code, again.out["created"]) == (0, False)
    assert box.snapshot() == before
    other = box.helper("create-device", A, "demo", key=KEY_B)
    assert (other.code, other.out["error"]) == (3, "conflict")
    assert box.snapshot() == before


def test_manager_reads_the_tree_and_other_device_does_not(box):
    box.helper("create-device", A, "demo", key=KEY_A)
    box.helper("create-device", B, "demo", key=KEY_B)
    box.sh(f"mkdir -p {WS}/{A}/tree/sub && echo dado > {WS}/{A}/tree/sub/a.txt", user=A)
    assert box.sh(f"cat {WS}/{A}/tree/sub/a.txt", user="tsm-manager") == "dado\n"
    denied = box.c.sh(f"ls {WS}/{A}", user=B, check=False)
    assert denied.returncode != 0 and "Permission denied" in denied.stderr
    listing = box.c.sh(f"ls {WS}", user=B, check=False)
    assert listing.returncode != 0


def test_disable_kills_processes_and_enable_reverts(box):
    box.helper("create-device", A, "demo", key=KEY_A)
    docker("exec", "-d", "-u", A, box.c.name, "sleep", "600")
    box.c.sh(f"for i in $(seq 50); do pgrep -u {A} >/dev/null && exit 0; sleep 0.2; done; "
             "exit 1")
    disabled = box.helper("disable-device", A)
    assert (disabled.code, disabled.out["exists"]) == (0, True)
    assert box.c.sh(f"pgrep -u {A}", check=False).returncode == 1
    assert box.sh(f"getent shadow {A}").strip().split(":")[7] == "1"
    assert box.sh(f"test -e {KEYS_DIR}/{A} && echo sim || echo nao").strip() == "nao"
    inspect = box.helper("inspect-device", A, "demo").out
    assert (inspect["expired"], inspect["key_fingerprint"], inspect["processes"]) == (
        True, None, 0)
    enabled = box.helper("enable-device", A, key=KEY_A)
    assert enabled.code == 0
    inspect = box.helper("inspect-device", A, "demo").out
    assert (inspect["expired"], inspect["key_fingerprint"]) == (False, FP_A)
    assert box.sh(f"getent shadow {A}").strip().split(":")[7] == ""


def test_delete_removes_account_group_key_and_workspace(box):
    box.helper("create-device", A, "demo", key=KEY_A)
    box.sh(f"echo x > {WS}/{A}/tree/a.txt", user=A)
    deleted = box.helper("delete-device", A, "demo")
    assert deleted.code == 0
    assert box.c.sh(f"id {A}", check=False).returncode != 0
    assert box.c.sh(f"getent group {A}", check=False).returncode != 0
    assert box.sh(f"ls -d /home/{A} {WS}/{A} {KEYS_DIR}/{A} 2>/dev/null; true") == ""
    inspect = box.helper("inspect-device", A, "demo").out
    assert (inspect["exists"], inspect["gate"], inspect["key_fingerprint"]) == (
        False, None, None)
    assert box.helper("delete-device", A, "demo").code == 0


@pytest.mark.parametrize("argv", [
    ["create-device", f"{A};touch /tmp/pwned", "demo"],
    ["create-device", "../../etc", "demo"],
    ["create-device", "root", "demo"],
    ["create-device", "tsm-manager", "demo"],
    ["create-device", A, "../../etc"],
    ["create-device", A, "$(touch /tmp/pwned)"],
    ["disable-device", "root"],
    ["delete-device", "tsm-dev-a", "demo"],
    ["inspect-device", A],
    ["useradd", "x"],
    [],
])
def test_malicious_arguments_have_no_effect(box, argv):
    before = box.snapshot()
    result = box.helper(*argv, key=KEY_A)
    assert (result.code, result.out.get("error")) == (2, "invalid")
    assert box.snapshot() == before
    assert box.c.sh("test -e /tmp/pwned", check=False).returncode == 1


@pytest.mark.parametrize("key", [
    f"restrict {KEY_A}", f'command="touch /tmp/pwned" {KEY_A}', f"{KEY_A}\n{KEY_B}",
    f"{KEY_A} comentario", _KEYS["other"][0]["line"],
])
def test_malicious_keys_have_no_effect(box, key):
    before = box.snapshot()
    assert box.helper("create-device", A, "demo", key=key).code == 2
    assert box.snapshot() == before


def test_planted_symlinks_are_not_followed(box):
    box.sh(f"ln -s /etc {WS}/{A}")
    planted = box.helper("create-device", A, "demo", key=KEY_A)
    assert planted.code == 4
    assert box.stat("/etc") == ["root:root 755 directory"]
    box.sh(f"rm {WS}/{A}")
    box.helper("disable-device", A)
    box.helper("delete-device", A, "demo")

    assert box.helper("create-device", A, "demo", key=KEY_A).code == 0
    box.sh(f"cd {WS}/{A} && mv tree tree-old && ln -s /etc tree", user=A)
    again = box.helper("create-device", A, "demo", key=KEY_A)
    assert again.code == 4
    assert box.stat("/etc") == ["root:root 755 directory"]


def test_helper_refuses_non_root(box):
    result = box.helper("inspect-device", A, "demo", user="tsm-manager")
    assert (result.code, result.out["error"]) == (4, "system")
