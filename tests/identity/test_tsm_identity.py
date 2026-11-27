"""O ``tsm`` contra o Manager real: cadastro, aprovação, vínculo, publicação e revogação.

Os cenários seguem em ordem e dividem o estado (um Manager por módulo). Os comandos ``tsm``
rodam no processo do teste com os adaptadores reais (``ssh-keygen``, ``icacls``, HTTP,
Mutagen); só o endereço de origem de cada "PC" é fixado (``conftest.SourceTransport``).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.identity.conftest import Pc
from tests.integration.conftest import wait_until
from tests.manager.identity_http import KEYGEN
from tsm_client.adapters.acl import current_user_sid
from tsm_client.adapters.mutagen import pins
from tsm_client.cli import EXIT_CONFIG, EXIT_IDENTITY, EXIT_OK, EXIT_REFUSED
from tsm_client.home import Home
from tsm_client.sshconfig import parse_connection, write_ssh_files
from tsm_common.rules import ProjectRules, rules_digest

pytestmark = pytest.mark.integration

SPELLS = "data/scripts/spells.lua"
world: dict = {}


@pytest.fixture(scope="module")
def pcs(srv, tmp_path_factory):
    base = tmp_path_factory.mktemp("pcs")
    made: dict[str, Pc] = {}

    def make(name: str, n: int) -> Pc:
        if name not in made:
            made[name] = Pc(base / name, n, srv)
        return made[name]

    yield make
    for pc in made.values():
        if (pc.home / "config.json").exists():
            pc.tsm("teardown", "--stop-daemon", expect=None)


def ssh_keygen_env(home: Path) -> dict[str, str]:
    env = {"HOME": str(home), "PATH": str(KEYGEN.parent), "LC_ALL": "C", "LANG": "C"}
    if os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def acl_of(path: Path) -> dict:
    script = (f"$a = Get-Acl -LiteralPath '{path}'; "
              "$r = @($a.Access | ForEach-Object { [pscustomobject]@{"
              "sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;"
              " inherited=$_.IsInherited; type=\"$($_.AccessControlType)\"} }); "
              "[pscustomobject]@{protected=$a.AreAccessRulesProtected; rules=$r} | "
              "ConvertTo-Json -Depth 4 -Compress")
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, text=True, timeout=60, check=True)
    return json.loads(r.stdout)


# ---------------------------------------------------------------- bootstrap e chave do dispositivo


def test_bootstrap_by_tsm(srv, pcs):
    boot = json.loads(srv.cli("bootstrap-admin", "--project", "demo", "--json").stdout)
    admin = pcs("admin", 1)
    res = admin.json("enroll", "--manager", admin.url, "--invite", boot["code"], "--name",
                     "Admin")
    assert res["status"] == "pending" and res["server_id"] == boot["server_id"]
    assert res["fingerprint"].startswith("SHA256:") and res["key_created"]
    r = srv.cli("requests", "approve", res["device_id"], "--fingerprint", "SHA256:errado",
                ok=(1,))
    assert "fingerprint_mismatch" in r.stderr
    srv.cli("requests", "approve", res["device_id"], "--fingerprint", res["fingerprint"])
    who = admin.json("whoami")
    assert who["user"]["role"] == "admin" and who["device"]["status"] == "active"
    assert who["session"]["scope"] == "full"
    srv.cli("bootstrap-admin", "--project", "demo", ok=(1,))  # já há admin ativo
    world["admin"] = res


def test_device_key_is_protected(pcs):
    """Só o usuário, sem herança; o OpenSSH do Git for Windows aceita a chave."""
    admin = pcs("admin", 1)
    home = Home(admin.home)
    sid = current_user_sid()
    for target in (home.root, home.ssh_dir, home.key_path, home.session_file):
        acl = acl_of(target)
        assert acl["protected"], target
        assert [(x["sid"], x["type"]) for x in acl["rules"]] == [(sid, "Allow")], target
    for target in (home.key_path, home.session_file):
        assert not any(x["inherited"] for x in acl_of(target)["rules"])
    r = subprocess.run([str(KEYGEN), "-y", "-f", str(home.key_path)],
                       env=ssh_keygen_env(home.ssh_home), stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and "UNPROTECTED" not in r.stderr, r.stderr
    assert r.stdout.split()[:2] == home.pub_path.read_text().split()[:2]


def test_openssh_of_git_does_not_check_key_permissions(pcs, tmp_path):
    """Controle negativo da proteção da chave (caracterização).

    O Git for Windows monta os discos com ``noacl``: todo arquivo aparece como ``0644`` e o
    OpenSSH dele não confere a permissão da chave. Uma chave legível por ``Everyone`` é
    aceita sem aviso; a proteção é só a ACL aplicada pelo ``tsm``. Se uma versão futura
    passar a conferir, este teste falha e o achado é revisto.
    """
    from tsm_client.adapters.acl import WindowsAcl

    admin = pcs("admin", 1)
    copy = tmp_path / "neg" / "id_ed25519"
    copy.parent.mkdir()
    shutil.copyfile(Home(admin.home).key_path, copy)
    WindowsAcl().restrict_file(copy)
    subprocess.run([os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32",
                                 "icacls.exe"), str(copy), "/grant", "*S-1-1-0:R", "/q"],
                   check=True, capture_output=True)
    r = subprocess.run([str(KEYGEN), "-y", "-f", str(copy)], env=ssh_keygen_env(tmp_path),
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and "UNPROTECTED" not in r.stderr, (r.returncode, r.stderr)
    assert "S-1-1-0" in json.dumps(acl_of(copy))  # a chave estava mesmo exposta


# ---------------------------------------------------------------- convite, pendência e aprovação


def test_invite_enroll_pending(srv, pcs):
    admin, dev = pcs("admin", 1), pcs("dev", 2)
    inv = admin.json("admin", "invite", "create", "--project", "demo", "--ttl", "1h")
    res = dev.json("enroll", "--manager", dev.url, "--invite", inv["code"], "--name", "Dev")
    assert res["status"] == "pending"
    used = [i for i in admin.json("admin", "invite", "list") if i["id"] == inv["id"]]
    assert used[0]["state"] == "used"
    who = dev.json("whoami")
    assert who["device"]["status"] == "pending" and who["session"]["scope"] == "pending"
    code, _, err = dev.tsm("bind", "--project", "demo", "--local", str(dev.work), expect=None)
    assert code == EXIT_IDENTITY and "aguardando aprovação" in err
    world["dev"] = res


def test_approve_with_fingerprint(pcs):
    admin = pcs("admin", 1)
    dev = world["dev"]
    code, _, err = admin.tsm("admin", "requests", "approve", dev["device_id"],
                             "--fingerprint", world["admin"]["fingerprint"], expect=None)
    assert code == EXIT_REFUSED and "fingerprint_mismatch" in err
    admin.tsm("admin", "requests", "approve", dev["device_id"], "--fingerprint",
              dev["fingerprint"])
    assert pcs("dev", 2).json("whoami")["device"]["status"] == "active"


def test_developer_cannot_administer(pcs):
    dev = pcs("dev", 2)
    code, _, err = dev.tsm("admin", "invite", "create", "--project", "demo", expect=None)
    assert code == EXIT_REFUSED and "forbidden" in err
    code, _, err = dev.tsm("admin", "devices", "revoke", world["admin"]["device_id"],
                           expect=None)
    assert code == EXIT_REFUSED and "forbidden" in err


# ---------------------------------------------------------------- vínculo, publicação e pull


def test_bind_init_publish_pull(srv, pcs):
    admin, dev = pcs("admin", 1), pcs("dev", 2)
    a = admin.json("bind", "--project", "demo", "--local", str(admin.work))
    d = dev.json("bind", "--project", "demo", "--local", str(dev.work))
    assert a["transport"] == d["transport"] == "local" and a["binding"] != d["binding"]
    assert (dev.work / SPELLS).is_file() and (admin.work / SPELLS).is_file()

    text = (dev.work / SPELLS).read_bytes() + b"\n-- editado pelo dev\n"
    (dev.work / SPELLS).write_bytes(text)
    code, out, _ = dev.tsm("publish", "--all", "-m", "edição do dev")
    assert "publicado: r2" in out
    code, out, _ = admin.tsm("pull", "--wait", "60")
    assert (admin.work / SPELLS).read_bytes() == text
    hist = admin.json("history")
    assert hist[0]["user"] == "Dev" and hist[0]["message"] == "edição do dev"
    assert dev.json("bind", "--project", "demo")["initialized"]  # só atualiza a conexão


# ---------------------------------------------------------------- novo dispositivo de usuário existente


def test_new_device_waits_for_approval(srv, pcs):
    admin, second = pcs("admin", 1), pcs("dev-pc2", 3)
    user_id = world["dev"]["user_id"]
    inv = admin.json("admin", "invite", "create", "--project", "demo", "--for-user", user_id)
    result: dict = {}

    def enroll() -> None:
        result["r"] = second.tsm("enroll", "--manager", second.url, "--invite", inv["code"],
                                 "--wait", "90", "--json", expect=None)

    t = threading.Thread(target=enroll)
    t.start()

    def pending():
        return [r for r in admin.json("admin", "requests", "list")
                if r["user"]["id"] == user_id]

    wait_until(lambda: bool(pending()), 60, 0.5, "solicitação do segundo dispositivo")
    req = pending()[0]["device"]
    admin.tsm("admin", "requests", "approve", req["id"], "--fingerprint", req["fingerprint"])
    t.join(120)
    code, out, err = result["r"]
    assert code == EXIT_OK, err
    res = json.loads(out)
    assert res["approved"] and res["user_id"] == user_id
    assert pcs("dev", 2).json("whoami")["device"]["status"] == "active"


# ---------------------------------------------------------------- revogação


def test_revocation_exit_code(srv, pcs):
    admin, dev = pcs("admin", 1), pcs("dev", 2)
    out = admin.tsm("admin", "devices", "revoke", world["dev"]["device_id"])[1]
    assert "revogado" in out
    code, _, err = dev.tsm("history", expect=None)
    assert code == EXIT_IDENTITY and "identidade recusada" in err
    assert dev.tsm("whoami", expect=None)[0] == EXIT_IDENTITY
    assert (Home(dev.home).refused_file).is_file()


# ---------------------------------------------------------------- config SSH lida pelo ssh


def test_generated_ssh_config_is_read_by_openssh(tmp_path, srv):
    home = Home(tmp_path / "home")
    host_key = (srv.tmp / "hostkey" / "ssh_host_ed25519_key.pub").read_text().strip()
    rules = {"allow": [], "ignore": []}
    conn = parse_connection({
        "server_id": "s-1", "project_id": "demo", "binding_id": "b-0123456789abcdef0123",
        "device_id": "d-1", "transport": "ssh",
        "ssh": {"host": "192.0.2.10", "port": 2222, "user": "tsm-d-0123456789ab",
                "host_keys": [host_key]},
        "paths": {"workspace": "/srv/ts/projects/demo/workspaces/tsm-d-0123456789ab/tree",
                  "shared": "/srv/ts/projects/demo/shared"},
        "workspace_group": "tsm-ws", "rules": rules,
        "rules_digest": rules_digest(ProjectRules.from_dict(rules))},
        server_id="s-1", device_id="d-1")
    write_ssh_files(home, [conn])
    ssh = KEYGEN.parent / ("ssh.exe" if KEYGEN.suffix == ".exe" else "ssh")
    r = subprocess.run([str(ssh), "-G", conn.alias], env=ssh_keygen_env(home.ssh_home),
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    opts: dict[str, list[str]] = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition(" ")
        opts.setdefault(k.lower(), []).append(v)
    assert opts["hostname"] == ["192.0.2.10"] and opts["port"] == ["2222"]
    assert opts["user"] == ["tsm-d-0123456789ab"] and opts["hostkeyalias"] == [conn.alias]
    assert opts["batchmode"] == ["yes"] and opts["stricthostkeychecking"][0] in ("true", "yes")
    assert opts["identityfile"][0].endswith("/.ssh/id_ed25519")
    assert opts["userknownhostsfile"][0].endswith("/.ssh/known_hosts")
    assert opts["globalknownhostsfile"] == ["/dev/null"]
    assert opts["passwordauthentication"] == ["no"]
    assert opts["forwardagent"] == ["no"]


# ---------------------------------------------------------------- nada fora do <home>


def _snapshot(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        out[rel] = p.read_bytes().hex() if p.is_file() else f"dir {p.stat().st_mtime_ns}"
    out["."] = f"dir {root.stat().st_mtime_ns}"
    return out


def test_tsm_writes_only_under_home_local_and_cache(srv, pcs, tmp_path):
    admin = pcs("admin", 1)
    sentinel = tmp_path / "sentinela"
    dirs = {k: sentinel / k for k in ("tmp", "home", "profile", "appdata", "local", "cwd")}
    for d in dirs.values():
        d.mkdir(parents=True)
        (d / "x.txt").write_text("intocado")
    env = {**os.environ, "TMP": str(dirs["tmp"]), "TEMP": str(dirs["tmp"]),
           "HOME": str(dirs["home"]), "USERPROFILE": str(dirs["profile"]),
           "APPDATA": str(dirs["appdata"]), "LOCALAPPDATA": str(dirs["local"])}
    env.pop("TSM_HOME", None)
    before = _snapshot(sentinel)
    home = tmp_path / "pc" / "home"
    work = tmp_path / "pc" / "work"

    def tsm(*args: str, ok: tuple[int, ...] = (0,)) -> str:
        r = subprocess.run([sys.executable, "-m", "tsm_client", "--home", str(home), *args],
                           env=env, cwd=dirs["cwd"], capture_output=True, text=True,
                           encoding="utf-8", timeout=600)
        assert r.returncode in ok, f"{args}: {r.returncode}\n{r.stdout}{r.stderr}"
        return r.stdout

    inv = admin.json("admin", "invite", "create", "--project", "demo")
    res = json.loads(tsm("enroll", "--manager", f"http://127.0.0.1:{srv.port}", "--invite",
                         inv["code"], "--name", "Isolado", "--json"))
    tsm("whoami")
    admin.tsm("admin", "requests", "approve", res["device_id"], "--fingerprint",
              res["fingerprint"])
    cfg = json.loads((home / "config.json").read_text("utf-8"))
    cfg["mutagen"]["executable"] = str(pins.executable_path(pins.find_tools_root(REPO_ROOT)))
    (home / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    try:
        tsm("bind", "--project", "demo", "--local", str(work))
        tsm("logout")
    finally:
        tsm("teardown", "--stop-daemon", ok=(0, 1, 2, 3, 5, 6))
    assert (work / SPELLS).is_file()
    assert _snapshot(sentinel) == before


def test_url_policy_by_tsm(pcs, tmp_path):
    pc = Pc(tmp_path / "x", 9, pcs("admin", 1).srv)
    code, _, err = pc.tsm("enroll", "--manager", "http://192.0.2.1:8740", "--invite",
                          "tsm-inv-x", expect=None)
    assert code == EXIT_CONFIG and "loopback" in err
    assert not pc.home.exists()
