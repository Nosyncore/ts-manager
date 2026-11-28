"""Recusas pelo ``tsm`` contra o Manager real: convites inválidos, acesso cruzado, operação
sem role, último admin, rate limit e um Manager com outro ``server_id`` na mesma URL.

Um Manager para o módulo (projetos ``demo`` e ``outro``); os cenários seguem em ordem e
dividem o estado. Cada PC tem ``<home>`` e endereço de loopback próprios: o rate limit conta
por endereço, e só o "sondador" (convites inválidos, 4 falhas) e o "insistente" (5 falhas e
o bloqueio) gastam fichas de falha. O bloqueio fica para o fim do módulo.
"""

from __future__ import annotations

import json
import re

import pytest
from tsm_client.cli import EXIT_IDENTITY, EXIT_OK, EXIT_REFUSED, EXIT_UNAVAILABLE
from tsm_client.home import Home
from tsm_client.identity import load_device_key

from tests.identity.conftest import Pc
from tests.integration.conftest import wait_until
from tests.manager.identity_http import Http
from tests.manager.server import Server

pytestmark = pytest.mark.integration

UNKNOWN_INVITE = "tsm-inv-" + "a" * 26  # formato válido, nunca emitido
world: dict = {}

ADMIN, DEV, OUTSIDER, PROBER, FLOODER, SWITCHER = 1, 2, 3, 4, 5, 6


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    s = Server(tmp_path_factory.mktemp("tsm-refusals"))
    s.cli("migrate")
    s.init_project("demo")
    s.init_project("outro")
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture(scope="module")
def pcs(srv, tmp_path_factory):
    base = tmp_path_factory.mktemp("pcs")
    made: dict[int, Pc] = {}

    def make(n: int) -> Pc:
        if n not in made:
            made[n] = Pc(base / f"pc{n}", n, srv)
        return made[n]

    return make


def fingerprint_of(pc: Pc) -> str:
    key = load_device_key(Home(pc.home))
    assert key is not None
    return key.fingerprint


def enroll(pc: Pc, code: str, name: str) -> dict:
    return pc.json("enroll", "--manager", pc.url, "--invite", code, "--name", name)


# ---------------------------------------------------------------- admin e developer


def test_admin_and_developer(srv, pcs):
    admin, dev = pcs(ADMIN), pcs(DEV)
    boot = json.loads(srv.cli("bootstrap-admin", "--project", "demo", "--json").stdout)
    res = enroll(admin, boot["code"], "Admin")
    srv.cli("requests", "approve", res["device_id"], "--fingerprint", res["fingerprint"])
    world["admin"] = admin.json("whoami")
    assert world["admin"]["user"]["role"] == "admin"

    inv = admin.json("admin", "invite", "create", "--project", "demo")
    res = enroll(dev, inv["code"], "Dev")
    admin.tsm("admin", "requests", "approve", res["device_id"], "--fingerprint",
              res["fingerprint"])
    world["dev"] = dev.json("whoami")
    world["dev_invite"] = inv["code"]
    assert world["dev"]["device"]["status"] == "active"


# ---------------------------------------------------------------- operação sem role


def test_developer_cannot_approve_or_block(pcs):
    admin, dev, outsider = pcs(ADMIN), pcs(DEV), pcs(OUTSIDER)
    inv = admin.json("admin", "invite", "create", "--project", "outro")
    req = enroll(outsider, inv["code"], "De Fora")

    code, _, err = dev.tsm("admin", "requests", "approve", req["device_id"], "--fingerprint",
                           req["fingerprint"], expect=None)
    assert code == EXIT_REFUSED and "forbidden" in err
    pending = {r["device"]["id"]: r["device"]["status"]
               for r in admin.json("admin", "requests", "list")}
    assert pending[req["device_id"]] == "pending"  # a tentativa não mudou nada

    code, _, err = dev.tsm("admin", "users", "block", world["admin"]["user"]["id"],
                           expect=None)
    assert code == EXIT_REFUSED and "forbidden" in err
    assert admin.json("whoami")["user"]["status"] == "active"

    admin.tsm("admin", "requests", "approve", req["device_id"], "--fingerprint",
              req["fingerprint"])
    world["outsider"] = outsider.json("whoami")


# ---------------------------------------------------------------- acesso cruzado


def test_bind_without_binding_in_project(pcs):
    outsider, dev = pcs(OUTSIDER), pcs(DEV)
    assert [b["project_id"] for b in world["outsider"]["bindings"]] == ["outro"]
    for pc, project in ((outsider, "demo"), (dev, "outro")):
        code, _, err = pc.tsm("bind", "--project", project, "--local", str(pc.work),
                              expect=None)
        assert code == EXIT_REFUSED and "not_found" in err, err
        home = Home(pc.home)
        assert json.loads(home.config_path.read_text("utf-8"))["bindings"] == []
        assert not list(home.state.glob("connections/*.json"))
        assert not pc.work.exists()


# ---------------------------------------------------------------- convites inválidos


def test_invalid_invites_give_the_same_generic_error(srv, pcs):
    admin, prober = pcs(ADMIN), pcs(PROBER)
    expiring = admin.json("admin", "invite", "create", "--project", "demo", "--ttl", "1")

    def state(invite_id: str) -> str:
        return next(i["state"] for i in admin.json("admin", "invite", "list")
                    if i["id"] == invite_id)

    revoked = admin.json("admin", "invite", "create", "--project", "demo")
    admin.tsm("admin", "invite", "revoke", revoked["id"])
    assert state(revoked["id"]) == "revoked"
    wait_until(lambda: state(expiring["id"]) == "expired", 15, 0.25, "convite expirado")

    before = len(srv.audit("register_refused"))
    errors = []
    for code in (world["dev_invite"], expiring["code"], revoked["code"], UNKNOWN_INVITE):
        exit_code, out, err = prober.tsm("enroll", "--manager", prober.url, "--invite", code,
                                         "--name", "Sondador", expect=None)
        assert exit_code == EXIT_REFUSED and out == "", (code, err)
        errors.append(err)
    assert len(set(errors)) == 1 and "invalid_invite" in errors[0], errors
    refused = srv.audit("register_refused")[before:]
    assert [(e["reason"], e["fingerprint"]) for e in refused] == \
        [("invalid_invite", fingerprint_of(prober))] * 4
    assert not Home(prober.home).config_path.exists()  # o <home> segue reutilizável

    inv = admin.json("admin", "invite", "create", "--project", "demo")
    assert enroll(prober, inv["code"], "Sondador")["status"] == "pending"


# ---------------------------------------------------------------- último admin


def test_last_admin_cannot_be_blocked_or_revoked(pcs):
    admin = pcs(ADMIN)
    me = world["admin"]
    for args in (("users", "block", me["user"]["id"]),
                 ("devices", "revoke", me["device"]["id"])):
        code, _, err = admin.tsm("admin", *args, expect=None)
        assert code == EXIT_REFUSED and "last_admin" in err, (args, err)
    who = admin.json("whoami")
    assert who["user"]["status"] == "active" and who["device"]["status"] == "active"
    devices = {d["id"]: d["status"] for d in admin.json("admin", "devices", "list")}
    assert devices[me["device"]["id"]] == "active"


# ---------------------------------------------------------------- rate limit (por último)


def test_rate_limit_by_tsm(srv, pcs):
    flooder, dev = pcs(FLOODER), pcs(DEV)
    for _ in range(5):  # 5 cadastros falhos esgotam as fichas de falha do endereço
        code, _, _ = flooder.tsm("enroll", "--manager", flooder.url, "--invite",
                                 UNKNOWN_INVITE, "--name", "Insistente", expect=None)
        assert code == EXIT_REFUSED
    code, _, err = flooder.tsm("enroll", "--manager", flooder.url, "--invite", UNKNOWN_INVITE,
                               "--name", "Insistente", expect=None)
    assert code == EXIT_UNAVAILABLE, err
    m = re.search(r"repita em (\d+) s", err)
    assert m and 1 <= int(m.group(1)) <= 12, err  # uma ficha de falha a cada 12 s
    events = [e for e in srv.audit("rate_limited") if e["ip"] == flooder.source]
    assert len(events) == 1 and events[0]["route_class"] == "auth"

    assert dev.tsm("logout")[0] == EXIT_OK  # outro endereço: login novo sem limite
    assert dev.json("whoami")["session"]["scope"] == "full"


# ---------------------------------------------------------------- outro Manager na mesma URL


def test_other_manager_on_the_same_url(tmp_path):
    """O ``tsm`` confere o ``server_id`` antes de assinar.

    Com sessão em cache (caracterização): o token vai ao outro Manager antes de qualquer
    conferência, o 401 apaga o token local e o ``tsm`` sai com 6; o token continua válido no
    Manager do cadastro até expirar.
    """
    a = Server(tmp_path / "a", projects=("demo",))
    b = Server(tmp_path / "b", projects=("demo",), port=a.port)
    a.cli("migrate")
    a.init_project("demo")
    b.cli("migrate")
    pc = Pc(tmp_path / "pc", SWITCHER, a)
    home = Home(pc.home)
    try:
        a.start()
        boot = json.loads(a.cli("bootstrap-admin", "--project", "demo", "--json").stdout)
        res = enroll(pc, boot["code"], "Admin")
        a.cli("requests", "approve", res["device_id"], "--fingerprint", res["fingerprint"])
        pc.tsm("whoami")
        pc.tsm("logout")

        # sem sessão em cache: recusa antes de assinar
        a.stop()
        b.start()
        code, _, err = pc.tsm("whoami", expect=None)
        assert code == EXIT_REFUSED and "outro server_id" in err, err
        assert not home.session_file.exists() and not home.refused_file.exists()
        challenges = b.rows("SELECT purpose, used_at FROM auth_challenges")
        assert challenges == [{"purpose": "login", "used_at": None}]
        assert b.rows("SELECT id FROM sessions") == []
        assert b.audit("auth_refused") == [] and b.audit("login") == []

        b.stop()
        a.start()
        assert pc.json("whoami")["device"]["status"] == "active"
        token = json.loads(home.session_file.read_text("utf-8"))["token"]

        # com sessão em cache: o token chega ao outro Manager
        a.stop()
        b.start()
        code, _, err = pc.tsm("whoami", expect=None)
        assert code == EXIT_IDENTITY, err
        assert not home.session_file.exists()
        assert b.rows("SELECT id FROM auth_challenges WHERE used_at IS NOT NULL") == []

        b.stop()
        a.start()
        assert Http(a.port).get("/me", token).status == 200  # ainda válido no Manager A
        assert pc.tsm("whoami")[0] == EXIT_OK  # login novo
    finally:
        a.stop()
        b.stop()
