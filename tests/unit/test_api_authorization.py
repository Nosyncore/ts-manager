"""Matriz de autorização da API, célula a célula.

Um mundo por módulo com um principal de cada tipo; cada célula é uma requisição real pela
API (``TestClient``) e confere código HTTP e status. As rotas que mudam estado são chamadas
com alvos inexistentes ou corpos vazios: o admin passa da autorização e recebe a recusa do
domínio (404/422), o que prova que a autorização deixou passar.
"""

from __future__ import annotations

import pytest

from tests.unit.api_env import ApiEnv, bearer, fingerprint
from tests.unit.identity_fakes import FakeClock, FakeRandom
from tsm_common import protocol as P
from tsm_manager.db.connection import ts
from tsm_manager.db.repository import Session
from tsm_manager.identity import accounts
from tsm_manager.identity.base import Actor
from tsm_manager.identity.sessions import token_hash

DENIED = ("anon", "malformed", "unknown", "expired", "blocked", "revoked")
PENDING = ("pending", "provisioning")
FULL = ("dev_owner", "dev_member", "dev_outsider", "admin_bound", "admin_unbound")
KINDS = DENIED + PENDING + FULL
LOGIN_KEYS = {"admin_bound": 1, "dev_owner": 2, "dev_member": 3, "dev_outsider": 4,
              "admin_unbound": 5, "pending": 6, "provisioning": 7}


class World:
    def __init__(self, tmp_path) -> None:
        self.clock = FakeClock()
        self.env = env = ApiEnv(tmp_path, self.clock, FakeRandom())
        env.manager.projects["outro"].layout.workspaces.mkdir(parents=True)  # sem init
        admin, self.admin_device = env.bootstrap_admin(1)
        owner, self.owner_device = env.developer(admin, 2)
        owner_user = env.client.get("/me", headers=bearer(owner)).json()["user"]["id"]
        member, _ = env.developer(admin, 3, kind="new_device", user_id=owner_user,
                                  project="outro")
        outsider, _ = env.developer(admin, 4, project="outro")
        admin_unbound, _ = env.developer(admin, 5, project="outro", role="admin")
        env.pending_device(admin, 6)
        pending = env.login(6)
        prov_device = env.pending_device(admin, 7)
        accounts.begin_approval(env.ctx, Actor.operator(), prov_device,
                                fingerprint=fingerprint(7))
        provisioning = env.login(7)
        blocked, _ = env.developer(admin, 8)
        blocked_user = env.client.get("/me", headers=bearer(blocked)).json()["user"]["id"]
        assert env.client.post(f"/admin/users/{blocked_user}/block",
                               headers=bearer(admin)).status_code == 200
        revoked, revoked_device = env.developer(admin, 9)
        assert env.client.post(f"/admin/devices/{revoked_device}/revoke",
                               headers=bearer(admin)).status_code == 200
        expired = "tsm-s-" + "E" * 43
        with env.ids.repo.write() as tx:
            now = ts(self.clock())
            tx.insert_session(Session("s-expired", token_hash(expired), self.owner_device,
                                      "full", now, now))
        self.owner_binding = env.binding_of(self.owner_device)
        self.headers = {
            "anon": {}, "malformed": {"Authorization": "Basic eA=="},
            "unknown": bearer("tsm-s-" + "U" * 43), "expired": bearer(expired),
            "blocked": bearer(blocked), "revoked": bearer(revoked),
            "pending": bearer(pending), "provisioning": bearer(provisioning),
            "dev_owner": bearer(owner), "dev_member": bearer(member),
            "dev_outsider": bearer(outsider), "admin_bound": bearer(admin),
            "admin_unbound": bearer(admin_unbound),
        }


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    w = World(tmp_path_factory.mktemp("matrix"))
    yield w
    w.env.close()


def _full(owner=None, member=None, outsider=None, admin_bound=None, admin_unbound=None,
          *, devs=None, admins=None):
    """Resultado por principal de sessão ``full``."""
    devs = devs or {}
    out = {"dev_owner": owner, "dev_member": member, "dev_outsider": outsider,
           "admin_bound": admin_bound, "admin_unbound": admin_unbound}
    if devs:
        out.update(dict.fromkeys(("dev_owner", "dev_member", "dev_outsider"), devs))
    if admins:
        out.update(dict.fromkeys(("admin_bound", "admin_unbound"), admins))
    return out


NOT_FOUND = 404
FORBIDDEN = 403

ROUTES = {
    "me": ("get", "/me", None, _full(200, 200, 200, 200, 200)),
    "connection": ("get", "/connection/config?project=demo", None,
                   _full(200, NOT_FOUND, NOT_FOUND, 200, NOT_FOUND)),
    "project_info": ("get", "/projects/demo", None, _full(200, 200, NOT_FOUND, 200, 200)),
    "revisions": ("get", "/projects/demo/revisions", None,
                  _full(200, 200, NOT_FOUND, 200, 200)),
    "revision": ("get", "/projects/demo/revisions/1", None,
                 _full(200, 200, NOT_FOUND, 200, 200)),
    "publish": ("post", "/projects/demo/bindings/{owner_binding}/publish", {},
                _full(422, FORBIDDEN, NOT_FOUND, FORBIDDEN, FORBIDDEN)),
    "rollback": ("post", "/projects/demo/rollback", {},
                 _full(FORBIDDEN, FORBIDDEN, NOT_FOUND, 422, 422)),
    "audit": ("get", "/projects/demo/audit", None,
              _full(FORBIDDEN, FORBIDDEN, NOT_FOUND, 200, 200)),
    "invites_list": ("get", "/admin/invites", None, _full(devs=FORBIDDEN, admins=200)),
    "invites_create": ("post", "/admin/invites", {"project": "demo"},
                       _full(devs=FORBIDDEN, admins=201)),
    "invites_revoke": ("post", "/admin/invites/nada/revoke", None,
                       _full(devs=FORBIDDEN, admins=NOT_FOUND)),
    "requests_list": ("get", "/admin/requests", None, _full(devs=FORBIDDEN, admins=200)),
    "requests_approve": ("post", "/admin/requests/nada/approve",
                         {"fingerprint": "SHA256:x"}, _full(devs=FORBIDDEN, admins=NOT_FOUND)),
    "requests_reject": ("post", "/admin/requests/nada/reject", None,
                        _full(devs=FORBIDDEN, admins=NOT_FOUND)),
    "devices_list": ("get", "/admin/devices", None, _full(devs=FORBIDDEN, admins=200)),
    "devices_revoke": ("post", "/admin/devices/nada/revoke", None,
                       _full(devs=FORBIDDEN, admins=NOT_FOUND)),
    "users_list": ("get", "/admin/users", None, _full(devs=FORBIDDEN, admins=200)),
    "users_block": ("post", "/admin/users/nada/block", None,
                    _full(devs=FORBIDDEN, admins=NOT_FOUND)),
    "users_unblock": ("post", "/admin/users/nada/unblock", None,
                      _full(devs=FORBIDDEN, admins=NOT_FOUND)),
}


def expected(route: str, kind: str) -> tuple[int, str | None]:
    if kind in DENIED:
        return 401, P.SESSION_EXPIRED if kind == "expired" else P.UNAUTHORIZED
    if kind in PENDING:
        return (200, None) if route == "me" else (403, P.PENDING_APPROVAL)
    code = ROUTES[route][3][kind]
    return code, {403: P.FORBIDDEN, 404: P.NOT_FOUND}.get(code)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("route", list(ROUTES))
def test_cell(world, route, kind):
    method, path, body, _ = ROUTES[route]
    path = path.format(owner_binding=world.owner_binding)
    kwargs = {"headers": world.headers[kind]}
    if body is not None:
        kwargs["json"] = body
    r = getattr(world.env.client, method)(path, **kwargs)
    code, status = expected(route, kind)
    assert r.status_code == code, (route, kind, r.text)
    if status is not None:
        assert r.json()["status"] == status, (route, kind, r.text)
    if code == 401:
        assert r.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("kind", KINDS)
def test_logout_cell(world, kind):
    env = world.env
    if kind in LOGIN_KEYS:
        headers = bearer(env.login(LOGIN_KEYS[kind]))  # sessão nova: não derruba as do mundo
        assert env.client.post("/auth/logout", headers=headers).status_code == 200
        assert env.client.get("/me", headers=headers).status_code == 401
    else:
        r = env.client.post("/auth/logout", headers=world.headers[kind])
        assert r.status_code == 401


@pytest.mark.parametrize("kind", KINDS)
def test_public_auth_routes_ignore_the_session(world, kind):
    r = world.env.client.post("/auth/challenge", headers=world.headers[kind],
                              json={"purpose": "login", "fingerprint": fingerprint(2)})
    assert r.status_code == 200


def test_blocked_and_revoked_cannot_log_in_again(world):
    env = world.env
    for n in (8, 9):
        ch = env.challenge("login", n)
        r = env.client.post("/auth/verify", json={"challenge_id": ch["challenge_id"],
                                                   "signature": env.sign(ch, n)})
        assert r.status_code == 401
