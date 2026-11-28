"""Sessão do Client: login preguiçoso, repetição única, marcador de recusa e HTTP."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from tests.unit.client_fakes import (
    DEVICE_ID,
    SERVER_ID,
    TOKEN,
    TOKEN2,
    FakeKeygen,
    HeaderAuth,
    RecordingAcl,
    ScriptedTransport,
    challenge_body,
    fingerprint,
    session_body,
)
from tsm_client.adapters.manager import (
    ManagerClient,
    ManagerProtocolError,
    ManagerUnavailable,
    ManagerUrlError,
    RateLimited,
    UrllibTransport,
    check_url,
)
from tsm_client.home import Home
from tsm_client.identity import ChallengeSigner, DeviceKey, ServerMismatch
from tsm_client.login import (
    IdentityPending,
    IdentityRefused,
    ManagerRefused,
    SessionAuth,
    SessionError,
    SessionStore,
    refusal,
)
from tsm_common.authmsg import AuthMessage, parse_expires

URL = "http://127.0.0.1:8740"


@pytest.fixture
def home(tmp_path) -> Home:
    h = Home(tmp_path / "home")
    h.state.mkdir(parents=True)
    return h


@pytest.fixture
def keygen() -> FakeKeygen:
    return FakeKeygen(1)


def make(home: Home, keygen: FakeKeygen, transport: ScriptedTransport, *,
         honor_refused: bool = True) -> tuple[ManagerClient, SessionAuth, SessionStore]:
    acl = RecordingAcl()
    store = SessionStore(home, acl)
    key = DeviceKey(home.key_path, "ssh-ed25519 x", fingerprint(1))
    auth = SessionAuth(store, ChallengeSigner(keygen, key), server_id=SERVER_ID,
                       device_id=DEVICE_ID, honor_refused=honor_refused)
    return ManagerClient(URL, auth, transport=transport), auth, store


def cache(store: SessionStore, scope: str = "full", token: str = TOKEN) -> None:
    store.save({"token": token, "scope": scope, "expires_at": "x", "server_id": SERVER_ID,
                "device_id": DEVICE_ID})


# ---------------------------------------------------------------- login


def test_lazy_login_signs_canonical_message_and_saves_session(home, keygen):
    t = ScriptedTransport().login_ok().on("GET", "/me", 200, {"ok": True})
    client, auth, store = make(home, keygen, t)
    assert client.me().ok
    assert t.paths() == ["POST /auth/challenge", "POST /auth/verify", "GET /me"]
    assert t.requests[0]["body"] == {"purpose": "login", "fingerprint": fingerprint(1)}
    assert "Authorization" not in t.requests[0]["headers"]
    ch = challenge_body()
    expected = AuthMessage(SERVER_ID, "login", "c-1", ch["nonce"], fingerprint(1),
                           parse_expires(ch["expires_at"])).to_bytes()
    assert keygen.signed == [expected]
    assert t.requests[2]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    saved = json.loads(home.session_file.read_text("utf-8"))
    assert saved["token"] == TOKEN and saved["scope"] == "full"
    assert store.acl.files == [home.session_file]


def test_cached_session_is_reused(home, keygen):
    t = ScriptedTransport().on("GET", "/me", 200, {})
    client, _, store = make(home, keygen, t)
    cache(store)
    client.me()
    assert t.paths() == ["GET /me"]


def test_cached_session_of_other_server_is_ignored(home, keygen):
    t = ScriptedTransport().login_ok(token=TOKEN2).on("GET", "/me", 200, {})
    client, _, store = make(home, keygen, t)
    store.save({"token": TOKEN, "scope": "full", "server_id": "outro", "device_id": DEVICE_ID})
    client.me()
    assert t.requests[-1]["headers"]["Authorization"] == f"Bearer {TOKEN2}"


def test_server_id_mismatch_refused_before_signing(home, keygen):
    t = ScriptedTransport().on("POST", "/auth/challenge", 200,
                               challenge_body(server_id="outro-manager"))
    client, _, _ = make(home, keygen, t)
    with pytest.raises(ServerMismatch, match="outro server_id"):
        client.me()
    assert keygen.signed == []


def test_login_refused_marks_and_blocks_next_attempts(home, keygen):
    t = (ScriptedTransport().on("POST", "/auth/challenge", 200, challenge_body())
         .on("POST", "/auth/verify", 401, {"status": "unauthorized"}))
    client, _, store = make(home, keygen, t)
    with pytest.raises(IdentityRefused):
        client.me()
    assert store.refused()
    n = len(t.requests)
    with pytest.raises(IdentityRefused):
        client.me()
    assert len(t.requests) == n  # nenhuma tentativa nova de login


def test_whoami_style_ignores_marker_and_clears_it(home, keygen):
    t = ScriptedTransport().login_ok().on("GET", "/me", 200, {})
    client, _, store = make(home, keygen, t, honor_refused=False)
    store.mark_refused("teste")
    client.me()
    assert store.refused() is None


@pytest.mark.parametrize("body", [{"token": "x", "scope": "full", "device_id": DEVICE_ID},
                                  {"token": TOKEN, "scope": "root", "device_id": DEVICE_ID},
                                  session_body(device_id="outro")])
def test_malformed_session_response(home, keygen, body):
    t = (ScriptedTransport().on("POST", "/auth/challenge", 200, challenge_body())
         .on("POST", "/auth/verify", 200, body))
    client, _, _ = make(home, keygen, t)
    with pytest.raises(ManagerProtocolError):
        client.me()


def test_malformed_challenge(home, keygen):
    t = ScriptedTransport().on("POST", "/auth/challenge", 200,
                               {**challenge_body(), "nonce": "curto"})
    client, _, _ = make(home, keygen, t)
    with pytest.raises(ManagerProtocolError, match="desafio"):
        client.me()


def test_challenge_refused(home, keygen):
    t = ScriptedTransport().on("POST", "/auth/challenge", 422, {"status": "invalid_request",
                                                                 "message": "fingerprint"})
    client, _, _ = make(home, keygen, t)
    with pytest.raises(ManagerRefused, match="invalid_request"):
        client.me()


# ---------------------------------------------------------------- repetição


def test_session_expired_relogs_and_repeats_same_body_once(home, keygen):
    body = {"idempotency_key": "k-1", "changes": []}
    t = (ScriptedTransport().login_ok(token=TOKEN2)
         .on("POST", "/projects/demo/bindings/b-1/publish", 401, {"status": "session_expired"})
         .on("POST", "/projects/demo/bindings/b-1/publish", 200, {"status": "published"}))
    client, _, store = make(home, keygen, t)
    cache(store)
    r = client.publish("demo", "b-1", body)
    assert r.status == "published"
    pubs = [x for x in t.requests if x["path"].endswith("/publish")]
    assert [p["body"] for p in pubs] == [body, body]
    assert [p["headers"]["Authorization"] for p in pubs] == [f"Bearer {TOKEN}",
                                                            f"Bearer {TOKEN2}"]


def test_session_expired_twice_is_not_repeated_again(home, keygen):
    t = (ScriptedTransport().login_ok(token=TOKEN2)
         .on("GET", "/me", 401, {"status": "session_expired"}))
    client, _, store = make(home, keygen, t)
    cache(store)
    with pytest.raises(SessionError):
        client.me()
    assert [r["path"] for r in t.requests].count("/me") == 2


def test_unauthorized_drops_token_without_new_login(home, keygen):
    t = ScriptedTransport().login_ok().on("GET", "/me", 401, {"status": "unauthorized"})
    client, _, store = make(home, keygen, t)
    cache(store)
    with pytest.raises(IdentityRefused):
        client.me()
    assert t.paths() == ["GET /me"]
    assert store.load() is None and store.refused() is None


def test_pending_cached_session_relogs_once(home, keygen):
    t = (ScriptedTransport().login_ok(scope="full", token=TOKEN2)
         .on("GET", "/connection/config", 403, {"status": "pending_approval"})
         .on("GET", "/connection/config", 200, {"ok": 1}))
    client, _, store = make(home, keygen, t)
    cache(store, scope="pending")
    assert client.connection_config("demo").ok
    assert t.paths() == ["GET /connection/config", "POST /auth/challenge",
                         "POST /auth/verify", "GET /connection/config"]


def test_still_pending_after_fresh_login(home, keygen):
    t = (ScriptedTransport().login_ok(scope="pending")
         .on("GET", "/connection/config", 403, {"status": "pending_approval"}))
    client, _, _ = make(home, keygen, t)
    with pytest.raises(IdentityPending):
        client.connection_config("demo")
    assert [r["path"] for r in t.requests].count("/connection/config") == 1


def test_ensure_full(home, keygen):
    t = ScriptedTransport().login_ok(scope="full", token=TOKEN2)
    client, auth, store = make(home, keygen, t)
    cache(store, scope="pending")
    auth.ensure_full(client)
    assert auth.scope == "full"
    t2 = ScriptedTransport().login_ok(scope="pending")
    client2, auth2, _ = make(home, keygen, t2)
    auth2.drop()
    with pytest.raises(IdentityPending):
        auth2.ensure_full(client2)


def test_other_refusals_pass_through(home, keygen):
    t = ScriptedTransport().on("GET", "/projects/demo/audit", 403, {"status": "forbidden"})
    client, _, store = make(home, keygen, t)
    cache(store)
    assert client.audit("demo").status == "forbidden"


def test_refusal_mapping():
    from tsm_client.adapters.manager import Response

    assert isinstance(refusal(Response(401, {"status": "unauthorized"}), "x"), IdentityRefused)
    assert isinstance(refusal(Response(403, {"status": "pending_approval"}), "x"),
                      IdentityPending)
    err = refusal(Response(409, {"status": "fingerprint_mismatch", "message": "m"}), "aprovar")
    assert isinstance(err, ManagerRefused) and err.status == "fingerprint_mismatch"


def test_token_never_in_error_messages(home, keygen):
    t = ScriptedTransport().on("GET", "/me", 401, {"status": "unauthorized"})
    client, _, store = make(home, keygen, t)
    cache(store)
    with pytest.raises(IdentityRefused) as info:
        client.me()
    assert TOKEN not in str(info.value)


def test_corrupt_session_file_is_discarded(home, keygen):
    home.session_file.write_text("{lixo")
    store = SessionStore(home, RecordingAcl())
    assert store.load() is None and not home.session_file.exists()
    home.session_file.write_text(json.dumps({"token": "abc", "scope": "full"}))
    assert store.load() is None


# ---------------------------------------------------------------- HTTP


def test_rate_limited():
    t = ScriptedTransport().on("POST", "/auth/challenge", 429, {"status": "rate_limited"},
                               {"Retry-After": "12"})
    with pytest.raises(RateLimited, match="12 s") as info:
        ManagerClient(URL, None, transport=t).challenge({})
    assert info.value.retry_after == 12
    assert isinstance(info.value, ManagerUnavailable)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8740", "http://localhost:1/",
                                 "http://[::1]:8740", "http://127.9.9.9",
                                 "https://ts.example.net", "https://10.0.0.1:443/api"])
def test_accepted_urls(url):
    assert check_url(url) == url.rstrip("/")


@pytest.mark.parametrize("url", ["", "ftp://127.0.0.1", "http://ts.example.net",
                                 "http://10.0.0.1:8740", "http://user:pw@127.0.0.1",
                                 "https://h?x=1", "https://h#f", "http://", "https://h:99999",
                                 "127.0.0.1:8740"])
def test_refused_urls(url):
    with pytest.raises(ManagerUrlError):
        check_url(url)


def test_client_without_session_sends_no_authorization():
    t = ScriptedTransport().on("GET", "/projects/demo", 401, {"status": "unauthorized"})
    r = ManagerClient(URL, transport=t).project("demo")
    assert r.http_status == 401
    assert "Authorization" not in t.requests[0]["headers"]


def test_client_does_not_accept_a_fixed_token():
    with pytest.raises(TypeError):
        ManagerClient(URL, "segredo", transport=ScriptedTransport())


def test_network_failure():
    t = ScriptedTransport()
    t.fail = ConnectionRefusedError("recusado")
    with pytest.raises(ManagerUnavailable, match="inacessível"):
        ManagerClient(URL, None, transport=t).health()


class _Redirect(BaseHTTPRequestHandler):
    seen: ClassVar[list[tuple[str, str | None]]] = []

    def do_GET(self):
        self.seen.append((self.path, self.headers.get("Authorization")))
        if self.path == "/projects/demo":
            self.send_response(302)
            self.send_header("Location", "/outro")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


def test_redirect_is_not_followed():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        _Redirect.seen = []
        client = ManagerClient(f"http://127.0.0.1:{srv.server_address[1]}", HeaderAuth("segredo"),
                               transport=UrllibTransport(), timeout=5)
        with pytest.raises(ManagerProtocolError):  # 302 sem corpo JSON, sem seguir
            client.project("demo")
        assert [p for p, _ in _Redirect.seen] == ["/projects/demo"]
    finally:
        srv.shutdown()
