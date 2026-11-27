"""Rate limit das rotas ``/auth`` com relógio monotônico falso, e auditoria das recusas."""

from __future__ import annotations

import pytest

from tests.unit.api_env import ApiEnv, fingerprint
from tsm_common import protocol as P
from tsm_manager.identity.ratelimit import RefusalAudit


@pytest.fixture
def env(tmp_path, clock, rng):
    e = ApiEnv(tmp_path, clock, rng, real_limits=True)
    yield e
    e.close()


def challenge(env, headers=None):
    return env.client.post("/auth/challenge", headers=headers or {},
                           json={"purpose": "login", "fingerprint": fingerprint(1)})


def refusals(env):
    return [e for e in env.audit() if e["event"] == "rate_limited"]


def test_twenty_requests_per_minute_then_429(env):
    for _ in range(20):
        assert challenge(env).status_code == 200
    r = challenge(env)
    assert r.status_code == 429 and r.json()["status"] == P.RATE_LIMITED
    assert r.headers["Retry-After"] == "3"  # 20 por minuto: uma ficha a cada 3 s
    env.mono.advance(3)
    assert challenge(env).status_code == 200


def test_proxy_headers_are_ignored(env):
    for i in range(20):
        assert challenge(env, {"X-Forwarded-For": f"10.0.0.{i}",
                               "X-Real-IP": f"10.1.0.{i}"}).status_code == 200
    assert challenge(env, {"X-Forwarded-For": "10.9.9.9"}).status_code == 429


@pytest.mark.parametrize("route, body", [
    ("/auth/verify", {"challenge_id": "nada", "signature": "x"}),
    ("/auth/verify", None),
    ("/auth/register", {"invite": "tsm-inv-" + "a" * 26, "device_name": "pc",
                        "challenge_id": "nada", "signature": "x"}),
])
def test_five_failures_block_every_auth_route(env, route, body):
    for _ in range(5):
        assert env.client.post(route, json=body).status_code in (401, 422)
    r = challenge(env)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) == 12  # 5 por minuto: uma ficha a cada 12 s
    env.mono.advance(12)
    assert challenge(env).status_code == 200


def test_successful_login_does_not_count_as_failure(env):
    env.bootstrap_admin()            # 4 requisições, nenhuma falha
    for _ in range(5):
        env.login(1)                 # 10 requisições, nenhuma falha
    for _ in range(4):               # 4 falhas: ainda abaixo do limite de 5
        env.client.post("/auth/verify", json={"challenge_id": "x", "signature": "y"})
    assert challenge(env).status_code == 200


def test_refusals_are_audited_aggregated(env):
    for _ in range(20):
        challenge(env)
    for _ in range(6):
        assert challenge(env).status_code == 429
    events = refusals(env)
    assert len(events) == 1
    assert events[0]["ip"] == "testclient" and events[0]["route_class"] == "auth"
    assert events[0]["count"] == 1
    env.mono.advance(60)
    for _ in range(20):
        challenge(env)
    assert challenge(env).status_code == 429
    events = refusals(env)
    assert len(events) == 2 and events[1]["count"] == 6  # 5 da janela anterior + esta


def test_refusal_audit_limits_keys():
    written = []
    now = [0.0]
    audit = RefusalAudit(lambda ip, cls, n: written.append((ip, cls, n)),
                         clock=lambda: now[0], max_keys=2)
    audit.refused("a", "auth")
    audit.refused("b", "auth")
    audit.refused("c", "auth")      # "a" sai
    audit.refused("a", "auth")      # volta como novo, registrado na hora
    audit.refused("c", "auth")      # dentro da janela: só conta
    assert written == [("a", "auth", 1), ("b", "auth", 1), ("c", "auth", 1),
                       ("a", "auth", 1)]
    now[0] = 61
    audit.refused("c", "auth")
    assert written[-1] == ("c", "auth", 2)
