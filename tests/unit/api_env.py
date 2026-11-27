"""Manager ``version: 2`` no processo do teste, para os unitários da API.

Banco real (SQLite em ``tmp_path``), verificador de assinatura, relógio e aleatórios falsos
(``identity_fakes``), ``LocalProvisioner`` em ``tmp_path`` e o projeto ``demo`` sobre Git e
Store em memória (``manager_fakes``). Nenhum subprocesso, rede ou Git real.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from tests.conftest import REPO_ROOT
from tests.unit.identity_fakes import SERVER_ID, T0, FakeVerifier, fake_key
from tests.unit.manager_fakes import FakeGit, FakeStore
from tsm_common.authmsg import AuthMessage, parse_expires
from tsm_common.sshkeys import parse_public_key
from tsm_manager.api import create_app
from tsm_manager.api_identity import refusal_writer
from tsm_manager.config import load_manager_config
from tsm_manager.db import Database, upgrade
from tsm_manager.identity import invites
from tsm_manager.identity.base import Actor
from tsm_manager.identity.ratelimit import Rate, RateLimiter, RefusalAudit
from tsm_manager.project import ProjectService
from tsm_manager.services import Manager

DEMO = REPO_ROOT / "examples" / "demo-project"
HOST_KEY = fake_key(999)


class FakeMonotonic:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def write_v2_config(tmp_path: Path, **extra: Any) -> Path:
    keygen = str((tmp_path / "bin" / "ssh-keygen").resolve())
    data = {"version": 2, "root": "srv", "shared_group": "tsm-readers",
            "workspace_group": "tsm-ws", "provisioner": {"mode": "local"},
            "auth": {"ssh_keygen": keygen},
            "projects": [{"id": "demo", "rules": {"allow": ["data/"]}}, {"id": "outro"}]}
    data.update(extra)
    p = tmp_path / "manager.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def key_line(n: int) -> str:
    return parse_public_key(fake_key(n)).openssh


def fingerprint(n: int) -> str:
    return parse_public_key(fake_key(n)).fingerprint


class ApiEnv:
    def __init__(self, tmp_path: Path, clock, rng, *, provisioner=None,
                 config: dict[str, Any] | None = None, real_limits: bool = False) -> None:
        self.clock = clock
        self.verifier = FakeVerifier()
        cfg = load_manager_config(write_v2_config(tmp_path, **(config or {})))
        self.db = Database(cfg.database)
        upgrade(self.db, clock=lambda: T0, new_id=lambda: SERVER_ID)
        self.manager = Manager(cfg, db=self.db, verifier=self.verifier, clock=clock,
                               random=rng, provisioner=provisioner)
        self.ids = self.manager.identity
        self.ids.host_keys = (HOST_KEY,)
        self.ctx = self.ids.ctx
        svc = self.manager.projects["demo"]
        self.git_events: list = []
        fake = ProjectService(svc.project, svc.layout, git=FakeGit(self.git_events),
                              store=FakeStore(self.git_events), bindings=svc.bindings,
                              lock_timeout=5)
        assert fake.init_project(DEMO).status == "published"
        self.manager.projects["demo"] = fake
        self.mono = FakeMonotonic()
        # Os cenários fazem muitos cadastros; só o teste do rate limit usa os limites reais.
        self.limiter = RateLimiter(clock=self.mono) if real_limits else RateLimiter(
            classes={"auth": Rate(100_000, 60)}, failures=Rate(100_000, 60), clock=self.mono)
        self.refusals = RefusalAudit(refusal_writer(self.ids), clock=self.mono)
        self.client = TestClient(create_app(self.manager, limiter=self.limiter,
                                            refusals=self.refusals))

    def close(self) -> None:
        self.client.close()
        self.manager.close()

    # ------------------------------------------------------------ lado do Client

    def challenge(self, purpose: str, n: int) -> dict[str, Any]:
        body = ({"purpose": purpose, "public_key": fake_key(n, "pc")} if purpose == "register"
                else {"purpose": purpose, "fingerprint": fingerprint(n)})
        r = self.client.post("/auth/challenge", json=body)
        assert r.status_code == 200, r.text
        return r.json()

    def sign(self, response: dict[str, Any], n: int, *, purpose: str | None = None,
             server_id: str | None = None) -> str:
        message = AuthMessage(server_id or response["server_id"],
                              purpose or response["purpose"], response["challenge_id"],
                              response["nonce"], fingerprint(n),
                              parse_expires(response["expires_at"])).to_bytes()
        return FakeVerifier.sign(key_line(n), message)

    def register(self, code: str, n: int, *, name: str | None = "Fulano",
                 device: str = "pc"):
        ch = self.challenge("register", n)
        body = {"invite": code, "device_name": device, "challenge_id": ch["challenge_id"],
                "signature": self.sign(ch, n)}
        if name is not None:
            body["display_name"] = name
        return self.client.post("/auth/register", json=body)

    def login(self, n: int) -> str:
        ch = self.challenge("login", n)
        r = self.client.post("/auth/verify", json={"challenge_id": ch["challenge_id"],
                                                    "signature": self.sign(ch, n)})
        assert r.status_code == 200, r.text
        return r.json()["token"]

    # ------------------------------------------------------------ cenário

    def bootstrap_admin(self, n: int = 1) -> tuple[str, str]:
        code = invites.create_bootstrap(self.ctx, Actor.operator(), project_id="demo").code
        r = self.register(code, n, name="Admin")
        assert r.status_code == 201, r.text
        device = r.json()["device_id"]
        self.ids.provisioning.approve(Actor.operator(), device, fingerprint(n))
        return self.login(n), device

    def invite(self, admin_token: str, **body: Any) -> str:
        r = self.client.post("/admin/invites", json={"project": "demo", **body},
                             headers=bearer(admin_token))
        assert r.status_code == 201, r.text
        return r.json()["code"]

    def pending_device(self, admin_token: str, n: int, **invite: Any) -> str:
        r = self.register(self.invite(admin_token, **invite), n, name=f"Dev {n}",
                          device=f"pc{n}")
        assert r.status_code == 201, r.text
        return r.json()["device_id"]

    def developer(self, admin_token: str, n: int, **invite: Any) -> tuple[str, str]:
        device = self.pending_device(admin_token, n, **invite)
        r = self.client.post(f"/admin/requests/{device}/approve",
                             json={"fingerprint": fingerprint(n)},
                             headers=bearer(admin_token))
        assert r.status_code == 200, r.text
        return self.login(n), device

    def binding_of(self, device: str, project: str = "demo") -> str:
        with self.ids.repo.read() as tx:
            return tx.binding_for(project, device).id

    def audit(self) -> list[dict[str, Any]]:
        with self.db.read() as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
        return [{"event": r["event"], **json.loads(r["fields"])} for r in rows]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
