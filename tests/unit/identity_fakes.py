"""Fakes do domínio de identidade: relógio, aleatórios e verificador de assinatura.

O repositório é o real, sobre SQLite em ``tmp_path``: as transições condicionais e a
concorrência são semântica do banco.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from datetime import UTC, datetime, timedelta

import pytest

from tsm_common.authmsg import NAMESPACE
from tsm_common.sshkeys import parse_public_key
from tsm_manager.db import Database, Repository, upgrade
from tsm_manager.db.connection import ts
from tsm_manager.db.repository import Binding, Device, Invite, User
from tsm_manager.identity.base import AuthSettings, IdentityContext

T0 = datetime(2026, 11, 26, 12, 0, 0, 250_000, tzinfo=UTC)
SERVER_ID = "5e1f0000-0000-4000-8000-00000000c0de"


class FakeClock:
    def __init__(self, start: datetime = T0) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class FakeRandom:
    """Bytes determinísticos e sempre diferentes entre chamadas."""

    def __init__(self, seed: bytes = b"tsm") -> None:
        self.seed = seed
        self.counter = 0
        self.calls: list[int] = []

    def __call__(self, n: int) -> bytes:
        self.calls.append(n)
        out = b""
        while len(out) < n:
            self.counter += 1
            out += hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
        return out[:n]


class FakeVerifier:
    """Aceita só a assinatura derivada de (chave, namespace, mensagem)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes, str]] = []

    @staticmethod
    def sign(public_key: str, message: bytes, namespace: str = NAMESPACE) -> str:
        digest = hashlib.sha256(public_key.encode() + b"\0" + namespace.encode() + b"\0"
                                + message).hexdigest()
        return f"fake-sshsig:{digest}"

    def verify(self, public_key: str, namespace: str, message: bytes,
               signature: str) -> bool:
        self.calls.append((public_key, namespace, message, signature))
        return signature == self.sign(public_key, message, namespace)


def fake_key(n: int, comment: str | None = None) -> str:
    """Chave pública ``ssh-ed25519`` válida (32 bytes derivados de ``n``)."""
    raw = hashlib.sha256(f"chave-{n}".encode()).digest()
    blob = (struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + raw)
    line = f"ssh-ed25519 {base64.b64encode(blob).decode()}"
    return f"{line} {comment}" if comment else line


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def rng() -> FakeRandom:
    return FakeRandom()


@pytest.fixture
def verifier() -> FakeVerifier:
    return FakeVerifier()


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "manager" / "manager.db")
    upgrade(db, clock=lambda: T0, new_id=lambda: SERVER_ID)
    yield db
    db.close()


@pytest.fixture
def ctx(database, clock, rng, verifier) -> IdentityContext:
    return IdentityContext(repo=Repository(database), server_id=SERVER_ID, verifier=verifier,
                           projects=frozenset({"demo", "outro"}), settings=AuthSettings(),
                           clock=clock, random=rng)


def audit_events(database) -> list[dict]:
    with database.read() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
    return [{"event": r["event"], "project": r["project_id"], "user": r["actor_user"],
             "device": r["actor_device"], **json.loads(r["fields"])} for r in rows]


def seed_user(ctx: IdentityContext, uid: str, *, role: str = "developer",
              status: str = "active", did: str | None = None, device_status: str = "active",
              key: int | None = None, project: str | None = None,
              invite_kind: str = "new_user") -> tuple[str, str]:
    """Usuário com um dispositivo (e vínculo, se ``project``) gravados direto no banco."""
    did = did or f"dev-{uid}"
    now = ts(ctx.now())
    if key is None:
        key = int(hashlib.sha256(did.encode()).hexdigest()[:8], 16)
    pk = parse_public_key(fake_key(key))
    with ctx.repo.write() as tx:
        if tx.get_user(uid) is None:
            tx.insert_user(User(uid, f"Nome {uid}", role, status, now, now))
        tx.insert_invite(Invite(f"inv-{did}", f"hash-{did}", invite_kind, role, "demo",
                                uid if invite_kind == "new_device" else None, None, now, now,
                                used_at=now))
        account = f"tsm-d-{hashlib.sha256(did.encode()).hexdigest()[:12]}"
        tx.insert_device(Device(did, uid, f"pc {did}", pk.openssh, pk.fingerprint,
                                device_status, account, f"inv-{did}", now))
        if project:
            tx.insert_binding(Binding(f"b-{did}", project, did, account, now))
    return uid, did
