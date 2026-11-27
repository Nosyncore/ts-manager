"""Chave do dispositivo, fingerprint e assinatura do desafio."""

from __future__ import annotations

import pytest

from tests.unit.client_fakes import (
    SERVER_ID,
    FakeKeygen,
    RecordingAcl,
    challenge_body,
    fake_key,
    fingerprint,
)
from tsm_client.adapters.manager import ManagerProtocolError
from tsm_client.adapters.sshkeygen import KeygenError
from tsm_client.home import Home
from tsm_client.identity import (
    ChallengeSigner,
    ServerMismatch,
    check_server_id,
    ensure_device_key,
    load_device_key,
)


def test_key_generated_once_with_acl(tmp_path):
    home, kg, acl = Home(tmp_path), FakeKeygen(3), RecordingAcl()
    key, new = ensure_device_key(home, kg, acl)
    assert new and key.fingerprint == fingerprint(3) and key.public_line == fake_key(3)
    assert acl.files == [home.key_path]
    again, new2 = ensure_device_key(home, kg, acl)
    assert not new2 and again == key and len(kg.generated) == 1


def test_incomplete_key_refused(tmp_path):
    home = Home(tmp_path)
    home.ssh_dir.mkdir(parents=True)
    home.key_path.write_text("x")
    with pytest.raises(KeygenError, match="incompleta"):
        load_device_key(home)


def test_invalid_public_key_refused(tmp_path):
    home = Home(tmp_path)
    home.ssh_dir.mkdir(parents=True)
    home.key_path.write_text("x")
    home.pub_path.write_text("ssh-rsa AAAA")
    with pytest.raises(KeygenError, match="inválida"):
        load_device_key(home)


def test_fingerprint_is_computed_locally(tmp_path):
    home = Home(tmp_path)
    home.ssh_dir.mkdir(parents=True)
    home.key_path.write_text("x")
    home.pub_path.write_text(fake_key(7, "comentário qualquer"), encoding="utf-8")
    assert load_device_key(home).fingerprint == fingerprint(7)


def test_check_server_id():
    assert check_server_id(SERVER_ID, SERVER_ID) == SERVER_ID
    with pytest.raises(ServerMismatch):
        check_server_id(SERVER_ID, "outro")
    for bad in (None, "", "com espaço", "x" * 65):
        with pytest.raises(ManagerProtocolError):
            check_server_id(SERVER_ID, bad)


def test_signer_uses_expected_purpose(tmp_path):
    home, kg = Home(tmp_path), FakeKeygen(1)
    key, _ = ensure_device_key(home, kg, RecordingAcl())
    signer = ChallengeSigner(kg, key)
    msg = signer.message({**challenge_body("register")}, "login")
    assert b"purpose: login\n" in msg and f"key: {fingerprint(1)}".encode() in msg
    with pytest.raises(ManagerProtocolError):
        signer.message({**challenge_body(), "expires_at": "amanhã"}, "login")
