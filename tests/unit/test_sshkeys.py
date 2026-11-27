"""Chaves públicas OpenSSH: parse, normalização e fingerprint (vetores do ssh-keygen)."""

from __future__ import annotations

import base64
import json
import struct

import pytest

from tsm_common.sshkeys import (
    ED25519_BLOB_SIZE,
    PublicKeyError,
    fingerprint_of_blob,
    is_fingerprint,
    parse_public_key,
)


@pytest.fixture
def vectors(fixtures_dir):
    return json.loads((fixtures_dir / "sshkeys" / "vectors.json").read_text(encoding="utf-8"))


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _line(blob: bytes, kind: str = "ssh-ed25519") -> str:
    return f"{kind} {base64.b64encode(blob).decode()}"


def _blob(key: bytes = b"\x01" * 32, kind: bytes = b"ssh-ed25519") -> bytes:
    return _string(kind) + _string(key)


def test_fingerprint_matches_ssh_keygen(vectors):
    for v in vectors["ed25519"]:
        key = parse_public_key(v["line"])
        assert key.fingerprint == v["fingerprint"]
        assert key.comment == v["line"].split(" ", 2)[2]


def test_fingerprint_function_matches_other_key_types(vectors):
    # o cálculo é o mesmo para qualquer tipo, ainda que só ed25519 seja aceito
    for v in vectors["other"]:
        blob = base64.b64decode(v["line"].split()[1])
        assert fingerprint_of_blob(blob) == v["fingerprint"]


def test_normalized_form_drops_comment(vectors):
    line = vectors["ed25519"][0]["line"]
    key = parse_public_key(line)
    assert key.openssh == " ".join(line.split()[:2])
    assert parse_public_key(key.openssh) == key.__class__(key.openssh, key.blob,
                                                         key.fingerprint, None)
    assert len(key.blob) == ED25519_BLOB_SIZE == 51


def test_surrounding_whitespace_and_trailing_newline_accepted(vectors):
    line = vectors["ed25519"][1]["line"]
    assert parse_public_key(f"  {line}\n").fingerprint == vectors["ed25519"][1]["fingerprint"]
    assert parse_public_key(f"{line}\r\n").fingerprint == vectors["ed25519"][1]["fingerprint"]


@pytest.mark.parametrize("index", [0, 1])
def test_other_key_types_refused(vectors, index):
    with pytest.raises(PublicKeyError, match="ssh-ed25519"):
        parse_public_key(vectors["other"][index]["line"])


def test_declared_type_must_match_blob():
    rsa_named = _line(_blob(), kind="ssh-rsa")
    with pytest.raises(PublicKeyError):
        parse_public_key(rsa_named)
    inner_mismatch = _line(_blob(kind=b"ssh-ed25518"))
    with pytest.raises(PublicKeyError, match="tipo"):
        parse_public_key(inner_mismatch)


@pytest.mark.parametrize("blob", [
    _blob()[:-1],                                  # truncado
    _blob() + b"\x00",                             # sobra no fim
    _blob(key=b"\x01" * 31) + b"\x00",             # chave de 31 bytes, mesmo tamanho total
    _string(b"ssh-ed25519") + struct.pack(">I", 64) + b"\x01" * 32,  # comprimento mentiroso
    b"\x00\x00",                                   # curto demais até para o cabeçalho
])
def test_wrong_blob_size_refused(blob):
    with pytest.raises(PublicKeyError):
        parse_public_key(_line(blob))


@pytest.mark.parametrize("text", [
    "ssh-ed25519 AAAA!!!!",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaBW3mTZmaTGddtY3pc+fZuseuAhrRtPAArlknPuVN",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaBW3mTZmaTGddtY3pc+fZuseuAhrRtPAArlknPuVNp=",
    "ssh-ed25519",
    "",
    "   ",
])
def test_invalid_base64_or_missing_blob_refused(text):
    with pytest.raises(PublicKeyError):
        parse_public_key(text)


@pytest.mark.parametrize("prefix", [
    "restrict ", 'command="/bin/sh" ', "no-pty,", 'from="10.0.0.1" ', "cert-authority ",
])
def test_embedded_options_refused(vectors, prefix):
    with pytest.raises(PublicKeyError):
        parse_public_key(prefix + vectors["ed25519"][0]["line"])


@pytest.mark.parametrize("comment", ["a\nssh-ed25519 AAAA", "a\x00b", "a\x1bb", "a\rb",
                                     "a\u0085b"])
def test_control_characters_refused(vectors, comment):
    base = " ".join(vectors["ed25519"][0]["line"].split()[:2])
    with pytest.raises(PublicKeyError):
        parse_public_key(f"{base} {comment}")


def test_two_lines_refused(vectors):
    a, b = (v["line"] for v in vectors["ed25519"][:2])
    with pytest.raises(PublicKeyError):
        parse_public_key(f"{a}\n{b}")


def test_non_text_refused():
    with pytest.raises(PublicKeyError):
        parse_public_key(b"ssh-ed25519 AAAA")  # type: ignore[arg-type]
    with pytest.raises(PublicKeyError):
        parse_public_key("x" * 5000)


def test_is_fingerprint(vectors):
    for v in vectors["ed25519"] + vectors["other"]:
        assert is_fingerprint(v["fingerprint"])
    for bad in ["", "SHA256:", "sha256:abBPfU7aCcoDwiDDdarFS0BxHQhEyGBlZ6EXeF5Tucc",
                "SHA256:abBPfU7aCcoDwiDDdarFS0BxHQhEyGBlZ6EXeF5Tuc",
                "SHA256:abBPfU7aCcoDwiDDdarFS0BxHQhEyGBlZ6EXeF5Tucc=",
                "MD5:aa:bb", "SHA256:abBPfU7aCcoDwiDDdarFS0BxHQhEyGBlZ6EXeF5Tuc!", None, 3]:
        assert not is_fingerprint(bad)
