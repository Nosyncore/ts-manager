"""Adaptador do ``ssh-keygen`` do Client: argv, ambiente e validação da saída."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.client_fakes import fake_key
from tsm_client.adapters.process import ProcessFailure, ProcResult
from tsm_client.adapters.sshkeygen import (
    KEY_COMMENT,
    KeygenError,
    SshKeygen,
    default_ssh_path,
    keygen_executable,
)

ARMOR = ("-----BEGIN SSH SIGNATURE-----\r\nU1NIU0lHAAAAAQ==\r\n"
         "-----END SSH SIGNATURE-----\r\n")


class FakeRun:
    def __init__(self, *, rc: int = 0, stdout: bytes = b"", stderr: bytes = b"",
                 write_pub: str | None = None, exc: Exception | None = None) -> None:
        self.calls: list[dict] = []
        self.rc, self.stdout, self.stderr = rc, stdout, stderr
        self.write_pub = write_pub
        self.exc = exc

    def __call__(self, argv, *, env=None, cwd=None, input=None, timeout):
        self.calls.append({"argv": list(argv), "env": dict(env or {}), "cwd": cwd,
                           "input": input, "timeout": timeout})
        if self.exc:
            raise self.exc
        if self.write_pub is not None and "-f" in argv:
            priv = Path(argv[argv.index("-f") + 1])
            priv.write_text("PRIVADA\n")
            priv.with_name(priv.name + ".pub").write_text(self.write_pub + "\n")
        return ProcResult(tuple(argv), self.rc, self.stdout, self.stderr)


@pytest.fixture
def exe(tmp_path) -> Path:
    return (tmp_path / "bin" / "ssh-keygen.exe").resolve()


def make(exe: Path, home: Path, run: FakeRun, **kw) -> SshKeygen:
    return SshKeygen(exe, home, run=run, environ={"SystemRoot": r"C:\Windows", "PATH": "x",
                                                   "SSH_AUTH_SOCK": "y", "HOME": "z"}, **kw)


def test_environment_is_built_from_scratch(tmp_path, exe):
    kg = make(exe, tmp_path / "ssh", FakeRun(), windows=True)
    assert kg.env() == {"HOME": str(tmp_path / "ssh"), "PATH": str(exe.parent),
                        "LC_ALL": "C", "LANG": "C", "SYSTEMROOT": r"C:\Windows"}
    posix = make(exe, tmp_path / "ssh", FakeRun(), windows=False)
    assert "SYSTEMROOT" not in posix.env()


def test_generate_argv_and_result(tmp_path, exe):
    home = tmp_path / "ssh"
    priv = home / ".ssh" / "id_ed25519"
    priv.parent.mkdir(parents=True)
    run = FakeRun(write_pub=fake_key(1, "tsm"))
    line = make(exe, home, run, windows=True).generate(priv)
    call = run.calls[0]
    assert call["argv"] == [str(exe), "-q", "-t", "ed25519", "-N", "", "-C", KEY_COMMENT,
                            "-f", str(priv)]
    assert call["input"] is None and call["cwd"] == home and call["timeout"] == 30
    assert call["env"]["HOME"] == str(home)
    assert line == fake_key(1)  # normalizada, sem comentário


def test_generate_never_overwrites(tmp_path, exe):
    priv = tmp_path / "id_ed25519"
    priv.write_text("já existe")
    run = FakeRun()
    with pytest.raises(KeygenError, match="já existe"):
        make(exe, tmp_path, run).generate(priv)
    assert run.calls == []


def test_generate_failure_and_bad_public_key(tmp_path, exe):
    priv = tmp_path / "id_ed25519"
    with pytest.raises(KeygenError, match="falhou"):
        make(exe, tmp_path, FakeRun(rc=1, stderr=b"erro\nmais")).generate(priv)
    with pytest.raises(KeygenError, match="pública"):
        make(exe, tmp_path, FakeRun(write_pub="ssh-rsa AAAAB3NzaC1yc2E=")).generate(priv)
    (tmp_path / "id_ed25519").unlink()
    (tmp_path / "id_ed25519.pub").unlink()
    with pytest.raises(KeygenError, match="não gerou"):
        make(exe, tmp_path, FakeRun()).generate(priv)


def test_sign_argv_input_and_output(tmp_path, exe):
    priv = tmp_path / "id_ed25519"
    run = FakeRun(stdout=ARMOR.encode())
    sig = make(exe, tmp_path, run).sign(priv, b"mensagem\n")
    call = run.calls[0]
    assert call["argv"] == [str(exe), "-Y", "sign", "-n", "ts-manager-auth", "-f", str(priv)]
    assert call["input"] == b"mensagem\n"
    assert sig == ARMOR.replace("\r\n", "\n")


@pytest.mark.parametrize("out", [b"", b"lixo", b"-----BEGIN SSH SIGNATURE-----\nx\n",
                                 ("-----BEGIN SSH SIGNATURE-----\n" + "A" * 5000
                                  + "\n-----END SSH SIGNATURE-----\n").encode(),
                                 b"\xff\xfe"])
def test_sign_rejects_bad_armor(tmp_path, exe, out):
    with pytest.raises(KeygenError, match="assinatura"):
        make(exe, tmp_path, FakeRun(stdout=out)).sign(tmp_path / "k", b"m")


def test_sign_failure_does_not_leak_message(tmp_path, exe):
    with pytest.raises(KeygenError) as info:
        make(exe, tmp_path, FakeRun(rc=255, stderr=b"Load key: bad")).sign(
            tmp_path / "k", b"segredo-da-mensagem")
    assert "segredo" not in str(info.value) and "255" in str(info.value)


def test_process_failure_becomes_keygen_error(tmp_path, exe):
    run = FakeRun(exc=ProcessFailure("tempo esgotado (30s): ssh-keygen.exe"))
    with pytest.raises(KeygenError, match="tempo esgotado"):
        make(exe, tmp_path, run).sign(tmp_path / "k", b"m")


def test_executable_must_be_absolute(tmp_path):
    with pytest.raises(KeygenError, match="absoluto"):
        SshKeygen(Path("ssh-keygen"), tmp_path)
    with pytest.raises(KeygenError, match="absoluto"):
        keygen_executable(Path("usr/bin"))


def test_executable_from_ssh_path(tmp_path):
    (tmp_path / "ssh-keygen.exe").write_text("")
    assert keygen_executable(tmp_path) == tmp_path / "ssh-keygen.exe"
    other = tmp_path / "posix"
    other.mkdir()
    assert keygen_executable(other) == other / "ssh-keygen"


def test_missing_executable_is_a_process_failure(tmp_path):
    from tsm_client.adapters.process import run_process

    with pytest.raises(ProcessFailure, match="não encontrado"):
        run_process([str(tmp_path / "nao-existe.exe")], timeout=5)


def test_stderr_line():
    assert ProcResult((), 1, b"", b"\n primeira\nsegunda").stderr_line() == "primeira"
    assert ProcResult((), 1, b"", b"").stderr_line() == ""


def test_default_ssh_path():
    assert default_ssh_path("win32") == Path(r"C:\Program Files\Git\usr\bin")
    assert default_ssh_path("linux") == Path("/usr/bin")
