"""ACL só do usuário: ``icacls`` no Windows (argv exato) e modos em POSIX."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from tsm_client.adapters.acl import (
    AclError,
    PosixAcl,
    WindowsAcl,
    current_user_sid,
    default_icacls,
)
from tsm_client.adapters.process import ProcResult

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


class FakeRun:
    def __init__(self, rc: int = 0, stderr: bytes = b"") -> None:
        self.calls: list[dict] = []
        self.rc = rc
        self.stderr = stderr

    def __call__(self, argv, *, env=None, cwd=None, input=None, timeout):
        self.calls.append({"argv": list(argv), "env": env, "cwd": cwd, "input": input,
                           "timeout": timeout})
        return ProcResult(tuple(argv), self.rc, b"", self.stderr)


ICACLS = Path(r"C:\Windows\System32\icacls.exe")


def test_icacls_argv_for_directory(tmp_path):
    run = FakeRun()
    WindowsAcl(ICACLS, sid=lambda: SID, run=run).restrict_dir(tmp_path)
    assert [c["argv"] for c in run.calls] == [[
        str(ICACLS), str(tmp_path), "/inheritance:r", "/grant:r", f"*{SID}:(OI)(CI)F", "/q"]]
    assert run.calls[0]["input"] is None


def test_icacls_argv_for_file(tmp_path):
    f = tmp_path / "id_ed25519"
    f.write_text("x")
    run = FakeRun()
    WindowsAcl(ICACLS, sid=lambda: SID, run=run).restrict_file(f)
    assert run.calls[0]["argv"] == [str(ICACLS), str(f), "/inheritance:r", "/grant:r",
                                    f"*{SID}:F", "/q"]


def test_icacls_failure_raises(tmp_path):
    run = FakeRun(rc=5, stderr=b"Acesso negado.\r\n")
    with pytest.raises(AclError, match="icacls"):
        WindowsAcl(ICACLS, sid=lambda: SID, run=run).restrict_dir(tmp_path)


def test_icacls_must_be_absolute():
    with pytest.raises(AclError, match="absoluto"):
        WindowsAcl(Path("icacls.exe"), sid=lambda: SID, run=FakeRun())


@pytest.mark.parametrize("bad", ["", "S-1", "Everyone", "S-1-5-21-1 /grant x:F", "*S-1-5-18"])
def test_invalid_sid_refused(tmp_path, bad):
    with pytest.raises(AclError, match="SID"):
        WindowsAcl(ICACLS, sid=lambda: bad, run=FakeRun()).restrict_dir(tmp_path)


def test_default_icacls_uses_systemroot():
    assert default_icacls({"SystemRoot": r"C:\Win"}) == Path(r"C:\Win\System32\icacls.exe")
    assert default_icacls({}) == Path(r"C:\Windows\System32\icacls.exe")


@pytest.mark.skipif(sys.platform != "win32", reason="SID só no Windows")
def test_current_user_sid_is_a_sid():
    assert re.fullmatch(r"S-1-\d+(-\d+)+", current_user_sid())


def test_posix_modes(tmp_path):
    calls = []
    acl = PosixAcl(chmod=lambda p, m: calls.append((Path(p), m)))
    acl.restrict_dir(tmp_path)
    acl.restrict_file(tmp_path / "k")
    assert calls == [(tmp_path, 0o700), (tmp_path / "k", 0o600)]


def test_posix_chmod_failure(tmp_path):
    def boom(p, m):
        raise PermissionError("negado")

    with pytest.raises(AclError, match="permissões"):
        PosixAcl(chmod=boom).restrict_file(tmp_path / "k")
