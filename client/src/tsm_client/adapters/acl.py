"""Acesso só do usuário a arquivos e diretórios do Client (chave, sessão, ``<home>``).

- Windows: ``icacls`` por caminho absoluto, uma chamada por alvo, removendo a herança e
  concedendo controle total só ao SID do usuário do processo (lido do token, nunca do nome,
  que é ambíguo entre conta local e de domínio). Diretórios recebem a concessão herdável
  ``(OI)(CI)``: o que for criado dentro herda só essa entrada.
- POSIX: diretórios ``0700`` e arquivos ``0600``.

Qualquer falha levanta ``AclError``: o Client não segue com a chave sem proteção.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol

from tsm_client.adapters.process import ProcessFailure, ProcRunner, run_process

ICACLS_TIMEOUT_S = 30
_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")


class AclError(RuntimeError):
    """Não foi possível restringir o acesso ao usuário."""


class Acl(Protocol):
    def restrict_dir(self, path: Path) -> None: ...

    def restrict_file(self, path: Path) -> None: ...


def default_icacls(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    root = env.get("SystemRoot") or env.get("SYSTEMROOT") or r"C:\Windows"
    return Path(root) / "System32" / "icacls.exe"


def current_user_sid() -> str:
    """SID (texto) do usuário do token do processo atual."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(wintypes.LPWSTR)]
    token_query, token_user = 0x0008, 1

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), token_query,
                                     ctypes.byref(token)):
        raise AclError(f"OpenProcessToken falhou ({ctypes.get_last_error()})")
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, token_user, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, token_user, buf, size, ctypes.byref(size)):
            raise AclError(f"GetTokenInformation falhou ({ctypes.get_last_error()})")
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(text)):
            raise AclError(f"ConvertSidToStringSidW falhou ({ctypes.get_last_error()})")
        try:
            return str(text.value)
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


class WindowsAcl:
    def __init__(self, icacls: Path | None = None, *,
                 sid: Callable[[], str] = current_user_sid,
                 run: ProcRunner = run_process) -> None:
        self.icacls = Path(icacls) if icacls is not None else default_icacls()
        if not self.icacls.is_absolute():
            raise AclError(f"icacls precisa de caminho absoluto: {self.icacls}")
        self._sid = sid
        self._run = run
        self._cached: str | None = None

    def sid(self) -> str:
        if self._cached is None:
            value = self._sid()
            if not isinstance(value, str) or not _SID_RE.match(value):
                raise AclError(f"SID do usuário inválido: {value!r}")
            self._cached = value
        return self._cached

    def argv(self, path: Path, *, directory: bool) -> list[str]:
        grant = f"*{self.sid()}:(OI)(CI)F" if directory else f"*{self.sid()}:F"
        return [str(self.icacls), str(path), "/inheritance:r", "/grant:r", grant, "/q"]

    def _apply(self, path: Path, *, directory: bool) -> None:
        argv = self.argv(path, directory=directory)
        try:
            res = self._run(argv, timeout=ICACLS_TIMEOUT_S)
        except ProcessFailure as exc:
            raise AclError(f"icacls: {exc}") from exc
        if res.returncode != 0:
            raise AclError(f"icacls falhou ({res.returncode}) em {path}: {res.stderr_line()}")

    def restrict_dir(self, path: Path) -> None:
        self._apply(path, directory=True)

    def restrict_file(self, path: Path) -> None:
        self._apply(path, directory=False)


class PosixAcl:
    def __init__(self, *, chmod: Callable[[Path, int], None] = os.chmod) -> None:
        self._chmod = chmod

    def _apply(self, path: Path, mode: int) -> None:
        try:
            self._chmod(path, mode)
        except OSError as exc:
            raise AclError(f"não foi possível ajustar as permissões de {path}: {exc}") from exc

    def restrict_dir(self, path: Path) -> None:
        self._apply(path, 0o700)

    def restrict_file(self, path: Path) -> None:
        self._apply(path, 0o600)


def default_acl() -> Acl:
    return WindowsAcl() if sys.platform == "win32" else PosixAcl()
