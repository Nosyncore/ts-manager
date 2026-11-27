"""``ssh-keygen`` do Client: chave Ed25519 do dispositivo e assinatura SSHSIG.

- Executável por caminho absoluto, a partir do diretório do OpenSSH (``mutagen.ssh_path``,
  o mesmo que o Mutagen usa); nunca procurado no ``PATH``.
- Ambiente montado do zero: ``HOME`` gerenciado (``<home>/ssh``), ``PATH`` = diretório do
  executável, ``LC_ALL``/``LANG`` = ``C`` e, no Windows, ``SYSTEMROOT``. Sem shell e sem TTY.
- Geração: só se a chave não existir (nunca sobrescreve). Assinatura: mensagem pela entrada
  padrão, assinatura pela saída padrão. O Python nunca lê a chave privada, e a mensagem
  assinada não aparece em erros.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

from tsm_client.adapters.process import ProcessFailure, ProcResult, ProcRunner, run_process
from tsm_common.authmsg import NAMESPACE
from tsm_common.sshkeys import PublicKeyError, parse_public_key

KEY_COMMENT = "tsm"
TIMEOUT_S = 30
MAX_SIGNATURE_CHARS = 4096
_BEGIN = "-----BEGIN SSH SIGNATURE-----"
_END = "-----END SSH SIGNATURE-----"


class KeygenError(RuntimeError):
    """Falha ao gerar a chave ou assinar."""


def default_ssh_path(platform: str = sys.platform) -> Path:
    return Path(r"C:\Program Files\Git\usr\bin") if platform == "win32" else Path("/usr/bin")


def keygen_executable(ssh_path: Path) -> Path:
    if not Path(ssh_path).is_absolute():
        raise KeygenError(f"diretório do OpenSSH precisa ser absoluto: {ssh_path}")
    exe = Path(ssh_path) / "ssh-keygen.exe"
    return exe if exe.exists() else Path(ssh_path) / "ssh-keygen"


class SshKeygen:
    def __init__(self, executable: Path, ssh_home: Path, *, run: ProcRunner = run_process,
                 timeout: float = TIMEOUT_S, environ: Mapping[str, str] | None = None,
                 windows: bool = sys.platform == "win32") -> None:
        self.executable = Path(executable)
        if not self.executable.is_absolute():
            raise KeygenError(f"ssh-keygen precisa de caminho absoluto: {executable}")
        self.ssh_home = Path(ssh_home)
        self._run = run
        self.timeout = timeout
        self._environ = os.environ if environ is None else environ
        self._windows = windows

    def env(self) -> dict[str, str]:
        env = {"HOME": str(self.ssh_home), "PATH": str(self.executable.parent),
               "LC_ALL": "C", "LANG": "C"}
        root = self._environ.get("SYSTEMROOT") or self._environ.get("SystemRoot")
        if self._windows and root:
            env["SYSTEMROOT"] = root
        return env

    def _call(self, argv: list[str], data: bytes | None) -> ProcResult:
        try:
            return self._run(argv, env=self.env(), cwd=self.ssh_home, input=data,
                             timeout=self.timeout)
        except ProcessFailure as exc:
            raise KeygenError(f"ssh-keygen: {exc}") from exc

    def generate_argv(self, private: Path) -> list[str]:
        return [str(self.executable), "-q", "-t", "ed25519", "-N", "", "-C", KEY_COMMENT,
                "-f", str(private)]

    def sign_argv(self, private: Path, namespace: str = NAMESPACE) -> list[str]:
        return [str(self.executable), "-Y", "sign", "-n", namespace, "-f", str(private)]

    def generate(self, private: Path) -> str:
        """Gera a chave em ``private`` (e ``.pub``); devolve a linha pública normalizada."""
        public = private.with_name(private.name + ".pub")
        if private.exists() or public.exists():
            raise KeygenError(f"a chave já existe: {private}")
        res = self._call(self.generate_argv(private), None)
        if res.returncode != 0:
            raise KeygenError(f"ssh-keygen falhou ao gerar a chave ({res.returncode}): "
                              f"{res.stderr_line()}")
        try:
            text = public.read_text("ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise KeygenError(f"ssh-keygen não gerou a chave pública: {public}") from exc
        try:
            return parse_public_key(text.strip()).openssh
        except PublicKeyError as exc:
            raise KeygenError(f"chave pública gerada inválida: {exc}") from exc

    def sign(self, private: Path, message: bytes, namespace: str = NAMESPACE) -> str:
        res = self._call(self.sign_argv(private, namespace), message)
        if res.returncode != 0:
            raise KeygenError(f"ssh-keygen -Y sign falhou ({res.returncode}): "
                              f"{res.stderr_line()}")
        try:
            text = res.stdout.decode("ascii").replace("\r\n", "\n")
        except UnicodeDecodeError as exc:
            raise KeygenError("assinatura com caracteres inválidos") from exc
        lines = text.strip("\n").split("\n")
        if (len(text) > MAX_SIGNATURE_CHARS or len(lines) < 3 or lines[0] != _BEGIN
                or lines[-1] != _END):
            raise KeygenError("assinatura fora do formato esperado")
        return text
