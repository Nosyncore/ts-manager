"""Verificação de assinaturas SSHSIG com ``ssh-keygen -Y verify``.

Implementa o ``SignatureVerifier`` do domínio de identidade, restrito ao namespace
``ts-manager-auth``:

- antes do processo, valida namespace, chave (só ``ssh-ed25519``, forma normalizada),
  tamanho da mensagem e armadura da assinatura; nada inválido chega ao ``ssh-keygen``;
- cada chamada usa um diretório próprio sob o diretório de trabalho (por padrão
  ``<root>/manager/tmp/sshsig/``), com um ``allowed_signers`` de uma linha (principal fixo
  ``tsm-device``, ``namespaces="ts-manager-auth"``) e a assinatura; o diretório é apagado no
  fim, com qualquer resultado. Nada vai para o diretório temporário do sistema;
- o processo roda com lista de argumentos (sem shell), mensagem pela entrada padrão,
  ambiente montado do zero e timeout;
- a assinatura só é aceita com código 0 **e** a linha ``Good …`` com o fingerprint da chave
  registrada. Código 255 é assinatura recusada;
- qualquer falha do processo devolve ``False``. O log guarda só a categoria da falha, nunca
  mensagem, assinatura, chave, caminho ou stderr.

``self_check()`` verifica um vetor embutido e serve para recusar a inicialização quando o
``ssh-keygen`` não funciona.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from tsm_common.authmsg import NAMESPACE
from tsm_common.sshkeys import PublicKey, PublicKeyError, parse_public_key

PRINCIPAL = "tsm-device"
DEFAULT_TIMEOUT_S = 5.0
DEFAULT_MAX_CONCURRENT = 8
STALE_AFTER_S = 600
MAX_MESSAGE_BYTES = 1024
MAX_SIGNATURE_CHARS = 4096
MIN_SIGNATURE_BYTES = 64
MAX_SIGNATURE_BYTES = 2048
MAX_ARMOR_LINE = 76
ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
ARMOR_END = "-----END SSH SIGNATURE-----"
SSHSIG_MAGIC = b"SSHSIG"
SSHSIG_VERSION = 1
CALL_PREFIX = "v-"
WINDOWS_EXECUTABLE = r"C:\Program Files\Git\usr\bin\ssh-keygen.exe"
POSIX_EXECUTABLE = "/usr/bin/ssh-keygen"

# Vetor do autoteste: gerado uma vez com ssh-keygen -Y sign (OpenSSH 10.2p1); a chave
# privada foi descartada.
SELF_CHECK_KEY = ("ssh-ed25519 "
                  "AAAAC3NzaC1lZDI1NTE5AAAAIKihaUpE9XPGcn/2oy/7JpNmnuZN0C8oGKxtLO3MjwV7")
SELF_CHECK_MESSAGE = b"tsm-sshsig-self-check-v1\n"
SELF_CHECK_SIGNATURE = (
    "-----BEGIN SSH SIGNATURE-----\n"
    "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgqKFpSkT1c8Zyf/ajL/smk2ae5k\n"
    "3QLygYrG0s7cyPBXsAAAAPdHMtbWFuYWdlci1hdXRoAAAAAAAAAAZzaGE1MTIAAABTAAAA\n"
    "C3NzaC1lZDI1NTE5AAAAQAJst0kacScbabd6MIxy0P844RReXXokVRJ5CvObG7eZx+S/Im\n"
    "zKJQhjda7NyAUMNIAFZE9+x9e5+0NNbi8PIQQ=\n"
    "-----END SSH SIGNATURE-----\n"
)
_SELF_CHECK_OTHER_MESSAGE = b"tsm-sshsig-self-check-v1 (alterada)\n"

_ARMOR_LINE_RE = re.compile(rf"^[A-Za-z0-9+/=]{{1,{MAX_ARMOR_LINE}}}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

log = logging.getLogger("tsm_manager.sshsig")


class SshsigUnavailable(RuntimeError):
    """O ``ssh-keygen`` configurado não verifica assinaturas SSHSIG."""


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: bytes


Runner = Callable[[Sequence[str], bytes, Mapping[str, str], Path, float], Completed]


def run_process(argv: Sequence[str], stdin: bytes, env: Mapping[str, str], cwd: Path,
                timeout: float) -> Completed:
    """Executa sem shell; stderr descartado; no timeout o processo é morto."""
    proc = subprocess.run(list(argv), input=stdin, env=dict(env), cwd=cwd,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=timeout, check=False)
    return Completed(proc.returncode, proc.stdout)


def default_executable(*, windows: bool | None = None) -> str:
    """OpenSSH do Git for Windows no Windows; ``/usr/bin/ssh-keygen`` em POSIX."""
    if windows is None:
        windows = os.name == "nt"
    return WINDOWS_EXECUTABLE if windows else POSIX_EXECUTABLE


def work_dir_for(database: Path) -> Path:
    """Diretório de trabalho ao lado do banco (padrão ``<root>/manager/tmp/sshsig``)."""
    return Path(database).parent / "tmp" / "sshsig"


def normalize_signature(signature: object) -> str | None:
    """Armadura SSHSIG normalizada (``\\n``, com quebra final), ou ``None`` se malformada.

    Confere só a forma: linhas de início e fim, corpo em base64 estrito com tamanho
    decodificado limitado, e prefixo ``SSHSIG`` versão 1. A verificação é do ``ssh-keygen``.
    """
    if not isinstance(signature, str) or not signature \
            or len(signature) > MAX_SIGNATURE_CHARS:
        return None
    text = signature.replace("\r\n", "\n")
    if text.endswith("\n"):
        text = text[:-1]
    lines = text.split("\n")
    if len(lines) < 3 or lines[0] != ARMOR_BEGIN or lines[-1] != ARMOR_END:
        return None
    body_lines = lines[1:-1]
    if not all(_ARMOR_LINE_RE.match(line) for line in body_lines):
        return None
    body = "".join(body_lines)
    if not _B64_RE.match(body) or len(body) % 4:
        return None
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(raw).decode("ascii") != body:
        return None
    if not MIN_SIGNATURE_BYTES <= len(raw) <= MAX_SIGNATURE_BYTES:
        return None
    header = SSHSIG_MAGIC + struct.pack(">I", SSHSIG_VERSION)
    if raw[:len(header)] != header:
        return None
    return "\n".join(lines) + "\n"


def _write_new(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class SshKeygenVerifier:
    """``SignatureVerifier`` sobre ``ssh-keygen -Y verify`` (namespace ``ts-manager-auth``)."""

    def __init__(self, executable: str | os.PathLike[str], work_dir: str | os.PathLike[str],
                 *, timeout_s: float = DEFAULT_TIMEOUT_S,
                 max_concurrent: int = DEFAULT_MAX_CONCURRENT, runner: Runner = run_process,
                 windows: bool | None = None) -> None:
        self.executable = Path(executable)
        if not self.executable.is_absolute():
            raise ValueError(f"ssh-keygen deve ter caminho absoluto: {executable}")
        if timeout_s <= 0:
            raise ValueError("timeout deve ser positivo")
        if max_concurrent < 1:
            raise ValueError("concorrência máxima deve ser ao menos 1")
        self.work_dir = Path(work_dir)
        self.timeout_s = float(timeout_s)
        self._runner = runner
        self._windows = os.name == "nt" if windows is None else windows
        self._slots = threading.BoundedSemaphore(max_concurrent)

    # ------------------------------------------------------------ verificação

    def verify(self, public_key: str, namespace: str, message: bytes,
               signature: str) -> bool:
        if namespace != NAMESPACE:
            return False
        try:
            key = parse_public_key(public_key)
        except PublicKeyError:
            return False
        if not isinstance(message, bytes) or not 1 <= len(message) <= MAX_MESSAGE_BYTES:
            return False
        armor = normalize_signature(signature)
        if armor is None:
            return False
        if not self._slots.acquire(timeout=self.timeout_s):
            return self._failure("busy")
        try:
            return self._verify(key, message, armor)
        finally:
            self._slots.release()

    def _verify(self, key: PublicKey, message: bytes, armor: str) -> bool:
        try:
            call_dir = self._new_call_dir()
        except OSError:
            return self._failure("workdir")
        try:
            allowed = call_dir / "allowed_signers"
            sig_file = call_dir / "signature"
            try:
                _write_new(allowed, f'{PRINCIPAL} namespaces="{NAMESPACE}" '
                                    f"{key.openssh}\n".encode("ascii"))
                _write_new(sig_file, armor.encode("ascii"))
            except OSError:
                return self._failure("workdir")
            argv = [str(self.executable), "-Y", "verify", "-f", str(allowed),
                    "-I", PRINCIPAL, "-n", NAMESPACE, "-s", str(sig_file)]
            try:
                done = self._runner(argv, message, self._env(call_dir), call_dir,
                                    self.timeout_s)
            except subprocess.TimeoutExpired:
                return self._failure("timeout")
            except (OSError, subprocess.SubprocessError):
                return self._failure("unavailable")
            return self._accepted(done, key)
        finally:
            shutil.rmtree(call_dir, ignore_errors=True)

    def _accepted(self, done: Completed, key: PublicKey) -> bool:
        if done.returncode == 255:
            return False
        if done.returncode != 0:
            return self._failure("unexpected_exit")
        expected = (f'Good "{NAMESPACE}" signature for {PRINCIPAL} with ED25519 key '
                    f"{key.fingerprint}")
        try:
            out = done.stdout.decode("ascii")
        except UnicodeDecodeError:
            return self._failure("unexpected_output")
        if out.replace("\r\n", "\n") != expected + "\n":
            return self._failure("unexpected_output")
        return True

    def _new_call_dir(self) -> Path:
        self.work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self._windows:
            self.work_dir.chmod(0o700)
        return Path(tempfile.mkdtemp(prefix=CALL_PREFIX, dir=self.work_dir))

    def _env(self, call_dir: Path) -> dict[str, str]:
        here = str(call_dir)
        env = {"LC_ALL": "C", "LANG": "C", "PATH": str(self.executable.parent),
               "HOME": here, "TMP": here, "TEMP": here, "TMPDIR": here}
        if self._windows and os.environ.get("SYSTEMROOT"):
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        return env

    @staticmethod
    def _failure(category: str) -> bool:
        log.warning("falha ao verificar assinatura SSHSIG: %s", category)
        return False

    # ------------------------------------------------------------ manutenção

    def self_check(self) -> None:
        """Vetor embutido: a assinatura válida passa e a mesma, sobre outra mensagem, não."""
        good = self.verify(SELF_CHECK_KEY, NAMESPACE, SELF_CHECK_MESSAGE,
                           SELF_CHECK_SIGNATURE)
        bad = self.verify(SELF_CHECK_KEY, NAMESPACE, _SELF_CHECK_OTHER_MESSAGE,
                          SELF_CHECK_SIGNATURE)
        if not good or bad:
            raise SshsigUnavailable(
                f"ssh-keygen em {self.executable} não verifica assinaturas SSHSIG")

    def purge_stale(self, older_than_s: float = STALE_AFTER_S) -> int:
        """Remove diretórios de chamada mais antigos que ``older_than_s`` (restos de queda)."""
        if not self.work_dir.is_dir():
            return 0
        limit = time.time() - older_than_s
        removed = 0
        for entry in self.work_dir.iterdir():
            if (entry.name.startswith(CALL_PREFIX) and entry.is_dir()
                    and not entry.is_symlink() and entry.stat().st_mtime <= limit):
                shutil.rmtree(entry, ignore_errors=True)
                removed += 1
        return removed
