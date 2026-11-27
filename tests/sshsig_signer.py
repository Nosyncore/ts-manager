"""Assinador de teste com o ``ssh-keygen`` real (OpenSSH do Git for Windows ou do sistema).

Gera chaves Ed25519 sem senha e assina com ``ssh-keygen -Y sign``: ``HOME`` gerenciado,
ambiente montado do zero, mensagem pela entrada padrão, assinatura pela saída padrão, sem
TTY. Serve ao gerador de vetores e aos testes de integração; o Client terá o próprio
adaptador. Chaves privadas ficam só no diretório passado pelo chamador.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from tsm_common.authmsg import NAMESPACE, AuthMessage, parse_expires
from tsm_common.sshkeys import parse_public_key

SSH_DIR = Path(os.environ.get("TSM_SSH_PATH", r"C:\Program Files\Git\usr\bin"))
SIGN_TIMEOUT_S = 30


def keygen_path(ssh_dir: Path = SSH_DIR) -> Path:
    exe = ssh_dir / "ssh-keygen.exe"
    return exe if exe.exists() else ssh_dir / "ssh-keygen"


def tool_env(keygen: Path, home: Path) -> dict[str, str]:
    env = {"HOME": str(home), "PATH": str(keygen.parent), "LC_ALL": "C", "LANG": "C"}
    if os.name == "nt" and os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def openssh_version(keygen: Path) -> str:
    ssh = keygen.parent / ("ssh.exe" if keygen.suffix == ".exe" else "ssh")
    proc = subprocess.run([str(ssh), "-V"], capture_output=True, timeout=SIGN_TIMEOUT_S,
                          check=True, stdin=subprocess.DEVNULL)
    return (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()


def generate_key(keygen: Path, directory: Path, name: str) -> tuple[Path, str]:
    """Chave Ed25519 sem senha em ``directory``; devolve (privada, linha pública)."""
    directory.mkdir(parents=True, exist_ok=True)
    private = directory / name
    subprocess.run([str(keygen), "-q", "-t", "ed25519", "-N", "", "-C", name,
                    "-f", str(private)], env=tool_env(keygen, directory), cwd=directory,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=SIGN_TIMEOUT_S,
                   check=True)
    public = (directory / f"{name}.pub").read_text("ascii").strip()
    return private, public


def sign(keygen: Path, private: Path, message: bytes, *, home: Path,
         namespace: str = NAMESPACE) -> str:
    """Assinatura SSHSIG armorada de ``message`` (entrada padrão → saída padrão)."""
    home.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([str(keygen), "-Y", "sign", "-n", namespace, "-f", str(private)],
                          input=message, env=tool_env(keygen, home), cwd=home,
                          capture_output=True, timeout=SIGN_TIMEOUT_S, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"ssh-keygen -Y sign falhou ({proc.returncode}): "
                           f"{proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout.decode("ascii").replace("\r\n", "\n")


class SigningDevice:
    """Lado do Client nos testes: chave real e mensagem montada a partir da resposta."""

    def __init__(self, keygen: Path, home: Path) -> None:
        self.keygen = keygen
        self.home = home
        self.private, self.public = generate_key(keygen, home / ".ssh", "id_ed25519")
        self.fingerprint = parse_public_key(self.public).fingerprint

    def message(self, response: dict[str, str], *, purpose: str | None = None) -> bytes:
        return AuthMessage(response["server_id"], purpose or response["purpose"],
                           response["challenge_id"], response["nonce"], self.fingerprint,
                           parse_expires(response["expires_at"])).to_bytes()

    def sign(self, message: bytes) -> str:
        return sign(self.keygen, self.private, message, home=self.home)

    def answer(self, response: dict[str, str]) -> str:
        return self.sign(self.message(response))
