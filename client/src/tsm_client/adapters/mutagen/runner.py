"""Execução de subprocessos do Mutagen com ambiente isolado.

Único ponto do Client que chama ``subprocess``. O ambiente:
- remove qualquer ``MUTAGEN_*`` herdado;
- define ``MUTAGEN_DATA_DIRECTORY`` (daemon isolado por Client/teste);
- define ``MUTAGEN_DISABLE_AUTOSTART=1`` (o daemon só sobe por ``daemon start`` explícito,
  garantindo que ele herde o ambiente abaixo);
- opcionalmente ``MUTAGEN_SSH_PATH`` (OpenSSH do Git for Windows) e ``HOME`` gerenciado,
  onde ficam a config SSH, o ``known_hosts`` e as chaves do Client. Com ``HOME``
  gerenciado, ``SSH_AUTH_SOCK`` também é removido para não usar o agente pessoal.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from tsm_client.adapters.mutagen.errors import MutagenNotFound, MutagenTimeout


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    def __call__(self, argv: Sequence[str], *, timeout: float) -> CommandResult: ...


def mutagen_env(
    data_directory: Path,
    *,
    ssh_path: Path | None = None,
    ssh_home: Path | None = None,
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    env = {
        k: v
        for k, v in (os.environ if base is None else base).items()
        if not k.upper().startswith("MUTAGEN_")
    }
    env["MUTAGEN_DATA_DIRECTORY"] = str(data_directory)
    env["MUTAGEN_DISABLE_AUTOSTART"] = "1"
    if ssh_path is not None:
        env["MUTAGEN_SSH_PATH"] = str(ssh_path)
    if ssh_home is not None:
        env["HOME"] = str(ssh_home)
        env.pop("SSH_AUTH_SOCK", None)
    return env


class SubprocessRunner:
    def __init__(self, env: Mapping[str, str]) -> None:
        self.env = dict(env)

    def __call__(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            proc = subprocess.run(
                list(argv),
                env=self.env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                creationflags=flags,
                check=False,
            )
        except FileNotFoundError as exc:
            raise MutagenNotFound(f"executável não encontrado: {argv[0]}", argv=argv) from exc
        except subprocess.TimeoutExpired as exc:
            raise MutagenTimeout(f"tempo esgotado ({timeout:.0f}s)", argv=argv) from exc
        return CommandResult(tuple(argv), proc.returncode, proc.stdout or "", proc.stderr or "")


def tool_version(executable: Path, flag: str = "--version") -> str:
    """Primeira linha de ``<executable> <flag>`` (diagnóstico do ``doctor``)."""
    try:
        out = subprocess.run([str(executable), flag], capture_output=True, text=True,
                             timeout=10, check=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return "não executável"
    text = (out.stderr or out.stdout).strip()
    return text.splitlines()[0] if text else "?"
