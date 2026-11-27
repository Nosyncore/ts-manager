"""Execução de processos auxiliares (``ssh-keygen``, ``icacls``): sem shell, sem janela.

Os adaptadores recebem um ``ProcRunner`` por injeção; os unitários usam um falso que
registra ``argv``, ambiente, diretório atual e entrada padrão.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class ProcessFailure(RuntimeError):
    """Executável ausente ou tempo esgotado."""


@dataclass(frozen=True)
class ProcResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes

    def stderr_line(self, limit: int = 200) -> str:
        text = self.stderr.decode("utf-8", "replace").strip()
        first = text.splitlines()[0] if text else ""
        return first[:limit]


class ProcRunner(Protocol):
    def __call__(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None,
                 cwd: Path | None = None, input: bytes | None = None,
                 timeout: float) -> ProcResult: ...


def run_process(argv: Sequence[str], *, env: Mapping[str, str] | None = None,
                cwd: Path | None = None, input: bytes | None = None,
                timeout: float) -> ProcResult:
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            list(argv), env=None if env is None else dict(env), cwd=cwd,
            input=input, stdin=None if input is not None else subprocess.DEVNULL,
            capture_output=True, timeout=timeout, creationflags=flags, check=False)
    except FileNotFoundError as exc:
        raise ProcessFailure(f"executável não encontrado: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ProcessFailure(f"tempo esgotado ({timeout:.0f}s): {Path(argv[0]).name}") from exc
    return ProcResult(tuple(argv), proc.returncode, proc.stdout or b"", proc.stderr or b"")
