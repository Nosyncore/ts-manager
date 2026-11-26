"""Erros tipados do adaptador Mutagen, derivados do código de saída e do stderr."""

from __future__ import annotations

from collections.abc import Sequence


class MutagenError(Exception):
    def __init__(
        self,
        message: str,
        *,
        argv: Sequence[str] = (),
        returncode: int | None = None,
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.argv = list(argv)
        self.returncode = returncode
        self.stderr = stderr


class MutagenNotFound(MutagenError):
    """Executável do Mutagen ausente."""


class DaemonUnavailable(MutagenError):
    """Daemon não está rodando (o autostart fica desligado de propósito)."""


class SessionNotFound(MutagenError):
    """Especificação de sessão não casou com nenhuma sessão."""


class SessionCannotSync(MutagenError):
    """Sessão desconectada, pausada ou parada por salvaguarda (ex.: flush)."""


class MutagenTimeout(MutagenError):
    """Comando excedeu o tempo limite."""


class MutagenOutputError(MutagenError):
    """Saída inesperada (JSON inválido, identificador ausente etc.)."""


_PATTERNS: tuple[tuple[str, type[MutagenError]], ...] = (
    ("unable to connect to daemon", DaemonUnavailable),
    ("did not match any sessions", SessionNotFound),
    ("not currently able to synchronize", SessionCannotSync),
    ("session is paused", SessionCannotSync),
)


def _last_error_line(stderr: str) -> str:
    lines = [ln.strip() for ln in stderr.replace("\r", "\n").splitlines() if ln.strip()]
    for ln in reversed(lines):
        if ln.startswith("Error:"):
            return ln[len("Error:") :].strip()
    return lines[-1] if lines else ""


def classify(argv: Sequence[str], returncode: int, stderr: str) -> MutagenError:
    detail = _last_error_line(stderr) or f"código de saída {returncode}"
    cls: type[MutagenError] = MutagenError
    for needle, candidate in _PATTERNS:
        if needle in stderr:
            cls = candidate
            break
    return cls(detail, argv=argv, returncode=returncode, stderr=stderr)
