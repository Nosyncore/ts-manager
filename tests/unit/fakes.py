"""Runner falso para o adaptador: registra argv e devolve respostas roteirizadas."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from tsm_client.adapters.mutagen import CommandResult

Responder = Callable[[list[str]], CommandResult | Exception]

DAEMON_DOWN = "Error: unable to connect to daemon: connection timed out (is the daemon running?)\n"


def ok(stdout: str = "", stderr: str = "") -> Callable[[list[str]], CommandResult]:
    return lambda argv: CommandResult(tuple(argv), 0, stdout, stderr)


def fail(stderr: str, rc: int = 1) -> Callable[[list[str]], CommandResult]:
    return lambda argv: CommandResult(tuple(argv), rc, "", stderr)


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], float]] = []
        self.routes: list[tuple[tuple[str, ...], Responder]] = []
        self.default: Responder = ok()

    def on(self, *prefix: str, respond: Responder) -> FakeRunner:
        """Responde a chamadas cujo argv (sem o executável) começa por ``prefix``."""
        self.routes.insert(0, (prefix, respond))
        return self

    def __call__(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        argv = list(argv)
        self.calls.append((argv, timeout))
        args = argv[1:]
        for prefix, respond in self.routes:
            if tuple(args[: len(prefix)]) == prefix:
                result = respond(argv)
                break
        else:
            result = self.default(argv)
        if isinstance(result, Exception):
            raise result
        return result

    def args(self, i: int = -1) -> list[str]:
        return self.calls[i][0][1:]
