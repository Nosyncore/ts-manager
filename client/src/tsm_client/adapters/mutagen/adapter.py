"""Adaptador da CLI do Mutagen.

Operações sobre sessões usam sempre o **identificador** obtido de uma listagem filtrada
por label, nunca o nome: uma sessão alheia com o mesmo nome jamais é afetada.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from tsm_client.adapters.mutagen.errors import (
    DaemonUnavailable,
    MutagenError,
    MutagenOutputError,
    classify,
)
from tsm_client.adapters.mutagen.models import SessionState
from tsm_client.adapters.mutagen.runner import CommandResult, Runner
from tsm_client.sessions import MANAGED_SELECTOR, SyncSpec

LIST_TEMPLATE = "{{json .}}"
_CREATED_RE = re.compile(r"Created session (sync_[A-Za-z0-9]+)")
_ID_RE = re.compile(r"^sync_[A-Za-z0-9]+$")


@dataclass(frozen=True)
class Timeouts:
    default: float = 30.0
    create: float = 600.0  # inclui instalação do agente via SSH (emulação arm64 é lenta)
    flush: float = 300.0
    daemon_ready: float = 20.0


class MutagenAdapter:
    def __init__(
        self,
        executable: Path,
        runner: Runner,
        *,
        timeouts: Timeouts | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.executable = Path(executable)
        self.runner = runner
        self.timeouts = timeouts or Timeouts()
        self._sleep = sleep
        self._clock = clock

    # ------------------------------------------------------------ base

    def _run(self, *args: str, timeout: float | None = None) -> CommandResult:
        argv = [str(self.executable), *args]
        result = self.runner(argv, timeout=timeout or self.timeouts.default)
        if result.returncode != 0:
            raise classify(argv, result.returncode, result.stderr)
        return result

    def version(self) -> str:
        return self._run("version").stdout.strip()

    # ------------------------------------------------------------ daemon

    def daemon_running(self) -> bool:
        try:
            self._run(
                "sync", "list", f"--template={LIST_TEMPLATE}", "--label-selector=tsm-probe=none"
            )
        except DaemonUnavailable:
            return False
        return True

    def daemon_start(self) -> None:
        """Inicia o daemon (idempotente) e espera ele aceitar conexões."""
        self._run("daemon", "start")
        deadline = self._clock() + self.timeouts.daemon_ready
        while not self.daemon_running():
            if self._clock() >= deadline:
                raise DaemonUnavailable("o daemon não ficou pronto a tempo")
            self._sleep(0.25)

    def daemon_stop(self) -> None:
        """Para o daemon; não falha se ele já estiver parado."""
        with contextlib.suppress(DaemonUnavailable):
            self._run("daemon", "stop")

    # ------------------------------------------------------------ sessões

    def list_sessions(self, label_selector: str | None = MANAGED_SELECTOR) -> list[SessionState]:
        args = ["sync", "list", f"--template={LIST_TEMPLATE}"]
        if label_selector:
            args.append(f"--label-selector={label_selector}")
        out = self._run(*args).stdout
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise MutagenOutputError(f"JSON inválido em sync list: {exc}", argv=args) from exc
        if not isinstance(data, list):
            raise MutagenOutputError("sync list: esperado um array JSON", argv=args)
        try:
            return [SessionState.from_json(d) for d in data]
        except (KeyError, TypeError, ValueError) as exc:
            raise MutagenOutputError(f"sync list: sessão malformada: {exc}", argv=args) from exc

    @staticmethod
    def create_args(spec: SyncSpec, *, paused: bool = False) -> list[str]:
        args = ["sync", "create", "--no-global-configuration", f"--name={spec.name}"]
        args += [f"--label={k}={v}" for k, v in sorted(spec.labels.items())]
        args.append(f"--mode={spec.mode}")
        args += list(spec.flags)
        if paused:
            args.append("--paused")
        args += [spec.alpha.url, spec.beta.url]
        return args

    def create(self, spec: SyncSpec, *, paused: bool = False) -> str:
        result = self._run(*self.create_args(spec, paused=paused), timeout=self.timeouts.create)
        match = _CREATED_RE.search(result.stdout + result.stderr)
        if not match:
            raise MutagenOutputError(
                "identificador da sessão criada não encontrado na saída", argv=result.argv
            )
        return match.group(1)

    def _by_id(
        self, verb: str, ids: Sequence[str], *extra: str, timeout: float | None = None
    ) -> None:
        if not ids:
            return
        for i in ids:
            if not _ID_RE.match(i):
                raise MutagenError(f"identificador de sessão inválido: {i!r}")
        self._run("sync", verb, *extra, *ids, timeout=timeout)

    def flush(self, ids: Sequence[str], *, skip_wait: bool = False) -> None:
        extra = ("--skip-wait",) if skip_wait else ()
        self._by_id("flush", ids, *extra, timeout=self.timeouts.flush)

    def pause(self, ids: Sequence[str]) -> None:
        self._by_id("pause", ids)

    def resume(self, ids: Sequence[str]) -> None:
        self._by_id("resume", ids, timeout=self.timeouts.create)

    def terminate(self, ids: Sequence[str]) -> None:
        self._by_id("terminate", ids)
