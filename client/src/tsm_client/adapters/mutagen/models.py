"""Estado das sessões, a partir de ``mutagen sync list --template '{{json .}}'``.

Os valores de ``Status`` são os de ``pkg/synchronization/state.go`` (v0.18.1). Valores
desconhecidos viram ``Status.UNKNOWN`` em vez de quebrar a leitura.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from tsm_client.paths import Endpoint


class Status(StrEnum):
    DISCONNECTED = "disconnected"
    HALTED_ON_ROOT_EMPTIED = "halted-on-root-emptied"
    HALTED_ON_ROOT_DELETION = "halted-on-root-deletion"
    HALTED_ON_ROOT_TYPE_CHANGE = "halted-on-root-type-change"
    CONNECTING_ALPHA = "connecting-alpha"
    CONNECTING_BETA = "connecting-beta"
    WATCHING = "watching"
    SCANNING = "scanning"
    WAITING_FOR_RESCAN = "waiting-for-rescan"
    RECONCILING = "reconciling"
    STAGING_ALPHA = "staging-alpha"
    STAGING_BETA = "staging-beta"
    TRANSITIONING = "transitioning"
    SAVING = "saving"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: Any) -> Status:
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN

    @property
    def halted(self) -> bool:
        return self.value.startswith("halted-")


@dataclass(frozen=True)
class Problem:
    path: str
    error: str


@dataclass(frozen=True)
class EndpointState:
    protocol: str
    host: str | None
    path: str
    connected: bool
    scanned: bool
    files: int
    directories: int
    scan_problems: tuple[Problem, ...] = ()
    transition_problems: tuple[Problem, ...] = ()

    @property
    def endpoint(self) -> Endpoint:
        return Endpoint(self.host if self.protocol != "local" else None, self.path)

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> EndpointState:
        protocol = str(d.get("protocol", "local"))
        return cls(
            protocol=protocol,
            host=(str(d["host"]) if d.get("host") else None) if protocol != "local" else None,
            path=str(d.get("path", "")),
            connected=bool(d.get("connected", False)),
            scanned=bool(d.get("scanned", False)),
            files=int(d.get("files", 0) or 0),
            directories=int(d.get("directories", 0) or 0),
            scan_problems=_problems(d.get("scanProblems")),
            transition_problems=_problems(d.get("transitionProblems")),
        )


def _problems(raw: Any) -> tuple[Problem, ...]:
    if not isinstance(raw, list):
        return ()
    return tuple(
        Problem(path=str(p.get("path", "")), error=str(p.get("error", "")))
        for p in raw
        if isinstance(p, dict)
    )


@dataclass(frozen=True)
class SessionState:
    identifier: str
    name: str
    labels: dict[str, str]
    status: Status
    raw_status: str
    paused: bool
    mode: str
    alpha: EndpointState
    beta: EndpointState
    last_error: str | None = None
    conflicts: int = 0
    successful_cycles: int = 0
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def problems(self) -> tuple[Problem, ...]:
        return (
            self.alpha.scan_problems
            + self.alpha.transition_problems
            + self.beta.scan_problems
            + self.beta.transition_problems
        )

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> SessionState:
        labels = d.get("labels") or {}
        conflicts = d.get("conflicts") or []
        raw_status = str(d.get("status", ""))
        return cls(
            identifier=str(d["identifier"]),
            name=str(d.get("name", "")),
            labels={str(k): str(v) for k, v in labels.items()},
            status=Status.parse(raw_status),
            raw_status=raw_status,
            paused=bool(d.get("paused", False)),
            mode=str(d.get("mode", "")),
            alpha=EndpointState.from_json(d.get("alpha") or {}),
            beta=EndpointState.from_json(d.get("beta") or {}),
            last_error=str(d["lastError"]) if d.get("lastError") else None,
            conflicts=len(conflicts) if isinstance(conflicts, list) else 0,
            successful_cycles=int(d.get("successfulCycles", 0) or 0),
            raw=d,
        )
