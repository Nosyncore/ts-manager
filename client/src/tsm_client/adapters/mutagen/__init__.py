"""Adaptador Mutagen: único ponto do Client que executa o binário do Mutagen."""

from tsm_client.adapters.mutagen.adapter import MutagenAdapter, Timeouts
from tsm_client.adapters.mutagen.errors import (
    DaemonUnavailable,
    MutagenError,
    MutagenNotFound,
    MutagenOutputError,
    MutagenTimeout,
    SessionCannotSync,
    SessionNotFound,
)
from tsm_client.adapters.mutagen.models import EndpointState, Problem, SessionState, Status
from tsm_client.adapters.mutagen.runner import CommandResult, SubprocessRunner, mutagen_env

__all__ = [
    "CommandResult",
    "DaemonUnavailable",
    "EndpointState",
    "MutagenAdapter",
    "MutagenError",
    "MutagenNotFound",
    "MutagenOutputError",
    "MutagenTimeout",
    "Problem",
    "SessionCannotSync",
    "SessionNotFound",
    "SessionState",
    "Status",
    "SubprocessRunner",
    "Timeouts",
    "mutagen_env",
]
