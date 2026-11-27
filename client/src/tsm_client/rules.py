"""Regras de sincronização do Client: reexporta as regras comuns e gera as flags Mutagen.

A avaliação de caminhos (``IgnoreMatcher``) e as regras por projeto ficam em
``tsm_common.rules``, para que o Manager valide publicações com as mesmas regras.
"""

from __future__ import annotations

from tsm_common.protocol import RESERVED_DIR
from tsm_common.rules import (
    DEFAULT_IGNORES,
    PROJECT_FILE,
    VCS_DIRECTORIES,
    IgnoreMatcher,
    ProjectRules,
    RulesError,
    ignore_patterns,
    rules_digest,
)

__all__ = [
    "DEFAULT_IGNORES",
    "PROJECT_FILE",
    "RESERVED_DIR",
    "VCS_DIRECTORIES",
    "IgnoreMatcher",
    "ProjectRules",
    "RulesError",
    "ignore_patterns",
    "local_patterns",
    "rules_digest",
    "sync_flags",
]

_BASE_FLAGS = ("--ignore-syntax=mutagen", "--ignore-vcs", "--symlink-mode=ignore")


def local_patterns(rules: ProjectRules) -> list[str]:
    """Padrões para a pasta de trabalho: as regras do projeto + ``/.tsm/``."""
    return [*ignore_patterns(rules), f"/{RESERVED_DIR}/"]


def sync_flags(rules: ProjectRules, *, role: str | None = None) -> list[str]:
    """Flags de filtragem de uma sessão.

    ``.tsm/`` é reservado ao Manager no shared: o upload nunca o envia, e o
    download o inclui mesmo com lista de permitidos (o último padrão que casa vence).
    """
    flags = list(_BASE_FLAGS)
    flags += [f"--ignore={p}" for p in ignore_patterns(rules)]
    if role == "upload":
        flags.append(f"--ignore=/{RESERVED_DIR}/")
    elif role == "download" and rules.allow:
        flags.append(f"--ignore=!/{RESERVED_DIR}/")
    return flags
