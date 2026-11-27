"""Exceções compartilhadas pelos módulos do Client."""

from __future__ import annotations


class RefusedError(Exception):
    """Operação recusada por segurança (salvaguarda, config alterada, recusa do Manager)."""
