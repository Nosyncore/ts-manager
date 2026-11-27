"""Mudanças locais contra a base (funciona offline)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tsm_client.rules import local_patterns
from tsm_common.manifest import files_only, manifest
from tsm_common.rules import IgnoreMatcher, ProjectRules

ADDED, MODIFIED, DELETED = "added", "modified", "deleted"


@dataclass(frozen=True)
class LocalChange:
    path: str
    kind: str  # added | modified | deleted
    sha: str | None  # conteúdo local atual (None se excluído)
    base_sha: str | None


def local_matcher(rules: ProjectRules) -> IgnoreMatcher:
    return IgnoreMatcher(local_patterns(rules))


def local_manifest(root: Path, rules: ProjectRules) -> dict[str, str]:
    return files_only(manifest(root, local_matcher(rules)))


def filter_manifest(files: dict[str, str], rules: ProjectRules) -> dict[str, str]:
    m = local_matcher(rules)
    return {p: s for p, s in files.items() if not m.is_ignored(p, False)}


def diff(base: dict[str, str], local: dict[str, str]) -> list[LocalChange]:
    out = []
    for path in sorted(set(base) | set(local)):
        b, cur = base.get(path), local.get(path)
        if b == cur:
            continue
        kind = ADDED if b is None else DELETED if cur is None else MODIFIED
        out.append(LocalChange(path, kind, cur, b))
    return out


def normalize_selector(raw: str) -> str:
    s = raw.replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    return s.rstrip("/")


def select(changes: list[LocalChange], selectors: list[str] | None) -> tuple[
        list[LocalChange], list[str]]:
    """Mudanças escolhidas por caminho exato ou prefixo de diretório; devolve as não achadas."""
    if selectors is None:
        return list(changes), []
    chosen: dict[str, LocalChange] = {}
    missing = []
    for raw in selectors:
        sel = normalize_selector(raw)
        hits = [c for c in changes if c.path == sel or c.path.startswith(sel + "/")]
        if not hits:
            missing.append(raw)
        for c in hits:
            chosen[c.path] = c
    return [chosen[p] for p in sorted(chosen)], missing


MASS_DELETE_COUNT = 10
MASS_DELETE_RATIO_MIN = 3


def mass_deletion(n_deleted: int, n_base: int) -> bool:
    """Exclusão em massa: mais de 10 arquivos, ou mais de 20% da base com pelo menos 3 exclusões.

    O mínimo de 3 evita que, num projeto pequeno, qualquer exclusão isolada exija
    confirmação (com 4 arquivos, 1 exclusão já passa de 20%).
    """
    if n_deleted > MASS_DELETE_COUNT:
        return True
    return n_deleted >= MASS_DELETE_RATIO_MIN and n_deleted * 5 > n_base
