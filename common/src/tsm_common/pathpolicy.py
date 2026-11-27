"""Política de caminhos publicáveis.

Um caminho válido no Linux pode ser impossível de materializar no Windows.
O Manager recusa a publicação inteira se algum caminho violar estas regras; o Client usa
o mesmo módulo para antecipar o erro. Caminhos são relativos à raiz do projeto, com
separador ``/``.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from tsm_common.protocol import RESERVED_DIR

DEFAULT_MAX_PATH_CHARS = 200

_INVALID_CHARS = set('<>:"|?*\\')
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in [*range(1, 10), "¹", "²", "³"]}
    | {f"LPT{i}" for i in [*range(1, 10), "¹", "²", "³"]}
)


@dataclass(frozen=True)
class PathIssue:
    path: str
    reason: str

    def __str__(self) -> str:
        return f"{self.path}: {self.reason}"


def collision_key(path: str) -> str:
    """Chave sob a qual dois caminhos são o mesmo no Windows/macOS (caixa e Unicode)."""
    return unicodedata.normalize("NFC", path).casefold()


def _reserved(component: str) -> bool:
    stem = component.split(".", 1)[0].rstrip(" ")
    return stem.upper() in _RESERVED_NAMES


def check_path(path: str, *, max_chars: int = DEFAULT_MAX_PATH_CHARS) -> str | None:
    """Motivo da recusa de um caminho isolado, ou ``None`` se ele é aceitável."""
    if not isinstance(path, str) or path == "":
        return "caminho vazio"
    if _CONTROL_RE.search(path):
        return "caractere de controle"
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return "caminho absoluto"
    if "\\" in path:
        return "barra invertida (use '/')"
    if len(path) > max_chars:
        return f"caminho com mais de {max_chars} caracteres"
    if unicodedata.normalize("NFC", path) != path:
        return "nome fora da normalização Unicode NFC"
    parts = path.split("/")
    for part in parts:
        if part == "":
            return "componente vazio ('//' ou '/' no fim)"
        if part in (".", ".."):
            return f"componente {part!r}"
        bad = sorted({c for c in part if c in _INVALID_CHARS})
        if bad:
            return f"caractere inválido no Windows: {''.join(bad)}"
        if part.endswith((".", " ")):
            return "componente terminado em ponto ou espaço"
        if _reserved(part):
            return f"nome reservado do Windows: {part}"
    if parts[0].casefold() == RESERVED_DIR:
        return f"diretório reservado ao Manager: {RESERVED_DIR}/"
    return None


def check_paths(paths: Iterable[str], *,
                max_chars: int = DEFAULT_MAX_PATH_CHARS) -> list[PathIssue]:
    issues = []
    for p in paths:
        reason = check_path(p, max_chars=max_chars)
        if reason is not None:
            issues.append(PathIssue(p, reason))
    return issues


def find_collisions(paths: Iterable[str]) -> list[PathIssue]:
    """Colisões de caixa/Unicode e arquivo × diretório num conjunto de caminhos de arquivo.

    Considera também os diretórios intermediários: ``Data/a.lua`` e ``data/b.lua``
    colidem, porque no Windows ``Data`` e ``data`` são o mesmo diretório.
    """
    files = sorted(set(paths))
    spelled: dict[str, str] = {}  # chave → grafia vista (arquivo ou diretório)
    kind: dict[str, str] = {}  # chave → "file" | "dir"
    issues: dict[str, PathIssue] = {}

    def see(name: str, what: str, origin: str) -> None:
        key = collision_key(name)
        prev = spelled.get(key)
        if prev is None:
            spelled[key], kind[key] = name, what
            return
        if prev != name:
            issues.setdefault(origin, PathIssue(origin, f"colide com {prev!r} (caixa/Unicode)"))
        elif kind[key] != what:
            issues.setdefault(origin, PathIssue(origin, f"{name!r} é arquivo e diretório"))

    for f in files:
        parts = f.split("/")
        for depth in range(1, len(parts)):
            see("/".join(parts[:depth]), "dir", f)
        see(f, "file", f)
    return sorted(issues.values(), key=lambda i: i.path)
