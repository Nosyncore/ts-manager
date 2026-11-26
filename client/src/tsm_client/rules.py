"""Regras de sincronização por projeto: ignores padrão, lista de permitidos e flags Mutagen.

A ordem dos padrões importa (o último que casa vence):
1. lista de permitidos (``/*`` + ``!/ts-project.json`` + ``!/<entrada>``), se houver;
2. ignores do projeto;
3. ignores padrão (por último, para que o projeto não consiga "designorar" segredos,
   logs ou builds).

``IgnoreMatcher`` reproduz a semântica da sintaxe ``mutagen`` para o subconjunto usado
aqui; serve para os testes compararem árvores e, nas fases seguintes, para a verificação
de manifestos. Ignores não são fronteira de segurança: o servidor valida por conta própria.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

PROJECT_FILE = "ts-project.json"

# .git e outros VCS saem via --ignore-vcs (tratados também no matcher).
DEFAULT_IGNORES: tuple[str, ...] = (
    # segredos e configuração privada
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "id_ed25519*",
    # logs, builds e caches
    "*.log",
    "logs/",
    "build/",
    "dist/",
    "__pycache__/",
    "*.pyc",
    ".cache/",
    "node_modules/",
    # temporários de editor/SO
    "*.tmp",
    "*.swp",
    "*~",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".vscode/",
    ".idea/",
)

VCS_DIRECTORIES: tuple[str, ...] = (".git", ".svn", ".hg", ".bzr", "_darcs")

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ALLOW_RE = re.compile(r"^[A-Za-z0-9._-]+/?$")


class RulesError(ValueError):
    """Regra de sincronização inválida."""


def _validate_pattern(p: str) -> str:
    if not isinstance(p, str) or not p.strip():
        raise RulesError("padrão de ignore vazio")
    if p != p.strip():
        raise RulesError(f"padrão com espaço nas pontas: {p!r}")
    if _CONTROL_RE.search(p):
        raise RulesError(f"padrão com caractere de controle: {p!r}")
    # pflag interpreta valores de --ignore como CSV: vírgula/aspas quebrariam o padrão
    for bad in ("\\", ",", '"'):
        if bad in p:
            raise RulesError(f"padrão com caractere não suportado {bad!r}: {p!r}")
    body = p[1:] if p.startswith("!") else p
    if body in ("", "/"):
        raise RulesError(f"padrão sem conteúdo: {p!r}")
    if re.match(r"^/?[A-Za-z]:", body):
        raise RulesError(f"padrão parece caminho Windows: {p!r}")
    if ".." in body.split("/"):
        raise RulesError(f"padrão com '..': {p!r}")
    return p


def _validate_allow(entry: str) -> str:
    if not isinstance(entry, str) or not _ALLOW_RE.match(entry) or entry.strip("./") == "":
        raise RulesError(
            f"entrada de lista de permitidos inválida {entry!r}: use um nome de primeiro nível, "
            "como 'data/' ou 'ts-project.json'"
        )
    return entry


@dataclass(frozen=True)
class ProjectRules:
    allow: tuple[str, ...] = ()
    ignore: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "allow", tuple(_validate_allow(a) for a in self.allow))
        object.__setattr__(self, "ignore", tuple(_validate_pattern(p) for p in self.ignore))

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ProjectRules:
        data = data or {}
        unknown = set(data) - {"allow", "ignore"}
        if unknown:
            raise RulesError(f"campos desconhecidos em rules: {sorted(unknown)}")
        allow, ignore = data.get("allow", []), data.get("ignore", [])
        if not isinstance(allow, list) or not isinstance(ignore, list):
            raise RulesError("rules.allow e rules.ignore precisam ser listas")
        return cls(allow=tuple(allow), ignore=tuple(ignore))


def ignore_patterns(rules: ProjectRules) -> list[str]:
    patterns: list[str] = []
    if rules.allow:
        patterns += ["/*", f"!/{PROJECT_FILE}"]
        patterns += [f"!/{a}" for a in rules.allow if a.rstrip("/") != PROJECT_FILE]
    patterns += list(rules.ignore)
    patterns += list(DEFAULT_IGNORES)
    return patterns


def sync_flags(rules: ProjectRules) -> list[str]:
    """Flags de filtragem comuns às duas sessões de um vínculo."""
    flags = ["--ignore-syntax=mutagen", "--ignore-vcs", "--symlink-mode=ignore"]
    flags += [f"--ignore={p}" for p in ignore_patterns(rules)]
    return flags


# ---------------------------------------------------------------- matcher


def _glob_to_regex(glob: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            if glob.startswith("**", i):
                # "**/" casa zero ou mais diretórios; "**" isolado casa qualquer coisa
                if glob.startswith("**/", i):
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            end = glob.find("]", i + 1)
            if end == -1:
                out.append(re.escape(c))
            else:
                body = glob[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = end
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


@dataclass(frozen=True)
class _Rule:
    regex: re.Pattern[str]
    negated: bool
    dir_only: bool
    match_leaf: bool


class IgnoreMatcher:
    """Avalia caminhos relativos (separador ``/``) contra padrões na sintaxe mutagen."""

    def __init__(self, patterns: Iterable[str], *, ignore_vcs: bool = True) -> None:
        self._ignore_vcs = ignore_vcs
        self._rules: list[_Rule] = []
        for raw in patterns:
            p = raw
            negated = p.startswith("!")
            if negated:
                p = p[1:]
            absolute = p.startswith("/")
            if absolute:
                p = p[1:]
            dir_only = p.endswith("/")
            if dir_only:
                p = p.rstrip("/")
            self._rules.append(
                _Rule(
                    regex=_glob_to_regex(p),
                    negated=negated,
                    dir_only=dir_only,
                    match_leaf=not absolute and "/" not in p,
                )
            )

    def _own_status(self, path: str, is_dir: bool) -> bool:
        name = path.rsplit("/", 1)[-1]
        if self._ignore_vcs and is_dir and name in VCS_DIRECTORIES:
            return True
        ignored = False
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            target = name if rule.match_leaf else path
            if rule.regex.match(target):
                ignored = not rule.negated
        return ignored

    def is_ignored(self, path: str, is_dir: bool) -> bool:
        """Ignorado se o próprio caminho ou algum diretório ancestral é ignorado."""
        parts: Sequence[str] = [p for p in path.replace("\\", "/").split("/") if p]
        for depth in range(1, len(parts)):
            if self._own_status("/".join(parts[:depth]), True):
                return True
        return self._own_status("/".join(parts), is_dir)
