"""Canonicalização de caminhos e detecção de sobreposição entre endpoints.

Regras:
- caminhos locais precisam ser absolutos, sem ``..``, sem UNC/device (``\\\\server``,
  ``\\\\?\\``) e a raiz não pode ser symlink nem junction;
- caminhos remotos são POSIX absolutos, sem ``..``, ``~``, barra invertida ou
  caracteres de controle; o host é um alias SSH simples (sem usuário/porta, para que
  toda a configuração de conexão venha da config SSH gerenciada);
- a comparação local é case-insensitive no Windows; a remota é case-sensitive.
"""

from __future__ import annotations

import os
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path

WINDOWS = sys.platform == "win32"

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$")
_WIN_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class PathError(ValueError):
    """Caminho inválido ou inseguro para uso como raiz de sincronização."""


@dataclass(frozen=True)
class Endpoint:
    """Raiz de sincronização: local (``host`` = None) ou remota via alias SSH."""

    host: str | None
    path: str

    @property
    def is_remote(self) -> bool:
        return self.host is not None

    @property
    def url(self) -> str:
        """Forma aceita pelo Mutagen."""
        return f"{self.host}:{self.path}" if self.host else self.path

    def __str__(self) -> str:
        return self.url


def _split_parts(p: str) -> list[str]:
    return [part for part in re.split(r"[\\/]", p) if part]


def _is_link(p: Path) -> bool:
    try:
        return p.is_symlink() or p.is_junction()
    except OSError:
        return False


def canonical_local(raw: str | os.PathLike[str]) -> str:
    """Valida e devolve a forma canônica de um caminho local."""
    p = os.fspath(raw)
    if not p or not p.strip():
        raise PathError("caminho local vazio")
    if _CONTROL_RE.search(p):
        raise PathError(f"caminho com caractere de controle: {p!r}")
    if p.startswith(("\\\\", "//")):
        raise PathError(f"caminhos UNC/device não são suportados: {p}")
    if WINDOWS:
        drive, _ = os.path.splitdrive(p)
        if not drive or not _WIN_ABS_RE.match(p):
            raise PathError(f"o caminho precisa ser absoluto, com unidade: {p}")
    elif not os.path.isabs(p):
        raise PathError(f"o caminho precisa ser absoluto: {p}")
    if ".." in _split_parts(p):
        raise PathError(f"o caminho não pode conter '..': {p}")

    normalized = os.path.normpath(p)
    if _is_link(Path(normalized)):
        raise PathError(f"a raiz não pode ser symlink nem junction (link): {normalized}")
    # resolve links em ancestrais, para comparar locais reais
    return os.path.realpath(normalized)


def canonical_remote(raw: str) -> str:
    """Valida e devolve a forma canônica de um caminho POSIX remoto."""
    if not raw:
        raise PathError("caminho remoto vazio")
    if _CONTROL_RE.search(raw) or "\\" in raw:
        raise PathError(f"caminho remoto com caractere inválido: {raw!r}")
    if not raw.startswith("/"):
        raise PathError(f"o caminho remoto precisa ser absoluto: {raw}")
    if ".." in raw.split("/"):
        raise PathError(f"o caminho remoto não pode conter '..': {raw}")
    normalized = posixpath.normpath(raw)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    if normalized == "/":
        raise PathError("a raiz '/' não pode ser endpoint")
    return normalized


def parse_endpoint(spec: str) -> Endpoint:
    """Interpreta ``C:\\dir`` / ``/dir`` (local) ou ``alias:/dir`` (remoto)."""
    if not spec:
        raise PathError("endpoint vazio")
    looks_local = (
        _WIN_ABS_RE.match(spec) is not None
        or spec.startswith(("\\\\", "//"))
        or (not WINDOWS and spec.startswith("/"))
        or ":" not in spec
    )
    if looks_local:
        return Endpoint(None, canonical_local(spec))
    host, _, path = spec.partition(":")
    if not _HOST_RE.match(host):
        raise PathError(
            f"host SSH inválido {host!r}: use um alias da config gerenciada (sem usuário/porta)"
        )
    return Endpoint(host, canonical_remote(path))


def _key(ep: Endpoint) -> tuple[str | None, str]:
    if ep.host is None:
        return None, os.path.normcase(ep.path)
    return ep.host.lower(), ep.path


def _contains(parent: str, child: str, sep: str) -> bool:
    if parent == child:
        return True
    prefix = parent if parent.endswith(sep) else parent + sep
    return child.startswith(prefix)


def endpoints_overlap(a: Endpoint, b: Endpoint) -> bool:
    """Verdadeiro se ``a`` e ``b`` são iguais ou um contém o outro."""
    (ha, pa), (hb, pb) = _key(a), _key(b)
    if ha != hb:
        return False
    sep = os.sep if ha is None else "/"
    return _contains(pa, pb, sep) or _contains(pb, pa, sep)
