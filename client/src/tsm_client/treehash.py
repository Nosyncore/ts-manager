"""Manifesto SHA-256 de uma árvore de diretórios.

Usado para verificar convergência (beta == alpha filtrado) e, nas fases seguintes, para
os manifestos de publicação. Links (symlinks e junctions) não são seguidos: por padrão
são omitidos, como faz o Mutagen com ``--symlink-mode=ignore``; com
``include_links=True`` aparecem como ``link:<alvo>``, útil para detectar alterações.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from tsm_client.rules import IgnoreMatcher

DIR = "dir"
_CHUNK = 1 << 20


def file_sha256(path: str | os.PathLike[str]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _is_link(entry: os.DirEntry[str]) -> bool:
    return entry.is_symlink() or entry.is_junction()


def manifest(
    root: str | os.PathLike[str],
    matcher: IgnoreMatcher | None = None,
    *,
    include_links: bool = False,
) -> dict[str, str]:
    """``{caminho relativo com '/': sha256 | 'dir' | 'link:<alvo>'}``, ordenado."""
    out: dict[str, str] = {}
    root_path = Path(root)
    if not root_path.is_dir():
        return out

    def walk(directory: str, prefix: str) -> None:
        with os.scandir(directory) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            rel = f"{prefix}{entry.name}"
            if _is_link(entry):
                if include_links:
                    try:
                        target = os.readlink(entry.path)
                    except OSError:
                        target = "?"
                    out[rel] = f"link:{target}"
                continue
            is_dir = entry.is_dir(follow_symlinks=False)
            if matcher is not None and matcher.is_ignored(rel, is_dir):
                continue
            if is_dir:
                out[rel] = DIR
                walk(entry.path, rel + "/")
            elif entry.is_file(follow_symlinks=False):
                out[rel] = file_sha256(entry.path)

    walk(str(root_path), "")
    return dict(sorted(out.items()))


def tree_digest(m: dict[str, str]) -> str:
    h = hashlib.sha256()
    for key, value in sorted(m.items()):
        h.update(key.encode("utf-8") + b"\0" + value.encode("utf-8") + b"\n")
    return h.hexdigest()
