"""Armazenamento local endereçado por SHA-256.

Guarda os conteúdos da base, das revisões importadas e os conteúdos locais anteriores a
um pull. A cópia é feita **antes** do hash: o que se publica ou compara é o que ficou no
armazenamento, não o arquivo original, que pode mudar no meio da operação.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
from pathlib import Path

_CHUNK = 1 << 20


class ObjectStoreError(RuntimeError):
    """Objeto ausente ou corrompido."""


class ObjectStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, sha: str) -> Path:
        return self.root / sha[:2] / sha[2:]

    def has(self, sha: str) -> bool:
        return self.path(sha).is_file()

    def _tmp(self) -> tuple[int, str]:
        self.root.mkdir(parents=True, exist_ok=True)
        return tempfile.mkstemp(prefix="incoming-", dir=self.root)

    def _commit(self, tmp: str, sha: str) -> None:
        dest = self.path(sha)
        if dest.is_file():
            os.unlink(tmp)
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(tmp, dest)
        except OSError:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            if not dest.is_file():
                raise

    def put_file(self, src: str | os.PathLike[str]) -> tuple[str, int]:
        """Copia ``src`` e devolve ``(sha256 da cópia, tamanho)``."""
        fd, tmp = self._tmp()
        h = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(fd, "wb") as out, open(src, "rb") as fh:
                while chunk := fh.read(_CHUNK):
                    h.update(chunk)
                    size += len(chunk)
                    out.write(chunk)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        sha = h.hexdigest()
        self._commit(tmp, sha)
        return sha, size

    def put_bytes(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        if self.has(sha):
            return sha
        fd, tmp = self._tmp()
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        self._commit(tmp, sha)
        return sha

    def read(self, sha: str) -> bytes:
        p = self.path(sha)
        try:
            data = p.read_bytes()
        except FileNotFoundError as exc:
            raise ObjectStoreError(f"objeto ausente: {sha[:12]}") from exc
        if hashlib.sha256(data).hexdigest() != sha:
            raise ObjectStoreError(f"objeto corrompido: {sha[:12]}")
        return data

    def size(self, sha: str) -> int:
        return self.path(sha).stat().st_size
