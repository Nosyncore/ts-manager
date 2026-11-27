"""Filesystem do Manager: leitura segura do workspace e escrita controlada do shared.

- Leitura do workspace: cada componente do caminho é conferido com ``lstat`` (nenhum
  symlink, junction ou reparse point; o final precisa ser arquivo regular) e o arquivo
  aberto é conferido de novo com ``fstat``. Nada fora da raiz do workspace é lido.
- Escrita no shared: o conteúdo vai para um temporário em ``history/tmp`` (mesmo
  filesystem), recebe grupo e modo do shared e entra no lugar com ``os.replace``. Nenhum
  temporário aparece dentro do shared.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

_CHUNK = 1 << 20
FILE_MODE = 0o640
DIR_MODE = 0o2750
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class UnsafePathError(ValueError):
    """Caminho do workspace não é um arquivo regular dentro da raiz."""


class SizeExceeded(ValueError):
    """Arquivo maior que o limite durante a cópia."""


@dataclass(frozen=True)
class CopiedFile:
    sha256: str
    size: int


def _is_link_stat(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & _REPARSE)


def _check_components(root: Path, rel: str) -> Path:
    if not rel or rel.startswith("/") or "\\" in rel:
        raise UnsafePathError(f"caminho inválido: {rel!r}")
    current = root
    parts = rel.split("/")
    for i, part in enumerate(parts):
        if part in ("", ".", ".."):
            raise UnsafePathError(f"componente inválido em {rel!r}")
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError as exc:
            raise FileNotFoundError(rel) from exc
        if _is_link_stat(st):
            raise UnsafePathError(f"{rel}: link no caminho ({'/'.join(parts[: i + 1])})")
        last = i == len(parts) - 1
        if not last and not stat.S_ISDIR(st.st_mode):
            raise UnsafePathError(f"{rel}: {'/'.join(parts[: i + 1])} não é diretório")
        if last and not stat.S_ISREG(st.st_mode):
            raise UnsafePathError(f"{rel}: não é arquivo regular")
    return current


def copy_from_workspace(root: Path, rel: str, dest: Path, max_bytes: int) -> CopiedFile:
    """Copia ``root/rel`` para ``dest`` calculando o SHA-256 **da cópia**."""
    src = _check_components(root, rel)
    before = os.lstat(src)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(src, flags)
    try:
        after = os.fstat(fd)
        if sys.platform != "win32" and (after.st_ino, after.st_dev) != (before.st_ino,
                                                                        before.st_dev):
            raise UnsafePathError(f"{rel}: arquivo trocado durante a abertura")
        if not stat.S_ISREG(after.st_mode):
            raise UnsafePathError(f"{rel}: não é arquivo regular")
        dest.parent.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256()
        size = 0
        with os.fdopen(os.dup(fd), "rb") as src_fh, open(dest, "wb") as out:
            while chunk := src_fh.read(_CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise SizeExceeded(f"{rel}: maior que {max_bytes} bytes")
                h.update(chunk)
                out.write(chunk)
        with open(dest, "rb") as check:  # hash do que ficou no staging
            h2 = hashlib.sha256()
            while chunk := check.read(_CHUNK):
                h2.update(chunk)
        if h2.hexdigest() != h.hexdigest():
            raise UnsafePathError(f"{rel}: cópia no staging divergiu")
        return CopiedFile(h.hexdigest(), size)
    finally:
        os.close(fd)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


class SharedWriter:
    """Escreve no shared com grupo/modo fixos; temporários ficam em ``tmp_dir``."""

    def __init__(self, shared: Path, tmp_dir: Path, group: str | None = None) -> None:
        self.shared = shared
        self.tmp_dir = tmp_dir
        self._gid: int | None = None
        if group and sys.platform != "win32":
            import grp

            self._gid = grp.getgrnam(group).gr_gid

    def _apply(self, path: Path, mode: int) -> None:
        if sys.platform == "win32":
            return
        if self._gid is not None:
            os.chown(path, -1, self._gid)
        os.chmod(path, mode)

    def ensure_dir(self, rel_dir: str) -> None:
        current = self.shared
        for part in [p for p in rel_dir.split("/") if p]:
            current = current / part
            if current.is_file() or current.is_symlink():
                current.unlink()
            if not current.is_dir():
                current.mkdir()
                self._apply(current, DIR_MODE)

    @contextlib.contextmanager
    def temp_file(self) -> Iterator[Path]:
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix="shared-", dir=self.tmp_dir)
        os.close(fd)
        path = Path(name)
        try:
            yield path
        finally:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()

    def install(self, tmp: Path, rel: str) -> None:
        """Coloca ``tmp`` em ``shared/rel`` de forma atômica (após fsync)."""
        parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
        self.ensure_dir(parent)
        target = self.shared / rel
        if target.is_dir() and not target.is_symlink():
            remove_tree(target)
        with open(tmp, "rb+") as fh:
            os.fsync(fh.fileno())
        self._apply(tmp, FILE_MODE)
        os.replace(tmp, target)

    def remove(self, rel: str) -> None:
        target = self.shared / rel
        with contextlib.suppress(FileNotFoundError):
            if target.is_dir() and not target.is_symlink():
                remove_tree(target)
            else:
                target.unlink()

    def prune_empty_dirs(self, keep: tuple[str, ...] = ()) -> None:
        for dirpath, dirnames, filenames in os.walk(self.shared, topdown=False):
            p = Path(dirpath)
            if p == self.shared:
                continue
            rel = p.relative_to(self.shared).as_posix()
            if rel.split("/")[0] in keep:
                continue
            if not dirnames and not filenames:
                with contextlib.suppress(OSError):
                    p.rmdir()


def remove_tree(path: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for f in filenames:
            os.unlink(os.path.join(dirpath, f))
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                os.unlink(full)
            else:
                os.rmdir(full)
    os.rmdir(path)


def scan_files(root: Path, skip_top: tuple[str, ...] = ()) -> dict[str, str]:
    """``{caminho: sha256}`` dos arquivos regulares sob ``root`` (links não seguidos)."""
    out: dict[str, str] = {}
    if not root.is_dir():
        return out

    def walk(d: Path, prefix: str) -> None:
        with os.scandir(d) as it:
            for e in sorted(it, key=lambda x: x.name):
                rel = f"{prefix}{e.name}"
                if not prefix and e.name in skip_top:
                    continue
                if e.is_symlink() or e.is_junction():
                    out[rel] = "link"
                    continue
                if e.is_dir(follow_symlinks=False):
                    walk(Path(e.path), rel + "/")
                elif e.is_file(follow_symlinks=False):
                    out[rel] = sha256_file(Path(e.path))

    walk(root, "")
    return out
