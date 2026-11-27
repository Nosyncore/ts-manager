"""Utilitários de filesystem usados pelos dois lados: escrita atômica e lock de arquivo."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any


class LockTimeout(TimeoutError):
    """Lock não obtido no prazo."""


def fsync_dir(path: Path) -> None:
    if sys.platform == "win32":
        return  # diretórios não podem ser abertos para fsync no Windows
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes, *, fsync: bool = True) -> None:
    """Grava em temporário no mesmo diretório e substitui com ``os.replace``."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            if fsync:
                fh.flush()
                os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    if fsync:
        fsync_dir(target.parent)


def atomic_write_json(path: str | os.PathLike[str], data: Any, *, fsync: bool = True) -> None:
    text = json.dumps(data, indent=1, ensure_ascii=False, sort_keys=True) + "\n"
    atomic_write_bytes(path, text.encode("utf-8"), fsync=fsync)


def read_json(path: str | os.PathLike[str]) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.Lock:
    key = os.path.normcase(str(path.resolve()))
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.Lock())


def _try_lock(fd: int) -> bool:
    if sys.platform == "win32":
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def file_lock(path: str | os.PathLike[str], timeout: float = 30.0,
              interval: float = 0.05) -> Iterator[None]:
    """Lock exclusivo entre processos (e entre threads do mesmo processo)."""
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    tlock = _thread_lock(lock_path)
    deadline = time.monotonic() + timeout
    if not tlock.acquire(timeout=max(timeout, 0)):
        raise LockTimeout(f"lock ocupado: {lock_path}")
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            while not _try_lock(fd):
                if time.monotonic() >= deadline:
                    raise LockTimeout(f"lock ocupado: {lock_path}")
                time.sleep(interval)
            try:
                yield
            finally:
                _unlock(fd)
        finally:
            os.close(fd)
    finally:
        tlock.release()
