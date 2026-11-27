"""Pull: verificação do cache e plano de três vias, sem efeitos.

Para cada caminho, compara base (armazenamento local), local (pasta de trabalho) e
theirs (revisão verificada no cache):

| base × local × theirs                     | ação                                   |
|-------------------------------------------|----------------------------------------|
| local == theirs                           | nada                                   |
| local == base                             | aplica theirs (escreve ou apaga)       |
| theirs == base                            | mantém local                           |
| texto alterado nos dois lados             | merge-file; limpo → escreve; senão conflito |
| binário nos dois lados, exclusão × modificação, criação × criação | conflito    |

Conflitos bloqueiam tudo, salvo resolução explícita por caminho.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from tsm_client.adapters.git import MergeOutcome
from tsm_client.objects import ObjectStore
from tsm_common.manifest import file_sha256
from tsm_common.protocol import RESERVED_DIR, REVISION_FILE, RevisionFormatError, RevisionInfo
from tsm_common.rules import IgnoreMatcher

KEEP, WRITE, DELETE, MERGE, MARKERS, CONFLICT = (
    "keep", "write", "delete", "merge", "markers", "conflict")
RESOLUTIONS = ("ours", "theirs", "markers")
MARKER_PREFIXES = (b"<<<<<<< ", b">>>>>>> ")


class CacheNotReady(RuntimeError):
    """O cache não confere com o ``revision.json`` (atualização em curso)."""


class PlanError(ValueError):
    """Resolução inválida (caminho sem conflito, ``markers`` em binário etc.)."""


@dataclass
class PullOp:
    path: str
    action: str
    base: str | None
    ours: str | None
    theirs: str | None
    kind: str | None = None  # tipo do conflito, quando houver
    content: bytes | None = None  # resultado do merge / marcadores
    resolution: str | None = None

    @property
    def changes_local(self) -> bool:
        return self.action in (WRITE, DELETE, MERGE, MARKERS)


@dataclass
class PullPlan:
    ops: list[PullOp] = field(default_factory=list)

    @property
    def conflicts(self) -> list[PullOp]:
        return [o for o in self.ops if o.action == CONFLICT]

    @property
    def changes(self) -> list[PullOp]:
        return [o for o in self.ops if o.changes_local]

    @property
    def deletes(self) -> list[PullOp]:
        return [o for o in self.ops if o.action == DELETE]

    @property
    def markers(self) -> list[str]:
        return [o.path for o in self.ops if o.action == MARKERS]


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8000]


def has_markers(data: bytes) -> bool:
    return any(line.startswith(MARKER_PREFIXES) for line in data.splitlines())


Merger = Callable[[bytes, bytes, bytes], MergeOutcome]
Loader = Callable[[str], bytes]


def plan_pull(base: dict[str, str], ours: dict[str, str], theirs: dict[str, str], *,
              load_base: Loader, load_ours: Callable[[str], bytes], load_theirs: Loader,
              merger: Merger, resolutions: dict[str, str] | None = None) -> PullPlan:
    resolutions = dict(resolutions or {})
    for path, r in resolutions.items():
        if r not in RESOLUTIONS:
            raise PlanError(f"{path}: resolução {r!r} inválida (use {', '.join(RESOLUTIONS)})")
    plan = PullPlan()
    for path in sorted(set(base) | set(ours) | set(theirs)):
        b, o, t = base.get(path), ours.get(path), theirs.get(path)
        if o == t:
            continue
        if o == b:
            plan.ops.append(PullOp(path, DELETE if t is None else WRITE, b, o, t))
            continue
        if t == b:
            plan.ops.append(PullOp(path, KEEP, b, o, t))
            continue
        # alterado dos dois lados
        if o is None or t is None:
            op = PullOp(path, CONFLICT, b, o, t, kind="delete_modify")
        else:
            od, td = load_ours(path), load_theirs(t)
            bd = load_base(b) if b is not None else b""
            if is_binary(od) or is_binary(td) or is_binary(bd):
                op = PullOp(path, CONFLICT, b, o, t, kind="binary")
            else:
                merged = merger(od, bd, td)
                kind = "add_add" if b is None else "content"
                if merged.clean and b is not None:
                    op = PullOp(path, MERGE, b, o, t, content=merged.content)
                else:
                    op = PullOp(path, CONFLICT, b, o, t, kind=kind, content=merged.content)
        plan.ops.append(op)

    by_path = {op.path: op for op in plan.ops}
    for path, r in resolutions.items():
        op = by_path.get(path)
        if op is None or op.action != CONFLICT:
            raise PlanError(f"{path}: não há conflito neste caminho")
        op.resolution = r
        if r == "ours":
            op.action = KEEP
        elif r == "theirs":
            op.action = DELETE if op.theirs is None else WRITE
            op.content = None
        else:
            if op.kind not in ("content", "add_add") or op.content is None:
                raise PlanError(f"{path}: 'markers' só vale para texto alterado dos dois lados")
            op.action = MARKERS
    return plan


# ---------------------------------------------------------------- cache


def read_cache(cache: Path, matcher: IgnoreMatcher, objects: ObjectStore) -> RevisionInfo:
    """Lê e verifica o cache contra ``revision.json``, guardando cada arquivo no armazenamento.

    A conferência é sobre a cópia guardada (ou sobre o hash do arquivo, se o conteúdo já
    está no armazenamento). Qualquer divergência → ``CacheNotReady``.
    """
    try:
        info = RevisionInfo.from_json((cache / REVISION_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CacheNotReady("revision.json ainda não chegou ao cache") from exc
    except (RevisionFormatError, UnicodeDecodeError) as exc:
        raise CacheNotReady(f"revision.json inválido ou incompleto: {exc}") from exc
    seen: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(cache):
        rel_dir = Path(dirpath).relative_to(cache).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        if rel_dir == "":
            dirnames[:] = [d for d in dirnames if d != RESERVED_DIR]
        dirnames[:] = [d for d in dirnames if not matcher.is_ignored(rel_dir + d, True)
                       and not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            rel = rel_dir + name
            full = Path(dirpath) / name
            if full.is_symlink() or matcher.is_ignored(rel, False):
                continue
            expected = info.files.get(rel)
            if expected is None:
                raise CacheNotReady(f"{rel}: no cache, mas fora da revisão r{info.revision}")
            if objects.has(expected):
                ok = file_sha256(full) == expected
            else:
                sha, _ = objects.put_file(full)
                ok = sha == expected
            if not ok:
                raise CacheNotReady(f"{rel}: conteúdo do cache difere da revisão r{info.revision}")
            seen.add(rel)
    missing = sorted(set(info.files) - seen)
    if missing:
        raise CacheNotReady(f"{len(missing)} arquivo(s) da revisão r{info.revision} ainda "
                            f"ausentes no cache (ex.: {missing[0]})")
    return info


def wait_cache(read: Callable[[], RevisionInfo], *, timeout: float,
               poll: Callable[[], None] | None = None,
               accept: Callable[[RevisionInfo], bool] | None = None,
               interval: float = 1.0) -> RevisionInfo:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while True:
        try:
            info = read()
            if accept is None or accept(info):
                return info
            last = CacheNotReady(f"cache em r{info.revision}; aguardando revisão mais nova")
        except CacheNotReady as exc:
            last = exc
        if time.monotonic() >= deadline:
            raise CacheNotReady(str(last)) from last
        time.sleep(interval)
        if poll is not None:
            poll()
