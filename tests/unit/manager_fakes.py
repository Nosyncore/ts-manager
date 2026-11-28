"""Git, Store e vínculos em memória para os unitários do ``ProjectService``.

O ``FakeGit`` modela objetos, árvores (dicionários caminho → blob), commits e refs com a
mesma interface do adaptador real. O merge é só por caminho: um lado mudou → vale esse
lado; os dois mudaram para conteúdos diferentes → conflito. Os merges reais de texto
continuam cobertos pelos testes com Git real.

Os dois registram cada operação de escrita em ``events`` (lista compartilhada), na ordem em
que acontecem, para os testes conferirem a ordem diário → ``update-ref`` → shared →
registro.
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from tsm_manager.adapters.git import CommitInfo, MergeConflict, MergeResult
from tsm_manager.config import BindingConfig
from tsm_manager.layout import ProjectLayout
from tsm_manager.store import Store


class FakeBindings:
    """Vínculos fixos, com o diretório sincronizado da conta (``workspaces/<conta>/tree``)
    como na ``DbBindings``."""

    def __init__(self, bindings: Iterable[BindingConfig]) -> None:
        self._by_id = {b.id: b for b in bindings}

    def get(self, binding_id: str) -> BindingConfig | None:
        return self._by_id.get(binding_id)

    def for_device(self, device: str) -> BindingConfig | None:
        return next((b for b in self._by_id.values() if b.device == device), None)

    def workspace_path(self, layout: ProjectLayout, binding: BindingConfig) -> Path:
        return layout.sync_root(binding.workspace)


class FakeGit:
    def __init__(self, events: list[tuple[Any, ...]],
                 on_update_refs: Callable[[list[tuple[str, str, str | None]]], None] | None = None
                 ) -> None:
        self.events = events
        self.on_update_refs = on_update_refs
        self.blobs: dict[str, bytes] = {}
        self.trees: dict[str, dict[str, str]] = {}
        self.commits: dict[str, CommitInfo] = {}
        self.commit_tree_of: dict[str, str] = {}
        self.refs: dict[str, str] = {}
        self.created = False
        self._seq = itertools.count(1)

    def _oid(self, kind: str, payload: bytes) -> str:
        return hashlib.sha1(kind.encode() + b"\0" + payload).hexdigest()

    # ------------------------------------------------------------ repositório

    def check_version(self) -> None:
        pass

    def init_bare(self) -> None:
        self.created = True

    def exists(self) -> bool:
        return self.created

    # ------------------------------------------------------------ objetos

    def _blob(self, data: bytes) -> str:
        oid = self._oid("blob", data)
        self.blobs[oid] = data
        return oid

    def hash_file(self, path: str | Path) -> str:
        return self._blob(Path(path).read_bytes())

    def cat_blob(self, oid: str) -> bytes:
        return self.blobs[oid]

    def blob_to_file(self, oid: str, dest: str | Path) -> None:
        Path(dest).write_bytes(self.blobs[oid])

    def _tree(self, entries: Mapping[str, str]) -> str:
        entries = dict(sorted(entries.items()))
        oid = self._oid("tree", repr(entries).encode())
        self.trees[oid] = entries
        return oid

    def tree_of(self, commit: str) -> str:
        return self.commit_tree_of[commit]

    def ls_tree(self, treeish: str) -> dict[str, str]:
        tree = self.commit_tree_of.get(treeish, treeish)
        return dict(self.trees[tree])

    def build_tree(self, base_tree: str | None, puts: Mapping[str, str],
                   deletes: Iterable[str] = ()) -> str:
        entries = dict(self.trees[base_tree]) if base_tree else {}
        for p in deletes:
            entries.pop(p, None)
        entries.update(puts)
        return self._tree(entries)

    def commit_tree(self, tree: str, parents: Iterable[str], message: str, author: Any) -> str:
        parents = tuple(parents)
        oid = self._oid("commit", f"{tree}{parents}{message}{next(self._seq)}".encode())
        self.commits[oid] = CommitInfo(oid, parents, author.name, author.email,
                                       "2026-11-26T12:00:00+00:00", message)
        self.commit_tree_of[oid] = tree
        return oid

    # ------------------------------------------------------------ refs e grafo

    def resolve(self, ref: str) -> str | None:
        if ref in self.commits:
            return ref
        return self.refs.get(ref)

    def _ancestors(self, oid: str) -> set[str]:
        seen, stack = set(), [oid]
        while stack:
            c = stack.pop()
            if c not in seen:
                seen.add(c)
                stack.extend(self.commits[c].parents)
        return seen

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        return ancestor in self._ancestors(descendant)

    def merge_base(self, a: str, b: str) -> str | None:
        common = self._ancestors(a) & self._ancestors(b)
        best = [c for c in common if not any(c != o and self.is_ancestor(c, o) for o in common)]
        return best[0] if best else None

    def update_refs(self, updates: Iterable[tuple[str, str, str | None]]) -> None:
        updates = list(updates)
        if self.on_update_refs:
            self.on_update_refs(updates)
        for ref, _new, old in updates:
            if self.refs.get(ref) != old:
                raise AssertionError(f"{ref}: esperado {old}, atual {self.refs.get(ref)}")
        for ref, new, _old in updates:
            self.refs[ref] = new
        self.events.append(("update_refs", tuple(r for r, _n, _o in updates)))

    def list_refs(self, prefix: str) -> dict[str, str]:
        return {r: o for r, o in self.refs.items() if r.startswith(prefix)}

    def merge_trees(self, base: str, ours: str, theirs: str) -> MergeResult:
        b, o, t = self.ls_tree(base), self.ls_tree(ours), self.ls_tree(theirs)
        out: dict[str, str] = {}
        conflicts = []
        for path in sorted(set(b) | set(o) | set(t)):
            vb, vo, vt = b.get(path), o.get(path), t.get(path)
            if vo == vt or vt == vb:
                chosen = vo
            elif vo == vb:
                chosen = vt
            else:
                conflicts.append(MergeConflict(path, "content"))
                continue
            if chosen is not None:
                out[path] = chosen
        return MergeResult(self._tree(out), tuple(conflicts))

    def log_first_parent(self, ref: str, limit: int | None = None) -> list[CommitInfo]:
        out, cur = [], self.resolve(ref)
        while cur and (limit is None or len(out) < limit):
            info = self.commits[cur]
            out.append(info)
            cur = info.parents[0] if info.parents else None
        return out

    def commit_info(self, oid: str) -> CommitInfo:
        return self.commits[oid]

    def diff_names(self, a: str | None, b: str) -> list[tuple[str, str]]:
        old = self.ls_tree(a) if a else {}
        new = self.ls_tree(b)
        out = []
        for path in sorted(set(old) | set(new)):
            if path not in new:
                out.append(("D", path))
            elif path not in old:
                out.append(("A", path))
            elif old[path] != new[path]:
                out.append(("M", path))
        return out


class FakeStore:
    """Mesma interface do ``Store``, em memória."""

    valid_key = staticmethod(Store.valid_key)

    def __init__(self, events: list[tuple[Any, ...]]) -> None:
        self.events = events
        self.results: dict[str, dict[str, Any]] = {}
        self.audits: list[dict[str, Any]] = []
        self.manifests: dict[str, dict[str, str]] = {}
        self.shared: str | None = None

    def get_result(self, key: str) -> dict[str, Any] | None:
        return self.results.get(key)

    def put_result(self, key: str, request_hash: str, result: dict[str, Any]) -> None:
        self.events.append(("put_result", key, result["status"]))
        self.results[key] = {"request_hash": request_hash, "result": dict(result), "at": "t"}

    def audit(self, event: str, **fields: Any) -> None:
        self.events.append(("audit", event))
        self.audits.append({"event": event, **fields})

    def read_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.audits[::-1][:limit]

    def get_manifest(self, commit: str) -> dict[str, str] | None:
        m = self.manifests.get(commit)
        return dict(m) if m is not None else None

    def put_manifest(self, commit: str, files: dict[str, str]) -> None:
        self.manifests[commit] = dict(files)

    def shared_commit(self) -> str | None:
        return self.shared

    def set_shared_commit(self, commit: str) -> None:
        self.events.append(("set_shared_commit", commit))
        self.shared = commit
