"""Colaboração pelo terminal: init, changes, diff, publish, pull, history, rollback.

Orquestra o estado local (``state``), o transporte (``TransportService``), o Manager (HTTP)
e o git local (merge de três vias). A lógica de decisão fica em ``changes`` e ``pulling``;
este módulo cuida da ordem das operações e da segurança dos dados locais:

- a pasta de trabalho só é escrita por ``init`` e ``pull``;
- antes de sobrescrever ou apagar um arquivo local, o conteúdo atual é guardado no
  armazenamento e o hash é reconferido (edição durante o pull não é perdida);
- a base só avança com a operação completa.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tsm_client.adapters.git import ClientGit
from tsm_client.adapters.manager import ManagerClient, ManagerUnavailable, Response
from tsm_client.changes import (
    DELETED,
    LocalChange,
    diff,
    filter_manifest,
    local_manifest,
    mass_deletion,
    select,
)
from tsm_client.config import Config, ConfigError, verify_project_folder
from tsm_client.pulling import (
    DELETE,
    MARKERS,
    MERGE,
    WRITE,
    CacheNotReady,
    PullPlan,
    has_markers,
    plan_pull,
    read_cache,
    wait_cache,
)
from tsm_client.service import RefusedError, TransportService
from tsm_client.sessions import Binding, Role
from tsm_client.state import BindingState, StateError, StateStore, now_iso
from tsm_common import protocol as P
from tsm_common.manifest import file_sha256, tree_digest
from tsm_common.pathpolicy import check_paths, find_collisions
from tsm_common.rules import IgnoreMatcher, ignore_patterns, rules_digest


@dataclass
class PublishReport:
    status: str
    body: dict[str, Any]
    changes: list[dict[str, Any]] = field(default_factory=list)
    dry_run: bool = False


@dataclass
class PullReport:
    status: str  # updated | up_to_date | blocked | incomplete | dry_run
    revision: int
    plan: PullPlan
    skipped: list[str] = field(default_factory=list)
    record: str | None = None
    warning: str | None = None


def read_token(cfg: Config) -> str:
    assert cfg.manager is not None
    try:
        token = cfg.manager.token_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise ConfigError(f"token do Manager ausente: {cfg.manager.token_file}") from exc
    if not token:
        raise ConfigError(f"token do Manager vazio: {cfg.manager.token_file}")
    return token


class CollabService:
    def __init__(self, cfg: Config, transport: TransportService, manager: ManagerClient,
                 git: ClientGit, state: StateStore, *, faults: dict[str, Any] | None = None
                 ) -> None:
        if not cfg.collab_enabled:
            raise ConfigError("colaboração exige config version 2 (state_directory e manager)")
        self.cfg = cfg
        self.transport = transport
        self.manager = manager
        self.git = git
        self.state = state
        self.faults = faults or {}

    # ================================================================ utilitários

    def binding(self, binding_id: str | None = None) -> Binding:
        if binding_id is None:
            if len(self.cfg.bindings) != 1:
                raise ConfigError("a config tem vários vínculos; use --binding")
            return self.cfg.bindings[0]
        for b in self.cfg.bindings:
            if b.id == binding_id:
                return b
        raise ConfigError(f"vínculo desconhecido: {binding_id}")

    def _state(self, b: Binding) -> BindingState:
        st = self.state.load(b.id)
        if st is None:
            raise RefusedError(f"vínculo {b.id} não inicializado: rode 'tsm init'")
        return st

    def _local_root(self, b: Binding) -> Path:
        return Path(b.local.path)

    def _cache_root(self, b: Binding) -> Path:
        return Path(b.cache.path)

    def _base_manifest(self, b: Binding, st: BindingState) -> dict[str, str]:
        return filter_manifest(self.state.manifest(st.base_commit), b.rules)

    def _session(self, b: Binding, role: Role):
        for v in self.transport.status():
            if v.binding_id == b.id and v.role is role:
                return v.session
        return None

    def _require_session(self, b: Binding, role: Role) -> None:
        if not self.transport.adapter.daemon_running():
            raise RefusedError("daemon do Mutagen parado: rode 'tsm up'")
        s = self._session(b, role)
        if s is None:
            raise RefusedError(f"sessão de {role.value} ausente: rode 'tsm up'")
        if s.paused:
            raise RefusedError(f"sessão de {role.value} pausada: rode 'tsm resume'")
        if s.status.halted:
            raise RefusedError(f"sessão de {role.value} parada por salvaguarda "
                               f"({s.status.value}); verifique as pastas")

    def _flush(self, role: Role) -> None:
        self.transport.flush(role)

    def _fault(self, point: str) -> None:
        if self.faults.get("crash") == point:
            raise KeyboardInterrupt(f"falha injetada: {point}")

    # ================================================================ escrita local

    @staticmethod
    def _write_local(root: Path, rel: str, data: bytes) -> None:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # o padrão *.tmp é ignorado pelo upload: o temporário nunca vai ao workspace
        fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.tsm-", suffix=".tmp",
                                   dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise

    @staticmethod
    def _delete_local(root: Path, rel: str) -> None:
        target = root / rel
        target.unlink(missing_ok=True)
        parent = target.parent
        while parent != root:
            try:
                parent.rmdir()  # só se ficou vazio
            except OSError:
                break
            parent = parent.parent

    @staticmethod
    def _current_sha(root: Path, rel: str) -> str | None:
        p = root / rel
        if p.is_symlink() or not p.is_file():
            return None
        return file_sha256(p)

    # ================================================================ init

    def init(self, binding_id: str | None = None, *, wait: float = 60.0) -> dict[str, Any]:
        b = self.binding(binding_id)
        local = self._local_root(b)
        with self.state.locked():
            if self.state.load(b.id) is not None:
                raise RefusedError(f"vínculo {b.id} já inicializado")
            if local.exists() and (not local.is_dir() or any(local.iterdir())):
                raise RefusedError(f"a pasta local precisa estar vazia ou ausente: {local}")
            self.transport.up()  # só o download, enquanto o vínculo não tem base
            info = self._wait_cache(b, wait, min_revision=1)
            local.mkdir(parents=True, exist_ok=True)
            theirs = filter_manifest(info.files, b.rules)
            for rel, sha in theirs.items():
                self._write_local(local, rel, self.state.objects.read(sha))
            self.state.put_manifest(info.commit, theirs)
            self.state.save(BindingState(b.id, info.commit, info.revision))
        results = self.transport.up()  # agora cria o upload
        return {"revision": info.revision, "commit": info.commit, "files": len(theirs),
                "sessions": [(r.spec.name, r.action) for r in results]}

    def _wait_cache(self, b: Binding, wait: float, *, min_revision: int):
        """Espera o cache conferir com ``revision.json`` numa revisão >= ``min_revision``."""
        matcher = IgnoreMatcher(ignore_patterns(b.rules))
        cache = self._cache_root(b)

        def read():
            return read_cache(cache, matcher, self.state.objects)

        def accept(info) -> bool:
            if info.project_id != b.project_id:
                raise RefusedError(f"o cache é do projeto {info.project_id}, não {b.project_id}")
            return info.revision >= min_revision

        def poll() -> None:
            with contextlib.suppress(Exception):
                self._flush(Role.DOWNLOAD)

        poll()
        return wait_cache(read, timeout=wait, poll=poll, accept=accept)

    # ================================================================ changes / diff

    def changes(self, binding_id: str | None = None) -> list[LocalChange]:
        b = self.binding(binding_id)
        st = self._state(b)
        return diff(self._base_manifest(b, st), local_manifest(self._local_root(b), b.rules))

    def diff(self, paths: list[str] | None, binding_id: str | None = None) -> str:
        b = self.binding(binding_id)
        changes, missing = select(self.changes(b.id), paths)
        if missing:
            raise RefusedError(f"sem mudança local: {', '.join(missing)}")
        out = []
        root = self._local_root(b)
        for c in changes:
            old = self.state.objects.path(c.base_sha) if c.base_sha else None
            new = root / c.path if c.kind != DELETED else None
            out.append(self.git.diff(old, new, c.path))
        return "".join(out)

    # ================================================================ publish

    def publish(self, paths: list[str] | None, *, message: str = "", dry_run: bool = False,
                confirm_deletions: bool = False, resume: bool = False,
                binding_id: str | None = None) -> PublishReport:
        b = self.binding(binding_id)
        root = self._local_root(b)
        with self.state.locked():
            st = self._state(b)
            if resume:
                if not st.pending_publish:
                    raise RefusedError("não há publicação pendente")
                body = st.pending_publish["body"]
            else:
                if st.pending_publish:
                    raise RefusedError("há uma publicação pendente (sem resposta do Manager): "
                                       "rode 'tsm publish --resume'")
                verify_project_folder(b)
                base = self._base_manifest(b, st)
                changes, missing = select(diff(base, local_manifest(root, b.rules)), paths)
                if missing:
                    raise RefusedError(f"sem mudança local: {', '.join(missing)}")
                if not changes:
                    raise RefusedError("nada a publicar")
                deletes = [c for c in changes if c.kind == DELETED]
                if mass_deletion(len(deletes), len(base)) and not confirm_deletions:
                    raise RefusedError(f"{len(deletes)} exclusões (de {len(base)} arquivos da "
                                       "base): confirme com --confirm-deletions")
                issues = check_paths([c.path for c in changes if c.kind != DELETED])
                result_paths = (set(base) - {c.path for c in deletes}) | {
                    c.path for c in changes if c.kind != DELETED}
                issues += find_collisions(sorted(result_paths))
                if issues:
                    raise RefusedError("caminhos recusados: " + "; ".join(map(str, issues)))
                for c in changes:
                    if c.kind != DELETED and c.path in st.markers and has_markers(
                            (root / c.path).read_bytes()):
                        raise RefusedError(f"{c.path}: ainda tem marcadores de conflito "
                                           "(<<<<<<< / >>>>>>>)")
                req_changes = []
                for c in changes:
                    if c.kind == DELETED:
                        req_changes.append({"path": c.path, "op": P.OP_DELETE})
                    else:  # snapshot: o hash é o da cópia guardada
                        sha, size = self.state.objects.put_file(root / c.path)
                        req_changes.append({"path": c.path, "op": P.OP_PUT, "sha256": sha,
                                            "size": size})
                body = {"idempotency_key": str(uuid.uuid4()),
                        "base": {"commit": st.base_commit},
                        "rules_digest": rules_digest(b.rules), "message": message,
                        "changes": req_changes}
                if dry_run:
                    return PublishReport("dry_run", body, req_changes, dry_run=True)
                self._require_session(b, Role.UPLOAD)
                st.pending_publish = {"body": body, "created": now_iso()}
                self.state.save(st)
            # flush depois do snapshot: o workspace precisa refletir o que foi guardado
            self._require_session(b, Role.UPLOAD)
            self._flush(Role.UPLOAD)
            self._fault("before_send")
            resp = self.manager.publish(b.project_id, b.id, body)  # ManagerUnavailable sobe
            self._fault("after_send")
            return self._finish_publish(b, st, body, resp)

    def _finish_publish(self, b: Binding, st: BindingState, body: dict[str, Any],
                        resp: Response) -> PublishReport:
        status = resp.status
        if status == P.BUSY or resp.http_status >= 500:
            return PublishReport(status, resp.body, body["changes"])  # mantém pendente
        if status == P.PUBLISHED:
            files = dict(self.state.manifest(st.base_commit))
            for c in body["changes"]:
                if c["op"] == P.OP_DELETE:
                    files.pop(c["path"], None)
                else:
                    files[c["path"]] = c["sha256"]
            if tree_digest(files) != resp.body.get("tree_digest"):
                raise StateError("o manifesto publicado diverge do Manager; base local não "
                                 "atualizada")
            commit = resp.body["commit"]
            self.state.put_manifest(commit, files)
            st.base_commit = commit
            st.base_revision = max(st.base_revision, int(resp.body["revision"]))
            published = {c["path"] for c in body["changes"]}
            st.markers = [m for m in st.markers if m not in published]
        st.pending_publish = None
        self.state.save(st)
        return PublishReport(status, resp.body, body["changes"])

    # ================================================================ pull

    def pull(self, *, dry_run: bool = False, wait: float = 60.0,
             resolutions: dict[str, str] | None = None, confirm_deletions: bool = False,
             binding_id: str | None = None) -> PullReport:
        b = self.binding(binding_id)
        root = self._local_root(b)
        with self.state.locked():
            st = self._state(b)
            if st.pending_publish:
                raise RefusedError("há uma publicação pendente: rode 'tsm publish --resume' antes")
            verify_project_folder(b)
            self._require_session(b, Role.DOWNLOAD)
            head = None
            warning = None
            try:
                resp = self.manager.project(b.project_id, timeout=5)
                if resp.ok:
                    head = resp.body.get("head")
            except ManagerUnavailable:
                warning = "Manager inacessível: usando a revisão verificada do cache"
            info = self._wait_for_pull(b, wait, st.base_revision, head)
            if head and info.revision < head["revision"]:
                warning = (f"o cache está em r{info.revision}; o Manager já está em "
                           f"r{head['revision']} (rode o pull de novo depois)")

            base = self._base_manifest(b, st)
            ours = local_manifest(root, b.rules)
            theirs = filter_manifest(info.files, b.rules)
            objs = self.state.objects
            plan = plan_pull(base, ours, theirs,
                             load_base=objs.read, load_theirs=objs.read,
                             load_ours=lambda rel: (root / rel).read_bytes(),
                             merger=lambda o, bb, t: self.git.merge(o, bb, t),
                             resolutions=resolutions)
            if plan.conflicts:
                return PullReport("blocked", info.revision, plan, warning=warning)
            if mass_deletion(len(plan.deletes), len(base)) and not confirm_deletions:
                raise RefusedError(f"o pull apagaria {len(plan.deletes)} arquivos locais: "
                                   "confirme com --confirm-deletions")
            if dry_run:
                return PullReport("dry_run", info.revision, plan, warning=warning)
            if not plan.changes and st.base_commit == info.commit:
                return PullReport("up_to_date", info.revision, plan, warning=warning)

            record: dict[str, Any] = {"from": st.base_commit, "to": info.commit,
                                      "revision": info.revision, "at": now_iso(), "ops": []}
            skipped: list[str] = []
            for n, op in enumerate(plan.changes):
                if n == 1:
                    self._fault("mid_pull")
                current = self._current_sha(root, op.path)
                if current != op.ours:
                    skipped.append(op.path)  # mudou durante o pull: não sobrescreve
                    continue
                preimage = None
                if op.ours is not None:
                    preimage, _ = objs.put_file(root / op.path)
                    if preimage != op.ours:
                        skipped.append(op.path)
                        continue
                if op.action == DELETE:
                    self._delete_local(root, op.path)
                elif op.action == WRITE:
                    self._write_local(root, op.path, objs.read(op.theirs))
                elif op.action in (MERGE, MARKERS):
                    assert op.content is not None
                    objs.put_bytes(op.content)
                    self._write_local(root, op.path, op.content)
                record["ops"].append({"path": op.path, "action": op.action,
                                      "resolution": op.resolution, "preimage": preimage,
                                      "theirs": op.theirs})
            record["skipped"] = skipped
            rec_path = self.state.record_pull(b.id, record)
            if skipped:
                return PullReport("incomplete", info.revision, plan, skipped, str(rec_path),
                                  warning)
            self.state.put_manifest(info.commit, theirs)
            st.base_commit = info.commit
            st.base_revision = info.revision
            st.markers = sorted(set(st.markers) | set(plan.markers))
            self.state.save(st)
            return PullReport("updated", info.revision, plan, [], str(rec_path), warning)

    def _wait_for_pull(self, b: Binding, wait: float, min_revision: int,
                       head: dict[str, Any] | None):
        target = max(min_revision, head["revision"]) if head else min_revision
        try:
            return self._wait_cache(b, wait, min_revision=target)
        except CacheNotReady:
            if head is None or target == min_revision:
                raise
        # o cache não alcançou o head no prazo: serve qualquer revisão >= base
        return self._wait_cache(b, 0.5, min_revision=min_revision)

    # ================================================================ consultas no Manager

    def _ok(self, resp: Response) -> dict[str, Any]:
        if not resp.ok:
            raise RefusedError(f"Manager: {resp.body.get('message') or resp.status} "
                               f"(HTTP {resp.http_status})")
        return resp.body

    def history(self, limit: int = 20, binding_id: str | None = None) -> list[dict[str, Any]]:
        b = self.binding(binding_id)
        return self._ok(self.manager.revisions(b.project_id, limit))["revisions"]

    def show(self, number: int, binding_id: str | None = None) -> dict[str, Any]:
        b = self.binding(binding_id)
        return self._ok(self.manager.revision(b.project_id, number))

    def rollback(self, number: int, message: str = "", binding_id: str | None = None
                 ) -> Response:
        b = self.binding(binding_id)
        return self.manager.rollback(b.project_id, {
            "idempotency_key": str(uuid.uuid4()), "target": number, "message": message})

    def audit(self, limit: int = 50, binding_id: str | None = None) -> list[dict[str, Any]]:
        b = self.binding(binding_id)
        return self._ok(self.manager.audit(b.project_id, limit))["events"]

    def status_info(self, binding_id: str | None = None) -> dict[str, Any]:
        b = self.binding(binding_id)
        st = self.state.load(b.id)
        info: dict[str, Any] = {"binding": b.id, "initialized": st is not None}
        if st is None:
            return info
        info.update({"base_commit": st.base_commit, "base_revision": st.base_revision,
                     "pending_publish": bool(st.pending_publish), "markers": st.markers})
        with contextlib.suppress(Exception):
            info["local_changes"] = len(self.changes(b.id))
        try:
            resp = self.manager.project(b.project_id, timeout=3)
            info["head"] = resp.body.get("head") if resp.ok else None
        except ManagerUnavailable:
            info["head"] = None
        return info
