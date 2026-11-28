"""Operações de um projeto no Manager: publicação, rollback, histórico e recuperação.

Modelo: ``refs/heads/main`` é a versão integrada; cada commit de ``main``
(primeiro pai) é uma revisão numerada. ``refs/tsm/bindings/<id>`` guarda a última
publicação ou base conhecida do vínculo, sempre ancestral de ``main``. Uma publicação
com conflito não avança nenhum ref.

Todas as operações que mudam refs rodam sob o lock do projeto e seguem a ordem:
validação → staging → objetos Git → diário (fsync) → ``update-ref`` atômico →
materialização do shared → registro idempotente → fim do diário. A recuperação usa o
diário para concluir ou descartar uma operação interrompida.

O serviço recebe o ``Git``, o ``Store`` e a fonte de vínculos prontos; ``open_project``
monta os três a partir da raiz do Manager e do banco.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tsm_common import protocol as P
from tsm_common.fsutil import LockTimeout, atomic_write_json, file_lock, read_json
from tsm_common.manifest import tree_digest
from tsm_common.pathpolicy import PathIssue, check_paths, find_collisions
from tsm_common.protocol import RESERVED_DIR, REVISION_FILE, RevisionFormatError, RevisionInfo
from tsm_common.rules import PROJECT_FILE, rules_digest
from tsm_manager.adapters.fs import (
    SharedWriter,
    SizeExceeded,
    UnsafePathError,
    copy_from_workspace,
    remove_tree,
    scan_files,
)
from tsm_manager.adapters.git import Author, CommitInfo, Git
from tsm_manager.bindings import BindingSource
from tsm_manager.config import BindingConfig, ProjectConfig
from tsm_manager.db.connection import Database
from tsm_manager.faults import Faults
from tsm_manager.layout import ProjectLayout
from tsm_manager.store import Store, now_iso
from tsm_manager.validation import (
    PublishRequest,
    RequestError,
    check_project_file,
    parse_publish_request,
    project_matcher,
    validate_changes,
)

MAIN = "refs/heads/main"
BINDING_PREFIX = "refs/tsm/bindings/"
LOCK_TIMEOUT = 30.0


class ProjectError(RuntimeError):
    """Estado do projeto impede a operação (ex.: projeto não inicializado)."""


class RecoveryError(ProjectError):
    """Diário com estado inesperado: exige o operador."""


@dataclass(frozen=True)
class Outcome:
    """Resultado de uma operação: ``status`` de ``tsm_common.protocol`` + dados."""

    status: str
    payload: dict[str, Any]

    @property
    def http_status(self) -> int:
        return P.HTTP_STATUS.get(self.status, 500)

    def body(self) -> dict[str, Any]:
        return {"status": self.status, **self.payload}


def binding_ref(binding_id: str) -> str:
    return f"{BINDING_PREFIX}{binding_id}"


@dataclass(frozen=True)
class Requester:
    """Quem pede a operação: ``name`` para leitura humana, ids para auditoria."""

    name: str
    user_id: str
    device_id: str | None
    is_admin: bool

    @property
    def user_id_trailer(self) -> str | None:
        return self.user_id if self.user_id != self.name else None


def _author(who: Requester | None) -> Author:
    if who is None:
        return Author(name="tsm-manager", email="tsm-manager@manager.tsm")
    name = "".join(ch for ch in who.name if ch not in "<>").strip() or who.user_id
    return Author(name=name, email=f"{who.user_id}@{who.device_id or 'manager'}.tsm")


def _message(title: str, trailers: dict[str, Any]) -> str:
    lines = [title.strip() or "(sem mensagem)", ""]
    lines += [f"TSM-{k}: {v}" for k, v in trailers.items() if v not in (None, "")]
    return "\n".join(lines) + "\n"


class ProjectService:
    def __init__(self, project: ProjectConfig, layout: ProjectLayout, *, git: Git, store: Store,
                 bindings: BindingSource, shared_group: str | None = None,
                 faults: Faults | None = None, lock_timeout: float = LOCK_TIMEOUT) -> None:
        self.project = project
        self.layout = layout
        self.git = git
        self.store = store
        self.bindings = bindings
        self.faults = faults or Faults()
        self.shared_group = shared_group
        self.lock_timeout = lock_timeout
        self._blob_sha: dict[str, str] = {}

    # ================================================================ consultas

    @property
    def initialized(self) -> bool:
        return self.git.exists() and self.git.resolve(MAIN) is not None

    def _main(self) -> str:
        oid = self.git.resolve(MAIN)
        if oid is None:
            raise ProjectError(f"projeto {self.project.id} não inicializado (tsm-manager "
                               "init-project)")
        return oid

    def revision_of(self, commit: str) -> int:
        rev = self.git.commit_info(commit).trailers.get("TSM-Revision")
        if rev is None:
            raise ProjectError(f"commit {commit[:12]} não é uma revisão de main")
        return int(rev)

    def manifest_of(self, commit: str) -> dict[str, str]:
        """``{caminho: sha256}`` dos arquivos de um commit (com cache)."""
        cached = self.store.get_manifest(commit)
        if cached is not None:
            return cached
        info = self.git.commit_info(commit)
        files: dict[str, str]
        parent_manifest = self.store.get_manifest(info.parents[0]) if info.parents else None
        if parent_manifest is not None:
            files = dict(parent_manifest)
            blobs = None
            for status, path in self.git.diff_names(info.parents[0], commit):
                if status == "D":
                    files.pop(path, None)
                else:
                    if blobs is None:
                        blobs = self.git.ls_tree(commit)
                    files[path] = self._sha_of_blob(blobs[path])
        else:
            files = {p: self._sha_of_blob(b) for p, b in self.git.ls_tree(commit).items()}
        files = dict(sorted(files.items()))
        self.store.put_manifest(commit, files)
        return files

    def _sha_of_blob(self, oid: str) -> str:
        sha = self._blob_sha.get(oid)
        if sha is None:
            sha = hashlib.sha256(self.git.cat_blob(oid)).hexdigest()
            self._blob_sha[oid] = sha
        return sha

    def head(self) -> dict[str, Any]:
        main = self._main()
        return {"revision": self.revision_of(main), "commit": main,
                "tree_digest": tree_digest(self.manifest_of(main))}

    def info(self) -> dict[str, Any]:
        return {
            "project_id": self.project.id,
            "head": self.head(),
            "rules": {"allow": list(self.project.rules.allow),
                      "ignore": list(self.project.rules.ignore)},
            "rules_digest": rules_digest(self.project.rules),
            "limits": self.project.limits.to_dict(),
        }

    def _describe(self, c: CommitInfo) -> dict[str, Any]:
        t = c.trailers
        return {
            "revision": int(t["TSM-Revision"]) if "TSM-Revision" in t else None,
            "commit": c.oid,
            "kind": t.get("TSM-Kind", ""),
            "user": t.get("TSM-User", c.author_name),
            "device": t.get("TSM-Device"),
            "binding": t.get("TSM-Binding"),
            "rollback_to": int(t["TSM-Rollback-To"]) if "TSM-Rollback-To" in t else None,
            "date": c.date,
            "message": c.message.split("\n", 1)[0],
        }

    def revisions(self, limit: int = 50) -> list[dict[str, Any]]:
        return [self._describe(c) for c in self.git.log_first_parent(self._main(), limit)]

    def _find_revision(self, number: int) -> CommitInfo | None:
        for c in self.git.log_first_parent(self._main()):
            if c.trailers.get("TSM-Revision") == str(number):
                return c
        return None

    def revision_detail(self, number: int) -> dict[str, Any] | None:
        c = self._find_revision(number)
        if c is None:
            return None
        parent = c.parents[0] if c.parents else None
        changes = [{"status": s, "path": p} for s, p in self.git.diff_names(parent, c.oid)]
        return {**self._describe(c), "changes": changes}

    # ================================================================ inicialização

    def init_project(self, source: Path, *, message: str = "revisão inicial") -> Outcome:
        if self.initialized:
            raise ProjectError(f"projeto {self.project.id} já inicializado")
        lay = self.layout
        lay.ensure_history()
        lay.workspaces.mkdir(parents=True, exist_ok=True)
        lay.shared.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            lay.workspaces.chmod(0o711)
        SharedWriter(lay.shared, lay.tmp, self.shared_group)._apply(lay.shared, 0o2750)
        if not self.git.exists():
            self.git.check_version()
            self.git.init_bare()

        matcher = project_matcher(self.project)
        files: dict[str, Path] = {}
        for p in sorted(source.rglob("*")):
            rel = p.relative_to(source).as_posix()
            if p.is_symlink() or p.is_junction() or not p.is_file():
                continue
            if matcher.is_ignored(rel, False) or rel.split("/")[0] == RESERVED_DIR:
                continue
            files[rel] = p
        issues = check_paths(files, max_chars=self.project.limits.max_path_chars)
        issues += find_collisions(list(files))
        if PROJECT_FILE not in files:
            issues.append(PathIssue(PROJECT_FILE, "ausente na origem"))
        else:
            reason = check_project_file(files[PROJECT_FILE].read_bytes(), self.project.id)
            if reason:
                issues.append(PathIssue(PROJECT_FILE, reason))
        if issues:
            return Outcome(P.REJECTED, {"errors": _issues(issues)})

        with self._locked():
            blobs = {rel: self.git.hash_file(p) for rel, p in files.items()}
            tree = self.git.build_tree(None, blobs)
            commit = self.git.commit_tree(tree, [], _message(message, {
                "Revision": 1, "Kind": "init", "User": "operator"}), _author(None))
            self.git.update_refs([(MAIN, commit, None)])
            self.materialize(commit, full=True)
            self.store.audit("init", revision=1, commit=commit, files=len(files))
        return Outcome(P.PUBLISHED, {"revision": 1, "commit": commit, "head": self.head()})

    # ================================================================ publicação

    def publish(self, identity: Requester, binding: BindingConfig, body: Any) -> Outcome:
        try:
            req = parse_publish_request(body)
        except RequestError as exc:
            return Outcome(P.REJECTED, {"errors": [{"path": "", "reason": str(exc)}]})
        if not Store.valid_key(req.idempotency_key):
            return Outcome(P.REJECTED, {"errors": [{"path": "",
                                                    "reason": "idempotency_key inválida"}]})
        request_hash = hashlib.sha256(req.canonical(binding.id).encode()).hexdigest()
        try:
            with self._locked():
                self._recover_locked()
                prev = self.store.get_result(req.idempotency_key)
                if prev is not None:
                    if prev["request_hash"] != request_hash:
                        return Outcome(P.IDEMPOTENCY_MISMATCH, {
                            "message": "chave já usada com outro conteúdo"})
                    res = prev["result"]
                    return Outcome(res["status"], {k: v for k, v in res.items()
                                                   if k != "status"} | {"replayed": True})
                outcome = self._publish_locked(identity, binding, req, request_hash)
                if outcome.status != P.PUBLISHED:  # publicado é registrado pelo diário
                    self._record(req.idempotency_key, request_hash, outcome)
                    self.store.audit("publish", result=outcome.status, binding=binding.id,
                                     user=identity.user_id, device=identity.device_id,
                                     key=req.idempotency_key,
                                     paths=[c.path for c in req.changes][:200])
                return outcome
        except LockTimeout:
            return Outcome(P.BUSY, {"message": "projeto ocupado; repita com a mesma chave"})

    def _publish_locked(self, identity: Requester, binding: BindingConfig, req: PublishRequest,
                        request_hash: str) -> Outcome:
        git = self.git
        if req.rules_digest != rules_digest(self.project.rules):
            return Outcome(P.RULES_MISMATCH, {
                "message": "as regras do projeto no Client diferem das do Manager; atualize a "
                           "config", "rules_digest": rules_digest(self.project.rules)})
        main = self._main()
        bref = binding_ref(binding.id)
        current = git.resolve(bref)
        base = req.base_commit
        if git.resolve(base) != base or not git.is_ancestor(base, main) or (
                current is not None and not git.is_ancestor(current, base)):
            return Outcome(P.STALE_BASE, {
                "message": "a base informada não é válida para este vínculo; rode 'tsm pull'",
                "head": self.head(), "binding": current})

        base_blobs = git.ls_tree(base)
        issues = validate_changes(req, self.project, base_blobs)
        if issues:
            return Outcome(P.REJECTED, {"errors": _issues(issues)})

        # ---- staging: cópia do workspace com SHA-256 da cópia
        pub_id = uuid.uuid4().hex
        stage = self.layout.staging / pub_id
        workspace = self.bindings.workspace_path(self.layout, binding)
        try:
            mismatched: list[dict[str, str]] = []
            staged: dict[str, Path] = {}
            for i, c in enumerate(req.puts):
                dest = stage / f"{i:06d}"
                try:
                    copied = copy_from_workspace(workspace, c.path, dest,
                                                 self.project.limits.max_file_bytes)
                except FileNotFoundError:
                    mismatched.append({"path": c.path, "reason": "ausente no workspace"})
                    continue
                except UnsafePathError as exc:
                    return Outcome(P.REJECTED, {"errors": [{"path": c.path,
                                                            "reason": str(exc)}]})
                except SizeExceeded as exc:
                    return Outcome(P.REJECTED, {"errors": [{"path": c.path,
                                                            "reason": str(exc)}]})
                if copied.sha256 != c.sha256 or copied.size != c.size:
                    mismatched.append({"path": c.path, "reason": "conteúdo difere do manifesto"})
                    continue
                staged[c.path] = dest
            if mismatched:
                return Outcome(P.WORKSPACE_MISMATCH, {
                    "message": "o workspace não confere com o manifesto; repita a publicação",
                    "paths": mismatched})
            if PROJECT_FILE in staged:
                reason = check_project_file(staged[PROJECT_FILE].read_bytes(), self.project.id)
                if reason:
                    return Outcome(P.REJECTED, {"errors": [{"path": PROJECT_FILE,
                                                            "reason": reason}]})
            self.faults.hit("after_stage")

            # ---- objetos: commit C no vínculo, merge em main
            puts = {path: git.hash_file(p) for path, p in staged.items()}
            deletes = [c.path for c in req.deletes]
            base_tree = git.tree_of(base)
            tree_c = git.build_tree(base_tree, puts, deletes)
            if tree_c == base_tree:
                return Outcome(P.NO_CHANGE, {"message": "nada muda em relação à base",
                                             "head": self.head()})
            collisions = find_collisions(list(git.ls_tree(tree_c)))
            if collisions:
                return Outcome(P.REJECTED, {"errors": _issues(collisions)})
            trailers = {"Kind": "change", "User": identity.name,
                        "User-Id": identity.user_id_trailer, "Device": identity.device_id,
                        "Binding": binding.id, "Publication": req.idempotency_key}
            commit_c = git.commit_tree(tree_c, [base], _message(req.message or "publicação",
                                                                trailers),
                                       _author(identity))
            merge_base = git.merge_base(main, commit_c) or base
            merged = git.merge_trees(merge_base, main, commit_c)
            if not merged.clean:
                return Outcome(P.CONFLICT, {
                    "message": "conflito com a revisão atual; rode 'tsm pull', resolva e "
                               "publique de novo",
                    "conflicts": [{"path": c.path, "kind": c.kind} for c in merged.conflicts],
                    "head": self.head()})
            if merged.tree == git.tree_of(main):
                return Outcome(P.NO_CHANGE, {
                    "message": "o conteúdo publicado já está na revisão atual; rode 'tsm pull'",
                    "head": self.head()})
            collisions = find_collisions(list(git.ls_tree(merged.tree)))
            if collisions:
                return Outcome(P.REJECTED, {"errors": _issues(collisions)})

            revision = self.revision_of(main) + 1
            commit_m = git.commit_tree(merged.tree, [main, commit_c], _message(
                req.message or f"publicação de {identity.name}",
                {"Revision": revision, "Kind": "publish", **{k: v for k, v in trailers.items()
                                                              if k != "Kind"}}),
                _author(identity))

            base_manifest = self.manifest_of(base)
            files_c = dict(base_manifest)
            for d in deletes:
                files_c.pop(d, None)
            for c in req.puts:
                files_c[c.path] = c.sha256 or ""
            files_c = dict(sorted(files_c.items()))
            self.store.put_manifest(commit_c, files_c)

            result = {"status": P.PUBLISHED, "revision": revision, "commit": commit_c,
                      "merge_commit": commit_m, "tree_digest": tree_digest(files_c),
                      "fast_forward": merge_base == main}
            journal = {
                "id": pub_id, "kind": "publish", "key": req.idempotency_key,
                "request_hash": request_hash, "commit": commit_m, "revision": revision,
                "refs": [[MAIN, commit_m, main], [bref, commit_c, current]],
                "result": result,
                "audit": {"binding": binding.id, "user": identity.user_id,
                          "device": identity.device_id,
                          "paths": [c.path for c in req.changes][:200]},
                "at": now_iso(),
            }
            self._commit_operation(journal)
            final = dict(self.store.get_result(req.idempotency_key)["result"])
            final.pop("status")
            return Outcome(P.PUBLISHED, final)
        finally:
            if stage.exists():
                remove_tree(stage)

    # ================================================================ rollback

    def rollback(self, identity: Requester, body: Any) -> Outcome:
        if not identity.is_admin:
            return Outcome(P.FORBIDDEN, {"message": "rollback exige admin"})
        if not isinstance(body, dict):
            return Outcome(P.REJECTED, {"errors": [{"path": "", "reason": "corpo inválido"}]})
        key, target, message = body.get("idempotency_key"), body.get("target"), body.get(
            "message") or ""
        if not Store.valid_key(key or "") or not isinstance(target, int) or isinstance(
                target, bool) or not isinstance(message, str):
            return Outcome(P.REJECTED, {"errors": [{"path": "", "reason":
                                                    "use idempotency_key, target (inteiro)"}]})
        request_hash = hashlib.sha256(json.dumps(["rollback", target, message]).encode()
                                      ).hexdigest()
        try:
            with self._locked():
                self._recover_locked()
                prev = self.store.get_result(key)
                if prev is not None:
                    if prev["request_hash"] != request_hash:
                        return Outcome(P.IDEMPOTENCY_MISMATCH, {
                            "message": "chave já usada com outro conteúdo"})
                    res = prev["result"]
                    return Outcome(res["status"], {k: v for k, v in res.items()
                                                   if k != "status"} | {"replayed": True})
                found = self._find_revision(target)
                if found is None:
                    return Outcome(P.NOT_FOUND, {"message": f"revisão r{target} não existe"})
                main = self._main()
                tree = self.git.tree_of(found.oid)
                if tree == self.git.tree_of(main):
                    out = Outcome(P.NO_CHANGE, {"message": f"a revisão atual já é igual a "
                                                           f"r{target}", "head": self.head()})
                    self._record(key, request_hash, out)
                    return out
                revision = self.revision_of(main) + 1
                commit = self.git.commit_tree(tree, [main], _message(
                    message or f"rollback para r{target}",
                    {"Revision": revision, "Kind": "rollback", "User": identity.name,
                     "User-Id": identity.user_id_trailer, "Rollback-To": target,
                     "Publication": key}), _author(identity))
                result = {"status": P.PUBLISHED, "revision": revision, "commit": commit,
                          "rollback_to": target}
                self._commit_operation({
                    "id": uuid.uuid4().hex, "kind": "rollback", "key": key,
                    "request_hash": request_hash, "commit": commit, "revision": revision,
                    "refs": [[MAIN, commit, main]], "result": result,
                    "audit": {"user": identity.user_id, "rollback_to": target},
                    "at": now_iso(),
                })
                final = dict(self.store.get_result(key)["result"])
                final.pop("status")
                return Outcome(P.PUBLISHED, final)
        except LockTimeout:
            return Outcome(P.BUSY, {"message": "projeto ocupado; repita com a mesma chave"})

    # ================================================================ diário

    def _journal_path(self, op_id: str) -> Path:
        return self.layout.journal / f"{op_id}.json"

    def _commit_operation(self, journal: dict[str, Any]) -> None:
        path = self._journal_path(journal["id"])
        atomic_write_json(path, journal)  # com fsync, antes do update-ref
        self.faults.hit("before_update_ref")
        self.git.update_refs([(r, new, old) for r, new, old in journal["refs"]])
        self._finish_operation(journal, recovered=False)

    def _finish_operation(self, journal: dict[str, Any], *, recovered: bool) -> None:
        self.materialize(journal["commit"], full=recovered)
        self.faults.hit("before_record")
        result = journal["result"]
        self.store.put_result(journal["key"], journal["request_hash"], result)
        self.store.audit(journal["kind"], result=result["status"], revision=journal["revision"],
                         commit=journal["commit"], key=journal["key"], recovered=recovered,
                         **journal.get("audit", {}))
        self._journal_path(journal["id"]).unlink(missing_ok=True)

    def _record(self, key: str, request_hash: str, outcome: Outcome) -> None:
        self.store.put_result(key, request_hash, outcome.body())

    @contextlib.contextmanager
    def _locked(self):
        self.layout.ensure_history()
        with file_lock(self.layout.lock, timeout=self.lock_timeout):
            yield

    def recover(self) -> list[str]:
        with self._locked():
            return self._recover_locked(reconcile=True)

    def _recover_locked(self, *, reconcile: bool = False) -> list[str]:
        notes: list[str] = []
        if not self.layout.journal.is_dir():
            return notes
        for path in sorted(self.layout.journal.glob("*.json")):
            j = read_json(path)
            refs = j["refs"]
            current = [self.git.resolve(r) for r, _new, _old in refs]
            if all(c == new for c, (_r, new, _old) in zip(current, refs, strict=True)):
                self._finish_operation(j, recovered=True)
                notes.append(f"{j['kind']} {j['key']}: concluída (r{j['revision']})")
            elif all(c == old for c, (_r, _new, old) in zip(current, refs, strict=True)):
                path.unlink()
                self.store.audit("discarded", kind=j["kind"], key=j["key"])
                notes.append(f"{j['kind']} {j['key']}: descartada (refs não avançaram)")
            else:
                raise RecoveryError(f"diário {path.name}: refs em estado inesperado")
        for d in (self.layout.staging, self.layout.tmp):
            if d.is_dir():
                for child in d.iterdir():
                    if child.is_dir():
                        remove_tree(child)
                    else:
                        child.unlink(missing_ok=True)
        if self.initialized:
            main = self._main()
            if reconcile or self.store.shared_commit() != main:
                changed = self.materialize(main, full=True)
                if changed:
                    notes.append(f"shared reconciliado com r{self.revision_of(main)} "
                                 f"({changed} caminhos)")
        return notes

    # ================================================================ shared

    def materialize(self, commit: str, *, full: bool = False) -> int:
        """Reconcilia o shared com ``commit``; ``revision.json`` por último."""
        git = self.git
        writer = SharedWriter(self.layout.shared, self.layout.tmp, self.shared_group)
        desired_blobs = git.ls_tree(commit)
        desired = self.manifest_of(commit)
        previous = self.store.shared_commit()
        if full or previous is None or git.resolve(previous) != previous:
            current = scan_files(self.layout.shared, skip_top=(RESERVED_DIR,))
            to_delete = [p for p in current if p not in desired]
            to_write = [p for p in desired if current.get(p) != desired[p]]
        else:
            diff = git.diff_names(previous, commit)
            to_delete = [p for s, p in diff if s == "D"]
            to_write = [p for s, p in diff if s != "D"]
        for rel in to_delete:
            writer.remove(rel)
        for n, rel in enumerate(to_write):
            with writer.temp_file() as tmp:
                git.blob_to_file(desired_blobs[rel], tmp)
                self.faults.per_file()
                writer.install(tmp, rel)
            if n == 0:
                self.faults.hit("during_materialize")
        writer.prune_empty_dirs(keep=(RESERVED_DIR,))
        info = RevisionInfo(self.project.id, self.revision_of(commit), commit, desired)
        writer.ensure_dir(RESERVED_DIR)
        with writer.temp_file() as tmp:
            tmp.write_text(info.to_json(), encoding="utf-8")
            writer.install(tmp, REVISION_FILE)
        self.store.set_shared_commit(commit)
        return len(to_delete) + len(to_write)

    # ================================================================ verificação

    def verify(self) -> list[str]:
        problems: list[str] = []
        main = self._main()
        desired = self.manifest_of(main)
        current = scan_files(self.layout.shared, skip_top=(RESERVED_DIR,))
        for p in sorted(set(desired) | set(current)):
            if desired.get(p) != current.get(p):
                problems.append(f"shared difere de main: {p}")
        rev_path = self.layout.shared / REVISION_FILE
        try:
            info = RevisionInfo.from_json(rev_path.read_text(encoding="utf-8"))
            if info.commit != main or info.files != desired:
                problems.append("revision.json não corresponde a main")
        except (FileNotFoundError, RevisionFormatError) as exc:
            problems.append(f"revision.json inválido: {exc}")
        for ref, oid in self.git.list_refs(BINDING_PREFIX.rstrip("/")).items():
            if not self.git.is_ancestor(oid, main):
                problems.append(f"{ref} não é ancestral de main")
        if self.layout.journal.is_dir() and any(self.layout.journal.glob("*.json")):
            problems.append("diário com operações pendentes (rode recover)")
        return problems

    def binding_refs(self) -> dict[str, str]:
        return {r[len(BINDING_PREFIX):]: o for r, o in self.git.list_refs(
            BINDING_PREFIX.rstrip("/")).items()}


def open_project(root: Path, project: ProjectConfig, db: Database, *,
                 bindings: BindingSource, shared_group: str | None = None,
                 git_executable: str = "git", faults: Faults | None = None,
                 lock_timeout: float = LOCK_TIMEOUT) -> ProjectService:
    """``ProjectService`` com Git interno, ``Store`` no banco e a fonte de vínculos dada
    (no Manager, a ``DbBindings`` do projeto)."""
    layout = ProjectLayout(root, project.id)
    git = Git(layout.repo, executable=git_executable, global_config=layout.git_global_config,
              tmp_dir=layout.tmp)
    return ProjectService(project, layout, git=git, store=Store(db, project.id),
                          bindings=bindings,
                          shared_group=shared_group, faults=faults, lock_timeout=lock_timeout)


def _issues(issues: Iterable[PathIssue]) -> list[dict[str, str]]:
    return [{"path": i.path, "reason": i.reason} for i in issues]
