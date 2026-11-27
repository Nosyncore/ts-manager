"""Validação de uma publicação, sem I/O.

Recebe a requisição já decodificada e a árvore da base; devolve as mudanças normalizadas
ou a lista de problemas por caminho. Qualquer problema recusa a publicação inteira.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tsm_common.pathpolicy import PathIssue, check_path, find_collisions
from tsm_common.protocol import OP_DELETE, OP_PUT
from tsm_common.rules import PROJECT_FILE, IgnoreMatcher, ignore_patterns
from tsm_manager.config import ProjectConfig

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


class RequestError(ValueError):
    """Requisição malformada (campos ausentes ou de tipo errado)."""


@dataclass(frozen=True)
class Change:
    path: str
    op: str
    sha256: str | None = None
    size: int | None = None


@dataclass(frozen=True)
class PublishRequest:
    idempotency_key: str
    base_commit: str
    rules_digest: str
    message: str
    changes: tuple[Change, ...]

    @property
    def puts(self) -> list[Change]:
        return [c for c in self.changes if c.op == OP_PUT]

    @property
    def deletes(self) -> list[Change]:
        return [c for c in self.changes if c.op == OP_DELETE]

    def canonical(self, binding_id: str) -> str:
        return json.dumps({
            "binding": binding_id, "base": self.base_commit, "rules": self.rules_digest,
            "message": self.message,
            "changes": [[c.path, c.op, c.sha256, c.size] for c in self.changes],
        }, separators=(",", ":"), ensure_ascii=False)


def parse_publish_request(body: Any) -> PublishRequest:
    if not isinstance(body, dict):
        raise RequestError("corpo deve ser um objeto JSON")
    try:
        key = body["idempotency_key"]
        base = body["base"]
        rules = body["rules_digest"]
        raw_changes = body["changes"]
    except KeyError as exc:
        raise RequestError(f"campo ausente: {exc.args[0]}") from exc
    message = body.get("message") or ""
    if not isinstance(key, str):
        raise RequestError("idempotency_key: esperado texto")
    if not isinstance(base, dict) or not isinstance(base.get("commit"), str) or not _HEX40.match(
            base["commit"]):
        raise RequestError("base.commit: esperado sha1 hexadecimal")
    if not isinstance(rules, str) or not _HEX64.match(rules):
        raise RequestError("rules_digest: esperado sha256 hexadecimal")
    if not isinstance(message, str) or len(message) > 2000 or "\0" in message:
        raise RequestError("message: texto de até 2000 caracteres")
    if not isinstance(raw_changes, list) or not raw_changes:
        raise RequestError("changes: esperada uma lista não vazia")
    changes = []
    seen: set[str] = set()
    for i, c in enumerate(raw_changes):
        if not isinstance(c, dict) or not isinstance(c.get("path"), str):
            raise RequestError(f"changes[{i}]: esperado objeto com path")
        path, op = c["path"], c.get("op")
        if path in seen:
            raise RequestError(f"changes[{i}]: caminho repetido {path!r}")
        seen.add(path)
        if op == OP_PUT:
            sha, size = c.get("sha256"), c.get("size")
            if not isinstance(sha, str) or not _HEX64.match(sha):
                raise RequestError(f"changes[{i}].sha256: esperado sha256 hexadecimal")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise RequestError(f"changes[{i}].size: esperado inteiro >= 0")
            changes.append(Change(path, op, sha, size))
        elif op == OP_DELETE:
            changes.append(Change(path, op))
        else:
            raise RequestError(f"changes[{i}].op: use {OP_PUT!r} ou {OP_DELETE!r}")
    return PublishRequest(key, base["commit"], rules, message,
                          tuple(sorted(changes, key=lambda x: x.path)))


def project_matcher(project: ProjectConfig) -> IgnoreMatcher:
    return IgnoreMatcher(ignore_patterns(project.rules))


def validate_changes(req: PublishRequest, project: ProjectConfig,
                     base_files: Mapping[str, str]) -> list[PathIssue]:
    """Problemas que recusam a publicação (antes de qualquer cópia)."""
    issues: list[PathIssue] = []
    limits = project.limits
    matcher = project_matcher(project)
    for c in req.changes:
        reason = check_path(c.path, max_chars=limits.max_path_chars)
        if reason is None and matcher.is_ignored(c.path, False):
            reason = "fora das regras do projeto (ignorado ou não permitido)"
        if reason is None and c.op == OP_DELETE:
            if c.path == PROJECT_FILE:
                reason = f"{PROJECT_FILE} não pode ser excluído"
            elif c.path not in base_files:
                reason = "exclusão de caminho que não existe na base"
        if reason is None and c.op == OP_PUT and (c.size or 0) > limits.max_file_bytes:
            reason = f"arquivo maior que {limits.max_file_bytes} bytes"
        if reason is not None:
            issues.append(PathIssue(c.path, reason))
    puts = req.puts
    if len(req.changes) > limits.max_files:
        issues.append(PathIssue("", f"mais de {limits.max_files} arquivos na publicação"))
    total = sum(c.size or 0 for c in puts)
    if total > limits.max_total_bytes:
        issues.append(PathIssue("", f"publicação maior que {limits.max_total_bytes} bytes"))
    return issues


def tree_collisions(paths: list[str]) -> list[PathIssue]:
    return find_collisions(paths)


def check_project_file(data: bytes, project_id: str) -> str | None:
    """Motivo da recusa de um ``ts-project.json`` publicado, ou ``None``."""
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return f"{PROJECT_FILE} não é JSON válido"
    if not isinstance(obj, dict) or obj.get("project_id") != project_id:
        return f"{PROJECT_FILE}: project_id precisa continuar {project_id!r}"
    return None
