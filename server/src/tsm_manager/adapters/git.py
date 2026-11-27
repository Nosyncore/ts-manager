"""Único ponto do Manager que executa o ``git``.

Repositório bare, só comandos de baixo nível, sem worktree. A configuração do sistema e
a global do operador são ignoradas; fim de linha nunca é convertido; renomeações não são
inferidas no merge (``merge.renames=false``): aparecem como exclusão + criação.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

ZERO_OID = "0" * 40
FILE_MODE = "100644"
MIN_GIT = (2, 40)

_FIXED_CONFIG = (
    "-c", "core.autocrlf=false",
    "-c", "core.safecrlf=false",
    "-c", "core.quotepath=false",
    "-c", "merge.renames=false",
    "-c", "diff.renames=false",
    "-c", "gc.auto=0",
)


class GitError(RuntimeError):
    """O git falhou de forma inesperada."""


@dataclass(frozen=True)
class Author:
    name: str
    email: str
    date: str | None = None  # ISO 8601; None = agora


@dataclass(frozen=True)
class MergeConflict:
    path: str
    kind: str  # content | binary | delete_modify | add_add | other


@dataclass(frozen=True)
class MergeResult:
    tree: str
    conflicts: tuple[MergeConflict, ...]

    @property
    def clean(self) -> bool:
        return not self.conflicts


@dataclass(frozen=True)
class CommitInfo:
    oid: str
    parents: tuple[str, ...]
    author_name: str
    author_email: str
    date: str
    message: str

    @property
    def trailers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in self.message.splitlines():
            m = re.match(r"^(TSM-[A-Za-z-]+):\s*(.*)$", line)
            if m:
                out[m.group(1)] = m.group(2).strip()
        return out


class Git:
    def __init__(self, git_dir: str | os.PathLike[str], *, executable: str = "git",
                 global_config: str | os.PathLike[str] | None = None) -> None:
        self.git_dir = Path(git_dir)
        self.executable = executable
        self._global_config = Path(global_config) if global_config else (
            self.git_dir.parent / "git-global.cfg"
        )

    # ------------------------------------------------------------ execução

    def _env(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        if not self._global_config.exists():
            self._global_config.parent.mkdir(parents=True, exist_ok=True)
            self._global_config.write_bytes(b"")
        env.update({
            "GIT_DIR": str(self.git_dir),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(self._global_config),
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "LANG": "C",
        })
        if extra:
            env.update(extra)
        return env

    def run(self, *args: str, input: bytes | None = None, env: Mapping[str, str] | None = None,
            ok_codes: Iterable[int] = (0,), stdout=None) -> subprocess.CompletedProcess[bytes]:
        argv = [self.executable, *_FIXED_CONFIG, *args]
        proc = subprocess.run(
            argv, input=input, env=self._env(env), check=False,
            stdout=stdout if stdout is not None else subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if proc.returncode not in tuple(ok_codes):
            raise GitError(
                f"git {' '.join(args[:2])} falhou ({proc.returncode}): "
                f"{proc.stderr.decode('utf-8', 'replace').strip()}"
            )
        return proc

    def out(self, *args: str, **kw) -> str:
        return self.run(*args, **kw).stdout.decode("utf-8").strip()

    # ------------------------------------------------------------ repositório

    def version(self) -> tuple[int, int]:
        text = subprocess.run([self.executable, "--version"], capture_output=True,
                              check=True).stdout.decode()
        m = re.search(r"(\d+)\.(\d+)", text)
        if not m:
            raise GitError(f"versão do git não reconhecida: {text!r}")
        return int(m.group(1)), int(m.group(2))

    def check_version(self) -> None:
        v = self.version()
        if v < MIN_GIT:
            raise GitError(f"git {v[0]}.{v[1]} encontrado; é necessário >= 2.40")

    def init_bare(self) -> None:
        self.git_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [self.executable, "init", "--quiet", "--bare", "--initial-branch=main",
             str(self.git_dir)],
            env=self._env(), check=True, capture_output=True,
        )

    def exists(self) -> bool:
        return (self.git_dir / "HEAD").is_file()

    # ------------------------------------------------------------ objetos

    def hash_file(self, path: str | os.PathLike[str]) -> str:
        return self.out("hash-object", "-w", "--no-filters", "--", str(path))

    def hash_bytes(self, data: bytes) -> str:
        return self.out("hash-object", "-w", "--no-filters", "--stdin", input=data)

    def cat_blob(self, oid: str) -> bytes:
        return self.run("cat-file", "blob", oid).stdout

    def blob_to_file(self, oid: str, dest: str | os.PathLike[str]) -> None:
        with open(dest, "wb") as fh:
            self.run("cat-file", "blob", oid, stdout=fh)

    def tree_of(self, commit: str) -> str:
        return self.out("rev-parse", "--verify", f"{commit}^{{tree}}")

    def ls_tree(self, treeish: str) -> dict[str, str]:
        """``{caminho: blob}`` de todos os arquivos (recursivo)."""
        raw = self.run("ls-tree", "-r", "-z", "--full-tree", treeish).stdout
        out: dict[str, str] = {}
        for rec in raw.split(b"\0"):
            if not rec:
                continue
            meta, path = rec.split(b"\t", 1)
            _mode, typ, oid = meta.decode().split()
            if typ == "blob":
                out[path.decode("utf-8")] = oid
        return out

    def build_tree(self, base_tree: str | None, puts: Mapping[str, str],
                   deletes: Iterable[str] = ()) -> str:
        """Árvore = ``base_tree`` + ``puts`` (caminho → blob) − ``deletes``."""
        with tempfile.TemporaryDirectory(prefix="tsm-index-") as tmp:
            env = {"GIT_INDEX_FILE": str(Path(tmp) / "index")}
            if base_tree:
                self.run("read-tree", base_tree, env=env)
            else:
                self.run("read-tree", "--empty", env=env)
            records = []
            for path in deletes:
                records.append(f"0 {ZERO_OID}\t{path}")
            for path, oid in puts.items():
                records.append(f"{FILE_MODE} {oid}\t{path}")
            if records:
                data = ("\0".join(records) + "\0").encode("utf-8")
                self.run("update-index", "-z", "--index-info", input=data, env=env)
            return self.out("write-tree", env=env)

    def commit_tree(self, tree: str, parents: Iterable[str], message: str,
                    author: Author) -> str:
        env = {
            "GIT_AUTHOR_NAME": author.name, "GIT_AUTHOR_EMAIL": author.email,
            "GIT_COMMITTER_NAME": author.name, "GIT_COMMITTER_EMAIL": author.email,
        }
        if author.date:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = author.date
        args = ["commit-tree", tree]
        for p in parents:
            args += ["-p", p]
        return self.out(*args, input=message.encode("utf-8"), env=env)

    # ------------------------------------------------------------ refs e grafo

    def resolve(self, ref: str) -> str | None:
        proc = self.run("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", ok_codes=(0, 1))
        text = proc.stdout.decode().strip()
        return text or None

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        proc = self.run("merge-base", "--is-ancestor", ancestor, descendant, ok_codes=(0, 1))
        return proc.returncode == 0

    def merge_base(self, a: str, b: str) -> str | None:
        proc = self.run("merge-base", a, b, ok_codes=(0, 1))
        return proc.stdout.decode().strip() or None

    def update_refs(self, updates: Iterable[tuple[str, str, str | None]]) -> None:
        """Transação atômica: ``(ref, novo, antigo)``; antigo ``None`` = o ref não pode existir."""
        lines = ["start"]
        for ref, new, old in updates:
            lines.append(f"update {ref} {new} {old or ZERO_OID}")
        lines += ["prepare", "commit"]
        self.run("update-ref", "--stdin", input=("\n".join(lines) + "\n").encode())

    def list_refs(self, prefix: str) -> dict[str, str]:
        text = self.out("for-each-ref", "--format=%(refname) %(objectname)", prefix)
        out = {}
        for line in text.splitlines():
            ref, oid = line.split()
            out[ref] = oid
        return out

    def merge_file(self, ours: bytes, base: bytes, theirs: bytes) -> tuple[int, bytes]:
        """``git merge-file`` sobre bytes: ``(número de conflitos, resultado)``."""
        with tempfile.TemporaryDirectory(prefix="tsm-merge-") as tmp:
            paths = []
            for name, data in (("ours", ours), ("base", base), ("theirs", theirs)):
                f = Path(tmp) / name
                f.write_bytes(data)
                paths.append(str(f))
            proc = self.run("merge-file", "--stdout", *paths, ok_codes=range(0, 128))
        return proc.returncode, proc.stdout

    def merge_trees(self, base: str, ours: str, theirs: str) -> MergeResult:
        """Merge de três vias **por caminho**, sem inferir renomeações.

        Mesmas regras do pull no Client: um lado mudou → vale esse lado; os dois mudaram →
        texto passa por ``git merge-file``; binário, exclusão × modificação e criação ×
        criação com conteúdos diferentes são conflito. Não usa ``git merge-tree``: no Git
        2.43 (Ubuntu 24.04) ele detecta renomeações mesmo com ``merge.renames=false``.
        """
        b, o, t = self.ls_tree(base), self.ls_tree(ours), self.ls_tree(theirs)
        puts: dict[str, str] = {}
        deletes: list[str] = []
        conflicts: list[MergeConflict] = []
        for path in sorted(set(b) | set(o) | set(t)):
            bo, oo, to = b.get(path), o.get(path), t.get(path)
            if oo == to or to == bo:
                continue  # iguais, ou só "ours" mudou: mantém ours
            if oo == bo:  # só "theirs" mudou
                if to is None:
                    deletes.append(path)
                else:
                    puts[path] = to
                continue
            if oo is None or to is None:
                conflicts.append(MergeConflict(path, "delete_modify"))
                continue
            if bo is None:
                conflicts.append(MergeConflict(path, "add_add"))
                continue
            od, bd, td = self.cat_blob(oo), self.cat_blob(bo), self.cat_blob(to)
            if any(is_binary(x) for x in (od, bd, td)):
                conflicts.append(MergeConflict(path, "binary"))
                continue
            n, merged = self.merge_file(od, bd, td)
            if n:
                conflicts.append(MergeConflict(path, "content"))
            else:
                puts[path] = self.hash_bytes(merged)
        if conflicts:
            return MergeResult("", tuple(conflicts))
        return MergeResult(self.build_tree(self.tree_of(ours), puts, deletes), ())

    def log_first_parent(self, ref: str, limit: int | None = None) -> list[CommitInfo]:
        args = ["log", "--first-parent", "--format=%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%B%x1e"]
        if limit:
            args.append(f"-n{limit}")
        raw = self.run(*args, ref, "--").stdout.decode("utf-8")
        out = []
        for rec in raw.split("\x1e"):
            rec = rec.strip("\n")
            if not rec:
                continue
            oid, parents, name, email, date, body = rec.split("\x1f", 5)
            out.append(CommitInfo(oid, tuple(parents.split()), name, email, date, body))
        return out

    def commit_info(self, oid: str) -> CommitInfo:
        raw = self.out("show", "-s", "--format=%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%B", oid)
        h, parents, name, email, date, body = raw.split("\x1f", 5)
        return CommitInfo(h, tuple(parents.split()), name, email, date, body)

    def diff_names(self, a: str | None, b: str) -> list[tuple[str, str]]:
        """``[(status A|M|D, caminho)]`` entre duas árvores/commits (``a`` None = vazio)."""
        if a is None:
            return [("A", p) for p in sorted(self.ls_tree(b))]
        raw = self.run("diff-tree", "-r", "-z", "--no-renames", "--name-status", a, b).stdout
        parts = [p for p in raw.decode("utf-8").split("\0") if p]
        return [(parts[i], parts[i + 1]) for i in range(0, len(parts) - 1, 2)]


def is_binary(data: bytes) -> bool:
    """Heurística do Git: NUL nos primeiros 8000 bytes."""
    return b"\0" in data[:8000]
