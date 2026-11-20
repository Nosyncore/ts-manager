import errno
import fcntl
import os
import re
import sqlite3
import stat
import subprocess
import tomllib
from contextlib import closing, contextmanager
from itertools import combinations
from pathlib import Path

from .common import ManagerError, lua_path, read_limited, sha256


MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

SCHEMA = """
CREATE TABLE IF NOT EXISTS revisions (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    parent INTEGER REFERENCES revisions(id),
    digest TEXT NOT NULL,
    actor TEXT NOT NULL,
    operation TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_revision ON revisions(state) WHERE state = 'pending';
CREATE TABLE IF NOT EXISTS published (
    path TEXT PRIMARY KEY,
    revision INTEGER NOT NULL REFERENCES revisions(id)
);
CREATE TABLE IF NOT EXISTS bases (
    path TEXT NOT NULL,
    actor TEXT NOT NULL,
    revision INTEGER NOT NULL REFERENCES revisions(id),
    PRIMARY KEY (path, actor)
);
"""


def directory(path, config_dir, *, workspace=False):
    root = Path(os.path.abspath(config_dir / path))
    if not workspace:
        root = root.resolve(strict=True)
    if not root.is_dir():
        raise ManagerError(f"O diretório {root} precisa existir.")
    return root


@contextmanager
def parent_directory(root, path):
    """Abre cada componente sem seguir links, mesmo durante uma troca concorrente."""
    *parents, name = path.split("/")
    fd = os.open(root.anchor, DIRECTORY_FLAGS)
    try:
        for part in (*root.parts[1:], *parents):
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, name
    finally:
        os.close(fd)


def read_at(parent, name):
    with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ManagerError(f"{name} precisa ser um arquivo regular sem links.")
        return read_limited(source), info


def read_file(root, path):
    try:
        with parent_directory(root, path) as (parent, name):
            return read_at(parent, name)[0]
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ManagerError(f"O caminho de {path} contém um link ou componente inválido.") from error
        raise


def sync_directory(path):
    fd = os.open(path, DIRECTORY_FLAGS)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data):
    path.unlink(missing_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


class Publisher:
    def __init__(self, config):
        with config.open("rb") as source:
            settings = tomllib.load(source)
        root = config.resolve().parent
        self.target = directory(settings["target"], root)
        self.state = directory(settings["state"], root)
        self.staging = directory(settings["staging"], root)
        self.validator = (root / settings["validator"]).resolve(strict=True)
        if not self.validator.is_file() or not os.access(self.validator, os.X_OK):
            raise ManagerError("Configure um executável luac para validar os arquivos.")
        self.allowed = {lua_path(path) for path in settings["allowed"]}
        self.workspaces = {
            actor: directory(path, root, workspace=True) for actor, path in settings["workspaces"].items()
        }
        if not self.allowed or not self.workspaces:
            raise ManagerError("Configure os caminhos permitidos e os workspaces do piloto.")
        roots = [self.target, self.state, self.staging, *self.workspaces.values()]
        for first, second in combinations(roots, 2):
            if first.is_relative_to(second) or second.is_relative_to(first):
                raise ManagerError("Configure raízes independentes para destino, estado, staging e workspaces.")
        self.snapshots = self.state / "snapshots"

    @contextmanager
    def locked(self):
        with (self.state / "publish.lock").open("ab") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.snapshots.mkdir(mode=0o700, exist_ok=True)
            with closing(sqlite3.connect(self.state / "revisions.sqlite3")) as db:
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA foreign_keys = ON")
                db.execute("PRAGMA synchronous = FULL")
                db.executescript(SCHEMA)
                sync_directory(self.state)
                self._recover(db)
                yield db

    def _workspace(self, actor, path):
        if actor not in self.workspaces:
            raise ManagerError("Identidade sem workspace configurado.")
        return read_file(self.workspaces[actor], path)

    def _allow(self, path):
        if lua_path(path) not in self.allowed:
            raise ManagerError("O arquivo está fora da lista de publicação.")

    def _current(self, db, path):
        row = db.execute(
            "SELECT revisions.* FROM revisions JOIN published ON revisions.id = published.revision WHERE published.path = ?",
            (path,),
        ).fetchone()
        if row is None:
            raise ManagerError("Inicialize a revisão do arquivo com o comando init.")
        return row

    def _base(self, db, path, actor):
        row = db.execute("SELECT revision FROM bases WHERE path = ? AND actor = ?", (path, actor)).fetchone()
        if row is None:
            raise ManagerError("Identidade sem revisão-base para este arquivo.")
        return row["revision"]

    def _insert_revision(self, db, path, parent, digest, actor, operation, state):
        return db.execute(
            "INSERT INTO revisions(path, parent, digest, actor, operation, state) VALUES (?, ?, ?, ?, ?, ?)",
            (path, parent, digest, actor, operation, state),
        ).lastrowid

    def _snapshot(self, data):
        digest = sha256(data)
        path = self.snapshots / digest
        if path.exists():
            self._read_snapshot(digest)
            return digest
        used = sum(item.stat().st_size for item in self.snapshots.iterdir() if item.name != ".pending")
        if used + len(data) > MAX_SNAPSHOT_BYTES:
            raise ManagerError("O limite de 32 MiB dos snapshots foi alcançado.")
        temporary = self.snapshots / ".pending"
        write_new(temporary, data)
        os.replace(temporary, path)
        sync_directory(self.snapshots)
        return digest

    def _read_snapshot(self, digest):
        data = read_file(self.snapshots, digest)
        if sha256(data) != digest:
            raise ManagerError("O SHA-256 do snapshot diverge. Verifique o estado antes de continuar.")
        return data

    def _finish(self, db, revision):
        with db:
            db.execute("UPDATE revisions SET state = 'applied' WHERE id = ?", (revision["id"],))
            db.execute("UPDATE published SET revision = ? WHERE path = ?", (revision["id"], revision["path"]))
            if revision["operation"] == "publish":
                db.execute(
                    "UPDATE bases SET revision = ? WHERE path = ? AND actor = ?",
                    (revision["id"], revision["path"], revision["actor"]),
                )

    def _recover(self, db):
        pending = db.execute("SELECT * FROM revisions WHERE state = 'pending'").fetchone()
        if pending is None:
            return
        path = pending["path"]
        previous = self._current(db, path)
        with parent_directory(self.target, path) as (parent, name):
            actual = sha256(read_at(parent, name)[0])
            if actual == pending["digest"]:
                os.fsync(parent)
                sync_directory(self.staging)
                self._finish(db, pending)
            elif actual == previous["digest"]:
                with db:
                    db.execute("UPDATE revisions SET state = 'aborted' WHERE id = ?", (pending["id"],))
            else:
                raise ManagerError(f"A recuperação de {path} encontrou um terceiro conteúdo. Investigue o destino.")

    def _validate(self, staged, data):
        if b"\x00" in data or b"\x1b" in data:
            raise ManagerError("O validador aceita somente código-fonte Lua em texto.")
        result = subprocess.run(
            [str(self.validator), "-p", str(staged)], capture_output=True, text=True, errors="replace", timeout=10,
        )
        if result.returncode:
            diagnostic = result.stderr.strip().replace(str(staged), "arquivo selecionado")
            raise ManagerError(f"Sintaxe Lua inválida. {diagnostic}")

    def initialize(self, path, actor):
        self._allow(path)
        with self.locked() as db:
            if db.execute("SELECT 1 FROM published WHERE path = ?", (path,)).fetchone():
                raise ManagerError("O arquivo já tem uma revisão inicial.")
            data = read_file(self.target, path)
            for developer in self.workspaces:
                if self._workspace(developer, path) != data:
                    raise ManagerError(f"O arquivo inicial em {developer} diverge do destino.")
            digest = self._snapshot(data)
            with db:
                revision = self._insert_revision(db, path, None, digest, actor, "init", "applied")
                db.execute("INSERT INTO published VALUES (?, ?)", (path, revision))
                db.executemany("INSERT INTO bases VALUES (?, ?, ?)", ((path, dev, revision) for dev in self.workspaces))
        return {"path": path, "revision": revision, "sha256": digest}

    def status(self, path, actor):
        self._allow(path)
        with self.locked() as db:
            current = self._current(db, path)
            base = self._base(db, path, actor)
            try:
                workspace_digest = sha256(self._workspace(actor, path))
            except FileNotFoundError:
                workspace_digest = None
            return {
                "path": path,
                "revision": current["id"],
                "base": base,
                "sha256": current["digest"],
                "workspace_sha256": workspace_digest,
                "target_sha256": sha256(read_file(self.target, path)),
            }

    def _apply(self, db, path, actor, current, data, operation):
        staged = self.staging / "candidate"
        with parent_directory(self.target, path) as (parent, name):
            fd = os.open(self.staging, DIRECTORY_FLAGS)
            try:
                previous, info = read_at(parent, name)
                if sha256(previous) != current["digest"]:
                    raise ManagerError("O destino diverge da revisão registrada. Investigue a edição externa.")
                digest = sha256(data)
                if digest == current["digest"]:
                    return {"path": path, "revision": current["id"], "sha256": digest, "changed": False}
                if os.fstat(fd).st_dev != info.st_dev:
                    raise ManagerError("O staging e o destino precisam compartilhar o sistema de arquivos.")
                if info.st_uid != os.geteuid():
                    raise ManagerError("O Lua no destino deve pertencer à conta do publicador.")
                write_new(staged, data)
                if operation == "publish":
                    self._validate(staged, data)
                with staged.open("rb+") as candidate:
                    os.fchown(candidate.fileno(), -1, info.st_gid)
                    os.fchmod(candidate.fileno(), stat.S_IMODE(info.st_mode) & 0o777)
                    os.fsync(candidate.fileno())
                self._snapshot(previous)
                self._snapshot(data)
                with db:
                    revision = self._insert_revision(db, path, current["id"], digest, actor, operation, "pending")
                if sha256(read_at(parent, name)[0]) != current["digest"]:
                    raise ManagerError("O destino foi alterado durante a publicação.")
                os.replace(staged.name, name, src_dir_fd=fd, dst_dir_fd=parent)
                os.fsync(parent)
                os.fsync(fd)
                self._finish(db, db.execute("SELECT * FROM revisions WHERE id = ?", (revision,)).fetchone())
                return {"path": path, "revision": revision, "sha256": digest, "changed": True}
            finally:
                os.close(fd)
                staged.unlink(missing_ok=True)

    def publish(self, path, actor, expected_hash):
        self._allow(path)
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
            raise ManagerError("A publicação precisa de um SHA-256 em hexadecimal minúsculo.")
        with self.locked() as db:
            current = self._current(db, path)
            base = self._base(db, path, actor)
            if base != current["id"]:
                raise ManagerError(f"Conflito em {path}. A base {base} diverge da revisão publicada {current['id']}.")
            try:
                data = self._workspace(actor, path)
            except FileNotFoundError as error:
                raise ManagerError(f"{path} está ausente no workspace remoto.") from error
            if sha256(data) != expected_hash:
                raise ManagerError("O workspace remoto diverge do SHA-256 local. Confira o Mutagen e tente novamente.")
            return self._apply(db, path, actor, current, data, "publish")

    def rollback(self, path, actor, expected_revision):
        self._allow(path)
        with self.locked() as db:
            current = self._current(db, path)
            if current["id"] != expected_revision or current["parent"] is None:
                raise ManagerError("A restauração exige a revisão publicada atual e um snapshot anterior.")
            previous = db.execute("SELECT digest FROM revisions WHERE id = ?", (current["parent"],)).fetchone()
            return self._apply(db, path, actor, current, self._read_snapshot(previous["digest"]), "rollback")

    def adopt(self, path, actor, expected_revision):
        self._allow(path)
        with self.locked() as db:
            current = self._current(db, path)
            self._base(db, path, actor)
            if current["id"] != expected_revision or sha256(read_file(self.target, path)) != current["digest"]:
                raise ManagerError("A adoção exige a revisão atual e um destino íntegro.")
            with db:
                db.execute("UPDATE bases SET revision = ? WHERE path = ? AND actor = ?", (expected_revision, path, actor))
        return {"path": path, "actor": actor, "base": expected_revision}
