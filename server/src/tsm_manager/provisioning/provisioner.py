"""Contas SSH de dispositivo: interface ``Provisioner`` e suas implementações.

- ``SudoProvisioner``: chama o helper root ``tsm-provision`` com ``sudo -n``, lista de
  argumentos, chave pela entrada padrão e ambiente mínimo; interpreta a linha JSON e o
  código de saída (0 ok, 2 inválido, 3 conflito, 4 falha do sistema).
- ``LocalProvisioner``: desenvolvimento no Windows e testes locais. Não cria conta: cria
  só o portão e o ``tree/`` sob ``<root>`` e guarda o estado da "conta" em
  ``<root>/manager/local-accounts/``, para que a conferência funcione de verdade.

O serviço (``provisioning.service``) chama sempre o verbo e depois ``inspect_device``.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from tsm_common.sshkeys import PublicKeyError, parse_public_key
from tsm_manager.layout import ProjectLayout

DEFAULT_HELPER = "/usr/local/libexec/tsm-provision"
DEFAULT_SUDO = "/usr/bin/sudo"
DEFAULT_TIMEOUT_S = 60.0
HOME_MODE = 0o700
GATE_MODE = 0o750
TREE_MODE = 0o750
MAX_DETAIL_CHARS = 200
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}
_ACCOUNT_RE = re.compile(r"^tsm-d-[0-9a-f]{12}$")
_PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_EXIT_KINDS = {2: "invalid", 3: "conflict", 4: "system"}


class ProvisionError(Exception):
    """Falha de provisionamento: ``kind`` em invalid, conflict, system, timeout, unavailable."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(f"{kind}: {message}")
        self.kind = kind
        self.message = message


@dataclass(frozen=True)
class AccountPolicy:
    devices_group: str = "tsm-devices"
    shared_group: str = "tsm-readers"
    workspace_group: str = "tsm-ws"
    manager_group: str = "tsm-manager"

    @property
    def device_groups(self) -> frozenset[str]:
        return frozenset((self.devices_group, self.shared_group, self.workspace_group))


@dataclass(frozen=True)
class DirInfo:
    owner: str
    group: str
    mode: int


@dataclass(frozen=True)
class Inspection:
    exists: bool
    expired: bool
    groups: frozenset[str]
    key_fingerprint: str | None
    processes: int
    home: DirInfo | None
    gate: DirInfo | None
    tree: DirInfo | None


class Provisioner(Protocol):
    def create_device(self, account: str, project: str, public_key: str) -> None: ...
    def disable_device(self, account: str) -> None: ...
    def enable_device(self, account: str, public_key: str) -> None: ...
    def delete_device(self, account: str, project: str) -> None: ...
    def inspect_device(self, account: str, project: str) -> Inspection: ...


def _key_line(public_key: str) -> str:
    try:
        return parse_public_key(public_key).openssh
    except PublicKeyError as exc:
        raise ProvisionError("invalid", f"chave recusada: {exc}") from exc


def _detail(value: object) -> str:
    text = str(value) if value is not None else ""
    return "".join(c for c in text if c.isprintable())[:MAX_DETAIL_CHARS]


# ---------------------------------------------------------------- sudo + helper


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: bytes


Runner = Callable[[Sequence[str], bytes, Mapping[str, str], float], Completed]


def run_process(argv: Sequence[str], stdin: bytes, env: Mapping[str, str],
                timeout: float) -> Completed:
    proc = subprocess.run(list(argv), input=stdin, env=dict(env), stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    return Completed(proc.returncode, proc.stdout)


def _dir_info(raw: object) -> DirInfo | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("diretório")
    owner, group, mode = raw["owner"], raw["group"], raw["mode"]
    if not (isinstance(owner, str) and isinstance(group, str) and isinstance(mode, str)):
        raise ValueError("diretório")
    return DirInfo(owner, group, int(mode, 8))


def parse_inspection(raw: dict[str, Any]) -> Inspection:
    try:
        groups = raw["groups"]
        fingerprint = raw["key_fingerprint"]
        if (not isinstance(raw["exists"], bool) or not isinstance(raw["expired"], bool)
                or not isinstance(groups, list)
                or not all(isinstance(g, str) for g in groups)
                or not (fingerprint is None or isinstance(fingerprint, str))
                or isinstance(raw["processes"], bool)
                or not isinstance(raw["processes"], int)):
            raise ValueError("tipos")
        return Inspection(raw["exists"], raw["expired"], frozenset(groups), fingerprint,
                          raw["processes"], _dir_info(raw["home"]), _dir_info(raw["gate"]),
                          _dir_info(raw["tree"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ProvisionError("system", "inspeção do helper em formato inesperado") from exc


class SudoProvisioner:
    def __init__(self, helper: str = DEFAULT_HELPER, *, sudo: str = DEFAULT_SUDO,
                 timeout_s: float = DEFAULT_TIMEOUT_S, runner: Runner = run_process) -> None:
        for name, value in (("helper", helper), ("sudo", sudo)):
            if not value.startswith("/"):
                raise ValueError(f"{name} deve ter caminho absoluto: {value}")
        if timeout_s <= 0:
            raise ValueError("timeout deve ser positivo")
        self.helper = helper
        self.sudo = sudo
        self.timeout_s = float(timeout_s)
        self._runner = runner

    def _call(self, verb: str, *args: str, key: str | None = None) -> dict[str, Any]:
        argv = [self.sudo, "-n", self.helper, verb, *args]
        stdin = (_key_line(key) + "\n").encode("ascii") if key is not None else b""
        try:
            done = self._runner(argv, stdin, dict(_ENV), self.timeout_s)
        except subprocess.TimeoutExpired as exc:
            raise ProvisionError("timeout", f"{verb}: tempo esgotado") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProvisionError("unavailable", f"{verb}: sudo indisponível") from exc
        try:
            lines = done.stdout.decode("utf-8").splitlines()
            reply = json.loads(lines[-1]) if lines else None
        except (UnicodeDecodeError, ValueError):
            reply = None
        if done.returncode == 0 and isinstance(reply, dict) and reply.get("ok") is True:
            return reply
        if done.returncode in _EXIT_KINDS:
            detail = _detail(reply.get("detail")) if isinstance(reply, dict) else ""
            raise ProvisionError(_EXIT_KINDS[done.returncode], f"{verb}: {detail}")
        if reply is None and done.returncode == 1:
            raise ProvisionError("unavailable", f"{verb}: sudo recusou (código 1)")
        raise ProvisionError("system", f"{verb}: resposta inesperada (código "
                             f"{done.returncode})")

    def create_device(self, account: str, project: str, public_key: str) -> None:
        self._call("create-device", account, project, key=public_key)

    def disable_device(self, account: str) -> None:
        self._call("disable-device", account)

    def enable_device(self, account: str, public_key: str) -> None:
        self._call("enable-device", account, key=public_key)

    def delete_device(self, account: str, project: str) -> None:
        self._call("delete-device", account, project)

    def inspect_device(self, account: str, project: str) -> Inspection:
        return parse_inspection(self._call("inspect-device", account, project))


# ---------------------------------------------------------------- local


class LocalProvisioner:
    """Sem contas do sistema: diretórios sob ``<root>`` e estado em ``manager/local-accounts``."""

    def __init__(self, root: str | os.PathLike[str], policy: AccountPolicy | None = None,
                 *, state_dir: str | os.PathLike[str] | None = None) -> None:
        self.root = Path(root)
        self.policy = policy or AccountPolicy()
        self.state_dir = Path(state_dir) if state_dir else self.root / "manager" / \
            "local-accounts"

    def _check(self, account: str, project: str | None = None) -> None:
        if not _ACCOUNT_RE.match(account):
            raise ProvisionError("invalid", "conta inválida")
        if project is not None and not _PROJECT_RE.match(project):
            raise ProvisionError("invalid", "projeto inválido")

    def _state_path(self, account: str) -> Path:
        return self.state_dir / f"{account}.json"

    def _load(self, account: str) -> dict[str, Any] | None:
        path = self._state_path(account)
        if not path.exists():
            return None
        return json.loads(path.read_text("utf-8"))

    def _save(self, account: str, state: dict[str, Any]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        tmp = self._state_path(account).with_suffix(".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._state_path(account))

    def _layout(self, project: str) -> ProjectLayout:
        layout = ProjectLayout(self.root, project)
        if not layout.workspaces.is_dir():
            raise ProvisionError("system", f"workspaces ausente no projeto {project}")
        return layout

    def create_device(self, account: str, project: str, public_key: str) -> None:
        self._check(account, project)
        line = _key_line(public_key)
        layout = self._layout(project)
        state = self._load(account)
        if state is not None and state["key"] not in (None, line):
            raise ProvisionError("conflict", "conta existente com outra chave")
        for path, mode in ((layout.account_gate(account), GATE_MODE),
                           (layout.sync_root(account), TREE_MODE)):
            path.mkdir(exist_ok=True)
            with contextlib.suppress(OSError):
                path.chmod(mode)
        self._save(account, {"project": project, "key": line, "expired": False})

    def disable_device(self, account: str) -> None:
        self._check(account)
        state = self._load(account)
        if state is not None:
            self._save(account, {**state, "key": None, "expired": True})

    def enable_device(self, account: str, public_key: str) -> None:
        self._check(account)
        line = _key_line(public_key)
        state = self._load(account)
        if state is None:
            raise ProvisionError("conflict", "conta inexistente")
        self._save(account, {**state, "key": line, "expired": False})

    def delete_device(self, account: str, project: str) -> None:
        self._check(account, project)
        layout = self._layout(project)
        self._state_path(account).unlink(missing_ok=True)
        gate = layout.account_gate(account)
        if gate.is_dir():
            shutil.rmtree(gate)

    def inspect_device(self, account: str, project: str) -> Inspection:
        self._check(account, project)
        layout = self._layout(project)
        state = self._load(account)
        p = self.policy

        def info(path: Path, group: str, mode: int) -> DirInfo | None:
            return DirInfo(account, group, mode) if path.is_dir() else None

        key = state["key"] if state else None
        return Inspection(
            exists=state is not None,
            expired=bool(state and state["expired"]),
            groups=(p.device_groups | {account}) if state else frozenset(),
            key_fingerprint=parse_public_key(key).fingerprint if key else None,
            processes=0,
            home=DirInfo(account, account, HOME_MODE) if state else None,
            gate=info(layout.account_gate(account), p.manager_group, GATE_MODE),
            tree=info(layout.sync_root(account), p.workspace_group, TREE_MODE),
        )
