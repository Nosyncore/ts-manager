"""Operações de transporte sobre o adaptador Mutagen.

A CLI (e, futuramente, a GUI) chamam este módulo; ele não executa subprocessos diretamente.
Só toca sessões com ``tsm-managed=true`` cujo ``tsm-binding`` pertence à configuração.

Com colaboração (config ``version: 2``), um vínculo ainda não inicializado (``tsm init``)
só tem a sessão de download: a pasta local ainda não existe e o upload não pode espelhá-la.
"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from tsm_client.adapters.mutagen import MutagenAdapter, SessionState, pins
from tsm_client.adapters.mutagen.runner import tool_version
from tsm_client.config import Config, ConfigError, verify_project_folder
from tsm_client.errors import RefusedError
from tsm_client.sessions import (
    LABEL_BINDING,
    LABEL_MANAGED,
    LABEL_ROLE,
    LABEL_SPEC,
    ExistingSession,
    Role,
    SyncSpec,
    build_specs,
    validate_specs,
)

__all__ = ["DoctorReport", "RefusedError", "SessionView", "TransportService", "UpResult",
           "resolve_executable"]


@dataclass(frozen=True)
class UpResult:
    spec: SyncSpec
    action: str  # created | resumed | unchanged
    identifier: str


@dataclass(frozen=True)
class SessionView:
    binding_id: str
    role: Role
    name: str
    session: SessionState | None


@dataclass
class DoctorReport:
    lines: list[tuple[str, str, bool]] = field(default_factory=list)

    def add(self, label: str, value: str, ok: bool = True) -> None:
        self.lines.append((label, value, ok))

    @property
    def ok(self) -> bool:
        return all(ok for _, _, ok in self.lines)


def resolve_executable(cfg: Config, cwd: Path | None = None) -> Path:
    if cfg.mutagen.executable is not None:
        return cfg.mutagen.executable
    for start in (cfg.path.parent, (cwd or Path.cwd()).resolve()):
        root = pins.find_tools_root(start)
        if root is not None:
            return pins.executable_path(root)
    raise ConfigError(
        "Mutagen não encontrado: rode 'python scripts/fetch_mutagen.py' ou defina "
        "mutagen.executable na config"
    )


class TransportService:
    def __init__(self, cfg: Config, adapter: MutagenAdapter,
                 initialized: Callable[[str], bool] | None = None) -> None:
        self.cfg = cfg
        self.adapter = adapter
        self._binding_ids = {b.id for b in cfg.bindings}
        self._initialized = initialized or (lambda _binding_id: True)

    # ------------------------------------------------------------ consultas

    def specs(self) -> list[SyncSpec]:
        out = []
        for b in self.cfg.bindings:
            up, down = build_specs(b)
            out += [up, down] if self._initialized(b.id) else [down]
        return out

    def _is_ours(self, s: SessionState) -> bool:
        return (
            s.labels.get(LABEL_MANAGED) == "true"
            and s.labels.get(LABEL_BINDING) in self._binding_ids
        )

    def managed_sessions(self) -> list[SessionState]:
        return [s for s in self.adapter.list_sessions() if self._is_ours(s)]

    def _match(self, spec: SyncSpec, sessions: Iterable[SessionState]) -> list[SessionState]:
        return [
            s
            for s in sessions
            if self._is_ours(s)
            and s.labels.get(LABEL_BINDING) == spec.binding_id
            and s.labels.get(LABEL_ROLE) == spec.role.value
        ]

    def status(self) -> list[SessionView]:
        sessions = self.managed_sessions()
        views = []
        for spec in self.specs():
            found = self._match(spec, sessions)
            current = found[0] if found else None
            views.append(SessionView(spec.binding_id, spec.role, spec.name, current))
        return views

    # ------------------------------------------------------------ up

    def up(self) -> list[UpResult]:
        for b in self.cfg.bindings:
            if self._initialized(b.id):
                verify_project_folder(b)
        specs = self.specs()
        self.adapter.daemon_start()
        all_sessions = self.adapter.list_sessions(label_selector=None)

        reused: dict[str, SessionState] = {}
        for spec in specs:
            found = self._match(spec, all_sessions)
            if len(found) > 1:
                raise RefusedError(
                    f"{spec.name}: {len(found)} sessões gerenciadas para o mesmo papel; "
                    "rode 'tsm teardown'"
                )
            if found:
                if found[0].labels.get(LABEL_SPEC) != spec.spec_hash:
                    raise RefusedError(
                        f"{spec.name}: a configuração mudou desde a criação da sessão; "
                        "rode 'tsm teardown' e depois 'tsm up'"
                    )
                reused[spec.name] = found[0]

        reused_ids = {s.identifier for s in reused.values()}
        others = [
            ExistingSession(s.name or s.identifier, s.alpha.endpoint, s.beta.endpoint)
            for s in all_sessions
            if s.identifier not in reused_ids
        ]
        validate_specs(specs, others)

        results = []
        for spec in specs:
            current = reused.get(spec.name)
            if current is None:
                results.append(UpResult(spec, "created", self.adapter.create(spec)))
            elif current.paused:
                self.adapter.resume([current.identifier])
                results.append(UpResult(spec, "resumed", current.identifier))
            else:
                results.append(UpResult(spec, "unchanged", current.identifier))
        return results

    # ------------------------------------------------------------ controle

    def _select(self, role: Role | None = None) -> list[SessionState]:
        sessions = self.managed_sessions()
        if role is not None:
            sessions = [s for s in sessions if s.labels.get(LABEL_ROLE) == role.value]
        return sessions

    def flush(self, role: Role | None = None) -> list[SessionState]:
        self.adapter.daemon_start()
        sessions = self._select(role)
        self.adapter.flush([s.identifier for s in sessions])
        return sessions

    def pause(self) -> list[SessionState]:
        self.adapter.daemon_start()
        sessions = [s for s in self._select() if not s.paused]
        self.adapter.pause([s.identifier for s in sessions])
        return sessions

    def resume(self, *, confirm_halted: bool = False) -> list[SessionState]:
        self.adapter.daemon_start()
        sessions = self._select()
        halted = [s for s in sessions if s.status.halted]
        if halted and not confirm_halted:
            names = ", ".join(f"{s.name} ({s.status.value})" for s in halted)
            raise RefusedError(
                f"sessões paradas por salvaguarda: {names}. Verifique as pastas antes de "
                "retomar; para retomar mesmo assim use --confirm-halted"
            )
        targets = [s for s in sessions if s.paused or s.status.halted]
        self.adapter.resume([s.identifier for s in targets])
        return targets

    def teardown(self, *, stop_daemon: bool = False) -> list[SessionState]:
        if not self.adapter.daemon_running():
            return []
        sessions = self._select()
        self.adapter.terminate([s.identifier for s in sessions])
        if stop_daemon:
            self.adapter.daemon_stop()
        return sessions

    # ------------------------------------------------------------ doctor

    def doctor(self) -> DoctorReport:
        r = DoctorReport()
        exe = self.adapter.executable
        if not exe.is_file():
            r.add("mutagen", f"ausente: {exe}", ok=False)
            return r
        r.add("mutagen", str(exe))
        expected = pins.ASSETS.get(_safe_platform(), None)
        if expected and exe.name in expected.extracted_sha256:
            digest = hashlib.sha256(exe.read_bytes()).hexdigest()
            r.add("sha256", digest[:16] + "…", ok=digest == expected.extracted_sha256[exe.name])
        version = self.adapter.version()
        r.add("versão", version, ok=version == pins.MUTAGEN_VERSION)
        bundle = exe.parent / pins.AGENT_BUNDLE_NAME
        r.add("agentes", str(bundle), ok=bundle.is_file())
        ssh_dir = self.cfg.mutagen.ssh_path
        if ssh_dir is not None:
            ssh = ssh_dir / ("ssh.exe" if (ssh_dir / "ssh.exe").exists() else "ssh")
            r.add("ssh", f"{ssh} ({tool_version(ssh, '-V')})", ok=ssh.is_file())
        else:
            r.add("ssh", f"busca padrão do Mutagen ({shutil.which('ssh') or 'não encontrado'})")
        if self.cfg.mutagen.ssh_home is not None:
            cfg_file = self.cfg.mutagen.ssh_home / ".ssh" / "config"
            r.add("HOME gerenciado", str(self.cfg.mutagen.ssh_home), ok=cfg_file.is_file())
        r.add("dados do daemon", str(self.cfg.mutagen.data_directory))
        running = self.adapter.daemon_running()
        r.add("daemon", "rodando" if running else "parado")
        if running:
            r.add("sessões gerenciadas", str(len(self.managed_sessions())))
        return r


def _safe_platform() -> str:
    try:
        return pins.host_platform()
    except RuntimeError:
        return ""

