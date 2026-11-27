"""Inicialização do ``serve`` com identidade real (config ``version: 2``) e manutenção.

Ordem, antes de abrir a porta (qualquer recusa levanta ``StartupError``):

1. em POSIX, ``shared_group`` e ``workspace_group`` entre os grupos efetivos do processo
   (``check_groups``; chamado pela CLI antes de abrir o banco);
2. chaves de host de ``ssh.host_key_files`` (só ``ssh-ed25519``);
3. autoteste do verificador SSHSIG;
4. limpeza dos temporários do verificador deixados por uma queda;
5. ``recover`` dos projetos (diário) e do provisionamento; operações que continuarem
   pendentes não impedem a subida;
6. uma rodada de manutenção; as seguintes rodam numa thread a cada 10 minutos.

Manutenção: apaga desafios e sessões vencidos há mais de 24 h, expira solicitações
pendentes antigas e limpa os temporários do verificador.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from tsm_manager.adapters.sshsig import SshsigUnavailable
from tsm_manager.connection import HostKeyError, load_host_keys
from tsm_manager.identity import accounts, challenges, sessions

if TYPE_CHECKING:
    from tsm_manager.config import ManagerConfig
    from tsm_manager.services import IdentityServices, Manager

MAINTENANCE_INTERVAL_S = 600.0


class StartupError(RuntimeError):
    """O ``serve`` não pode subir; a mensagem diz o que corrigir."""


def check_groups(required: Iterable[str], *, getgroups: Callable[[], list[int]],
                 getegid: Callable[[], int], getgrnam: Callable[[str], Any],
                 user: str) -> None:
    """Recusa se algum grupo exigido não estiver entre os grupos efetivos do processo."""
    current = set(getgroups()) | {getegid()}
    missing = []
    for name in required:
        try:
            gid = getgrnam(name).gr_gid
        except KeyError:
            missing.append(name)
            continue
        if gid not in current:
            missing.append(name)
    if missing:
        names = ",".join(missing)
        raise StartupError(
            f"o processo não está nos grupos {names} (exigidos para ler o shared e os "
            f"workspaces); rode: sudo usermod -aG {names} {user} e reinicie o serviço "
            "(os grupos só valem a partir de um novo login)")


def check_process_groups(cfg: ManagerConfig) -> None:
    """``check_groups`` com os grupos da config e o processo atual; nada fora de POSIX."""
    if os.name != "posix":
        return
    import grp
    import pwd

    required = [g for g in (cfg.shared_group, cfg.workspace_group) if g]
    check_groups(required, getgroups=os.getgroups, getegid=os.getegid,
                 getgrnam=grp.getgrnam, user=pwd.getpwuid(os.geteuid()).pw_name)


@dataclass
class MaintenanceReport:
    challenges: int = 0
    sessions: int = 0
    expired_requests: list[str] = field(default_factory=list)
    stale_dirs: int = 0

    def notes(self) -> list[str]:
        out = []
        if self.challenges or self.sessions:
            out.append(f"manutenção: {self.challenges} desafio(s) e {self.sessions} "
                       "sessão(ões) apagados")
        for device in self.expired_requests:
            out.append(f"manutenção: solicitação {device} expirada")
        if self.stale_dirs:
            out.append(f"manutenção: {self.stale_dirs} temporário(s) do verificador removidos")
        return out


def run_maintenance(ids: IdentityServices) -> MaintenanceReport:
    report = MaintenanceReport(challenges=challenges.purge(ids.ctx),
                               sessions=sessions.purge(ids.ctx),
                               expired_requests=accounts.expire_pending(ids.ctx))
    purge = getattr(ids.ctx.verifier, "purge_stale", None)
    if purge is not None:
        report.stale_dirs = purge()
    return report


class Maintenance:
    """Rodadas de manutenção numa thread daemon; ``stop`` encerra a espera."""

    def __init__(self, ids: IdentityServices, *, interval_s: float = MAINTENANCE_INTERVAL_S,
                 log: Callable[[str], None] = lambda _line: None) -> None:
        self.ids = ids
        self.interval_s = interval_s
        self.log = log
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.rounds = 0

    def run_once(self) -> MaintenanceReport:
        report = run_maintenance(self.ids)
        self.rounds += 1
        for line in report.notes():
            self.log(line)
        return report

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s):
            try:
                self.run_once()
            except Exception as exc:
                self.log(f"manutenção falhou: {type(exc).__name__}")

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="tsm-maintenance",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


def prepare_identity(manager: Manager, *, log: Callable[[str], None]) -> Maintenance:
    """Passos 2 a 6 da inicialização; devolve a manutenção já com a primeira rodada feita."""
    ids = manager.identity
    assert ids is not None
    cfg = manager.cfg
    if cfg.ssh is not None:
        try:
            ids.host_keys = load_host_keys(cfg.ssh.host_key_files)
        except HostKeyError as exc:
            raise StartupError(str(exc)) from exc
    self_check = getattr(ids.ctx.verifier, "self_check", None)
    if self_check is not None:
        try:
            self_check()
        except SshsigUnavailable as exc:
            raise StartupError(f"verificador de assinaturas indisponível: {exc}") from exc
    purge = getattr(ids.ctx.verifier, "purge_stale", None)
    if purge is not None:
        purge()
    if ids.transport == "local":
        log("provisionador local: nenhuma conta SSH é criada (só desenvolvimento e testes)")
    for note in manager.recover_all():
        log(note)
    for result in ids.provisioning.recover():
        log(f"provisionamento: operação {result.op_id} ({result.action}, dispositivo "
            f"{result.device_id}): {result.status}"
            + (f" — {result.error}" if result.error else ""))
    maintenance = Maintenance(ids, log=log)
    maintenance.run_once()
    return maintenance
