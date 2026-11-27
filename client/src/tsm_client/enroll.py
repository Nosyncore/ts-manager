"""Comandos de identidade do dispositivo: ``enroll``, ``whoami``, ``bind`` e ``logout``.

- ``enroll``: prepara o ``<home>``, gera a chave (se faltar), registra com o convite e a
  prova de posse, fixa o ``server_id`` e grava a config ``version: 3``. Repetir é seguro: se
  a chave já estiver cadastrada (queda entre o cadastro e a gravação da config), o cadastro
  é recuperado pelo login com a própria chave, sem consumir outro convite.
- ``whoami``: ``/me`` com a sessão (funciona com o dispositivo pendente).
- ``bind``: ``/connection/config`` validada → conexão gravada → vínculo na config → config
  SSH e ``known_hosts`` reescritos. O ``init`` do vínculo é feito pela CLI em seguida.
- ``logout``: revoga a sessão atual no Manager e apaga o token local.
"""

from __future__ import annotations

import json
import os
import socket
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tsm_client.adapters.acl import Acl, default_acl
from tsm_client.adapters.manager import (
    ManagerClient,
    ManagerProtocolError,
    ManagerUnavailable,
    Transport,
    check_url,
)
from tsm_client.adapters.sshkeygen import SshKeygen, default_ssh_path, keygen_executable
from tsm_client.config import (
    ConfigError,
    HomeBinding,
    HomeConfig,
    MutagenSettings,
    check_own_dirs,
    home_connections,
    read_home_config,
    write_home_config,
)
from tsm_client.errors import RefusedError
from tsm_client.home import Home, prepare_home
from tsm_client.identity import (
    ChallengeSigner,
    ensure_device_key,
    load_device_key,
    valid_id,
    valid_server_id,
)
from tsm_client.login import (
    IdentityPending,
    IdentityRefused,
    ManagerRefused,
    SessionAuth,
    SessionStore,
    refusal,
)
from tsm_client.paths import PathError, canonical_local
from tsm_client.sessions import SessionRuleError, build_specs, validate_specs
from tsm_client.sshconfig import Connection, parse_connection, write_ssh_files
from tsm_common import protocol as P
from tsm_common.fsutil import atomic_write_json

WAIT_INTERVAL_S = 5.0
MAX_NAME = 64

KeygenFactory = Callable[[Path, Path], SshKeygen]


def _real_keygen(ssh_path: Path, ssh_home: Path) -> SshKeygen:
    return SshKeygen(keygen_executable(ssh_path), ssh_home)


@dataclass
class Toolkit:
    """Adaptadores do Client, trocados por falsos nos unitários."""

    acl: Acl = field(default_factory=default_acl)
    keygen: KeygenFactory = _real_keygen
    transport: Transport | None = None
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    hostname: Callable[[], str] = socket.gethostname


def device_name_default(raw: str) -> str:
    text = unicodedata.normalize("NFC", raw or "")
    text = "".join(c for c in text if unicodedata.category(c) != "Cc").strip()
    return (text or "dispositivo")[:MAX_NAME]


@dataclass
class EnrollResult:
    device_id: str
    fingerprint: str
    server_id: str
    status: str
    user_id: str | None
    project_id: str | None
    recovered: bool
    key_created: bool
    approved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class BindResult:
    binding: HomeBinding
    connection: Connection
    created: bool
    host_keys_changed: bool


class Identity:
    def __init__(self, home: Home, toolkit: Toolkit | None = None) -> None:
        self.home = home
        self.tk = toolkit or Toolkit()

    # ------------------------------------------------------------ montagem

    def client(self, url: str, ca_file: str | None, auth: Any = None) -> ManagerClient:
        return ManagerClient(url, auth, transport=self.tk.transport,
                             ca_file=Path(ca_file) if ca_file else None)

    def keygen(self, hc: HomeConfig | None = None) -> SshKeygen:
        return self.tk.keygen(hc.ssh_dir if hc else default_ssh_path(), self.home.ssh_home)

    def store(self) -> SessionStore:
        return SessionStore(self.home, self.tk.acl)

    def session(self, hc: HomeConfig, *, honor_refused: bool = True
                ) -> tuple[ManagerClient, SessionAuth]:
        key = load_device_key(self.home)
        if key is None:
            raise ConfigError(f"chave do dispositivo ausente em {self.home.ssh_dir}")
        if key.fingerprint != hc.fingerprint:
            raise RefusedError("a chave do dispositivo não confere com o cadastro "
                               f"({key.fingerprint} ≠ {hc.fingerprint})")
        auth = SessionAuth(self.store(), ChallengeSigner(self.keygen(hc), key),
                           server_id=hc.server_id, device_id=hc.device_id,
                           honor_refused=honor_refused)
        return self.client(hc.manager_url, hc.ca_file, auth), auth

    # ------------------------------------------------------------ enroll

    def enroll(self, *, manager_url: str, invite: str, name: str | None = None,
               device_name: str | None = None, ca_file: str | None = None,
               wait: float | None = None) -> EnrollResult:
        url = check_url(manager_url)
        ca = None
        if ca_file:
            ca_path = Path(ca_file)
            if not ca_path.is_absolute() or not ca_path.is_file():
                raise ConfigError(f"--ca-file precisa ser um arquivo com caminho absoluto: "
                                  f"{ca_file}")
            ca = str(ca_path)
        if self.home.config_path.exists():
            hc = read_home_config(self.home)
            raise RefusedError(f"já há um dispositivo cadastrado em {self.home.root} "
                               f"({hc.device_id}); use outro --home")
        prepare_home(self.home, self.tk.acl)
        keygen = self.keygen()
        key, created = ensure_device_key(self.home, keygen, self.tk.acl)
        signer = ChallengeSigner(keygen, key)
        client = self.client(url, ca)

        ch = client.challenge({"purpose": "register", "public_key": key.public_line})
        if not ch.ok:
            raise refusal(ch, "desafio de cadastro")
        server_id = valid_server_id(ch.body.get("server_id"))
        body: dict[str, Any] = {
            "invite": invite,
            "device_name": device_name_default(device_name or self.tk.hostname()),
            "challenge_id": ch.body.get("challenge_id"),
            "signature": signer.answer(ch.body, "register")}
        if name:
            body["display_name"] = name
        r = client.register(body)
        recovered = False
        if r.http_status == 201:
            if r.body.get("fingerprint") != key.fingerprint:
                raise ManagerProtocolError("o Manager registrou outro fingerprint")
            device_id = str(r.body.get("device_id"))
            status, user_id = str(r.body.get("status")), r.body.get("user_id")
            project_id = r.body.get("project_id")
        elif r.status == P.KEY_IN_USE:
            device_id, status, user_id = self._recover(client, signer, server_id)
            project_id, recovered = None, True
        elif r.http_status == 401:
            raise ManagerRefused(r, "cadastro (prova de posse recusada)")
        else:
            raise refusal(r, "cadastro")

        hc = HomeConfig(url, server_id, valid_id(device_id, "id do dispositivo"),
                        key.fingerprint, ca_file=ca)
        write_home_config(self.home, hc)
        self.store().clear_refused()
        result = EnrollResult(device_id, key.fingerprint, server_id, status, user_id,
                              project_id, recovered, created)
        if wait is not None:
            result.status = self.wait_approval(hc, wait)
            result.approved = result.status == "active"
        return result

    def _recover(self, client: ManagerClient, signer: ChallengeSigner,
                 server_id: str) -> tuple[str, str, str | None]:
        auth = SessionAuth(self.store(), signer, server_id=server_id, device_id=None,
                           honor_refused=False)
        authed = ManagerClient(client.url, auth, transport=client.transport)
        me = authed.me()
        if not me.ok:
            raise refusal(me, "consulta do cadastro")
        device = me.body.get("device") or {}
        if device.get("fingerprint") != signer.key.fingerprint:
            raise ManagerProtocolError("o Manager devolveu outro dispositivo")
        return str(device.get("id")), str(device.get("status")), \
            (me.body.get("user") or {}).get("id")

    def wait_approval(self, hc: HomeConfig, timeout: float) -> str:
        client, auth = self.session(hc, honor_refused=False)
        deadline = self.tk.monotonic() + max(0.0, timeout)
        while True:
            r = client.me()
            if not r.ok:
                raise refusal(r, "consulta do cadastro")
            status = str((r.body.get("device") or {}).get("status"))
            if status == "active":
                auth.ensure_full(client)
                return status
            if status not in ("pending", "provisioning"):
                raise IdentityRefused(f"solicitação {status}: fale com o admin")
            remaining = deadline - self.tk.monotonic()
            if remaining <= 0:
                raise IdentityPending(f"ainda aguardando aprovação após {timeout:.0f} s "
                                      "(rode 'tsm whoami' depois)")
            self.tk.sleep(min(WAIT_INTERVAL_S, remaining))

    # ------------------------------------------------------------ whoami

    def whoami(self) -> dict[str, Any]:
        hc = read_home_config(self.home)
        client, auth = self.session(hc, honor_refused=False)
        r = client.me()
        if r.ok and (r.body.get("device") or {}).get("status") == "active" \
                and (r.body.get("session") or {}).get("scope") == "pending":
            auth.ensure_full(client)  # aprovado depois do login: a sessão não é promovida
            r = client.me()
        if not r.ok:
            raise refusal(r, "consulta da identidade")
        valid = valid_server_id(r.body.get("server_id"))
        if valid != hc.server_id:
            raise RefusedError("o Manager respondeu com outro server_id")
        return {"manager": hc.manager_url, "server_id": hc.server_id,
                "home": str(self.home.root), "fingerprint": hc.fingerprint,
                "user": r.body.get("user"), "device": r.body.get("device"),
                "session": r.body.get("session"), "bindings": r.body.get("bindings", []),
                "local_bindings": [{"id": b.id, "project_id": b.project_id, "local": b.local,
                                    "cache": b.cache} for b in hc.bindings]}

    # ------------------------------------------------------------ bind

    def bind(self, project: str, local: str | None = None,
             cache: str | None = None) -> BindResult:
        hc = read_home_config(self.home)
        client, _ = self.session(hc)
        r = client.connection_config(project)
        if not r.ok:
            raise refusal(r, f"configuração de conexão do projeto {project}")
        conn = parse_connection(r.body, server_id=hc.server_id, device_id=hc.device_id,
                                project_id=project)
        existing = hc.binding_for(project)
        try:
            local_c = canonical_local(local) if local else None
            cache_c = canonical_local(cache) if cache else None
        except PathError as exc:
            raise ConfigError(str(exc)) from exc
        if existing is not None:
            if existing.id != conn.binding_id:
                raise RefusedError(f"o Manager devolveu outro vínculo ({conn.binding_id}) "
                                   f"para o projeto {project} (local: {existing.id})")
            def differs(a: str | None, b: str) -> bool:
                return a is not None and os.path.normcase(a) != os.path.normcase(b)

            if differs(local_c, existing.local) or differs(cache_c, existing.cache):
                raise RefusedError(f"o projeto {project} já está vinculado a "
                                   f"{existing.local}; trocar a pasta não é suportado")
            hb, created = existing, False
        else:
            if local_c is None:
                raise ConfigError("informe --local no primeiro bind do projeto")
            hb = HomeBinding(conn.binding_id, project, local_c,
                             cache_c or str(self.home.default_cache(project)))
            created = True
        self._validate(hb, conn)

        path = self.home.connection_file(hb.id)
        changed = False
        if path.is_file():
            try:
                old = json.loads(path.read_text("utf-8"))
                old_keys = ((old.get("ssh") or {}).get("host_keys")) or []
            except (OSError, ValueError, AttributeError):
                old_keys = []
            changed = bool(old_keys) and sorted(old_keys) != sorted(conn.host_keys)
        atomic_write_json(path, conn.raw)
        # o Mutagen exige que o pai da raiz de destino exista (ex.: <home>/cache/)
        Path(hb.cache).parent.mkdir(parents=True, exist_ok=True)
        if created:
            hc.bindings.append(hb)
            write_home_config(self.home, hc)
        write_ssh_files(self.home, home_connections(self.home, hc))
        return BindResult(hb, conn, created, changed)

    def _validate(self, hb: HomeBinding, conn: Connection) -> None:
        self.home.check_outside(Path(hb.local))
        binding = conn.binding(hb.local, hb.cache)
        settings = MutagenSettings(self.home.mutagen_data, None, None, self.home.ssh_home)
        try:
            validate_specs(list(build_specs(binding)))
        except SessionRuleError as exc:
            raise ConfigError(str(exc)) from exc
        check_own_dirs(settings, self.home.state, [binding])

    # ------------------------------------------------------------ logout

    def logout(self) -> bool:
        """``True`` se havia sessão; ``ManagerUnavailable`` após apagar o token local."""
        hc = read_home_config(self.home)
        store = self.store()
        session = store.load()
        if session is None:
            return False
        try:
            self.client(hc.manager_url, hc.ca_file).logout(f"Bearer {session['token']}")
        except ManagerUnavailable:
            store.clear()
            raise
        store.clear()
        return True
