"""Transporte Windows → contêiner sshd linux/arm64 com Mutagen e OpenSSH reais."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from tsm_client.adapters.mutagen import Status
from tsm_client.treehash import manifest

from .conftest import REMOTE_PROJECT, SshLayout, docker, filter_manifest

pytestmark = [pytest.mark.ssh, pytest.mark.timeout(900)]

SSH_TIMEOUT = 300.0


def write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def up_pc(pc) -> None:
    pc.tsm("up")
    pc.wait_watching(timeout=SSH_TIMEOUT)
    pc.tsm("flush")


def test_up_installs_arm64_agent_and_uses_managed_home(ssh_layout: SshLayout, record_property):
    c = ssh_layout.container
    c.setup("clear-agents")
    start = time.monotonic()
    for pc in (ssh_layout.a, ssh_layout.b):
        up_pc(pc)
    record_property("up_seconds", round(time.monotonic() - start, 1))

    # agente linux/arm64 instalado via scp/SFTP nas contas de dispositivo
    for user in ("tsm-dev-a", "tsm-dev-b"):
        out = c.sh(f"ls /home/{user}/.mutagen/agents/*/mutagen-agent && "
                   f"uname -m").stdout
        assert "mutagen-agent" in out and "aarch64" in out
    agent = c.sh("file -b /home/tsm-dev-a/.mutagen/agents/*/mutagen-agent || "
                 "od -An -tx1 -j18 -N2 /home/tsm-dev-a/.mutagen/agents/*/mutagen-agent",
                 check=False).stdout
    print(f"\nS1 agente: {agent.strip()}")

    # /srv/ts em outro filesystem que /home (staging em ~/.mutagen)
    devs = c.sh("stat -c %d /home /srv/ts").stdout.split()
    assert devs[0] != devs[1]

    # 4 sessões em watching; conteúdos convergem
    for pc in (ssh_layout.a, ssh_layout.b):
        sessions = pc.sessions()
        assert {r: s.status for r, s in sessions.items()} == {
            "upload": Status.WATCHING, "download": Status.WATCHING}
        assert sessions["upload"].beta.endpoint.host in ("tsm-test-a", "tsm-test-b")
    m = ssh_layout.matcher()
    for pc, dev in ((ssh_layout.a, "dev-a"), (ssh_layout.b, "dev-b")):
        assert filter_manifest(c.manifest(SshLayout.workspace(dev)), m) == manifest(pc.work, m)
        assert manifest(pc.cache) == c.manifest(SshLayout.shared)

    # o alias tsm-test-a só existe na config gerenciada; conectar prova que ela foi usada.
    # O ~/.ssh pessoal é conferido pela fixture de sessão (personal_ssh_untouched).
    raw = ssh_layout.a.adapter.list_sessions()
    (ssh_up,) = [s for s in raw if s.labels["tsm-role"] == "upload"]
    record_property("ssh_session_json", json.dumps(ssh_up.raw)[:2000])
    capture = os.environ.get("TSM_CAPTURE_FIXTURES")
    if capture:
        Path(capture, "list_ssh_watching.json").write_text(
            json.dumps([ssh_up.raw], indent=2) + "\n", encoding="utf-8")


def test_propagation_deletions_ignores_and_flush_loop(ssh_layout: SshLayout):
    c, a, b = ssh_layout.container, ssh_layout.a, ssh_layout.b
    for pc in (a, b):
        up_pc(pc)
    ws_a, ws_b = SshLayout.workspace("dev-a"), SshLayout.workspace("dev-b")
    m = ssh_layout.matcher()
    ws_b_before = c.manifest(ws_b)
    shared_before = c.manifest(SshLayout.shared)

    for rel, text in {".env": "S=1\n", "logs/a.log": "l\n", "build/x": "b\n",
                      "data/x.tmp": "t\n", "__pycache__/m.pyc": "p\n"}.items():
        write(a.work / rel, text)
    write(a.work / "data" / "novo.lua", "return 1\n")
    (a.work / "data" / "scripts" / "creatures.lua").unlink()
    a.tsm("flush", "--role", "upload")
    remote = c.manifest(ws_a)
    assert filter_manifest(remote, m) == manifest(a.work, m)
    assert remote == filter_manifest(remote, m)  # nenhum ignorado chegou
    assert "data/scripts/creatures.lua" not in remote

    # réplica: intruso no workspace remoto é removido
    c.sh(f"echo intruso > {ws_a}/intruso.lua && chown tsm-dev-a {ws_a}/intruso.lua")
    a.tsm("flush", "--role", "upload")
    assert "intruso.lua" not in c.manifest(ws_a)

    mismatches = []
    target = a.work / "data" / "scripts" / "spells.lua"
    for i in range(20):
        target.write_text(f"-- {i}\n", encoding="utf-8")
        a.tsm("flush", "--role", "upload")
        if filter_manifest(c.manifest(ws_a), m) != manifest(a.work, m):
            mismatches.append(i)
    assert mismatches == []  # flush garante igualdade também via SSH
    assert c.manifest(ws_b) == ws_b_before
    assert c.manifest(SshLayout.shared) == shared_before


def _raw_create(pc, alpha, beta_url, *extra) -> str:
    """Sessão Mutagen "crua", fora do Client (sem validações nem labels)."""
    adapter = pc.adapter
    res = adapter.runner(
        [str(adapter.executable), "sync", "create", "--no-global-configuration",
         "--mode=one-way-replica", "--name=crua", *extra, str(alpha), beta_url],
        timeout=SSH_TIMEOUT)
    return f"rc={res.returncode} {res.stderr.strip()[-300:]}"


def _raw_sessions(pc):
    return [s for s in pc.adapter.list_sessions(label_selector=None) if s.name == "crua"]


def test_shared_is_read_only_for_device_accounts(ssh_layout: SshLayout):
    c, a = ssh_layout.container, ssh_layout.a
    up_pc(a)  # o download funciona com o shared somente leitura
    assert manifest(a.cache) == c.manifest(SshLayout.shared)
    shared_before = c.manifest(SshLayout.shared)

    evil = ssh_layout.root / "evil"
    ssh_layout.extra_roots.append(evil)
    write(evil / "data" / "scripts" / "spells.lua", "-- sobrescrita indevida\n")
    outcome = _raw_create(a, evil, f"tsm-test-a:{SshLayout.shared}")
    print(f"\nS3 sessão crua com beta=shared: {outcome}")
    time.sleep(10)
    for s in _raw_sessions(a):
        print(f"shared somente leitura, estado: {s.raw_status} erro={s.last_error} problemas={len(s.problems)}")
        a.adapter.terminate([s.identifier])
    assert c.manifest(SshLayout.shared) == shared_before


def test_cross_access_denied_and_manager_reads_workspace(ssh_layout: SshLayout):
    c, a, b = ssh_layout.container, ssh_layout.a, ssh_layout.b
    up_pc(a)
    up_pc(b)
    ws_b_before = c.manifest(SshLayout.workspace("dev-b"))

    evil, plain = ssh_layout.root / "evil", ssh_layout.root / "plain"
    ssh_layout.extra_roots += [evil, plain]
    write(evil / "x.lua", "-- de A para B\n")
    outcome = _raw_create(a, evil, f"tsm-test-a:{SshLayout.workspace('dev-b')}")
    print(f"\nS4 dev-a -> workspace dev-b: {outcome}")
    time.sleep(10)
    for s in _raw_sessions(a):
        print(f"acesso cruzado, estado: {s.raw_status} erro={s.last_error}")
        a.adapter.terminate([s.identifier])
    assert c.manifest(SshLayout.workspace("dev-b")) == ws_b_before
    # dev-a não lista o diretório de workspaces (0711)
    assert c.sh(f"ls {REMOTE_PROJECT}/workspaces", user="tsm-dev-a", check=False).returncode != 0

    # positivo: com 0640/0750 + grupo, o Manager lê o workspace
    ws_a = SshLayout.workspace("dev-a")
    assert "spells" in c.sh(f"ls {ws_a}/data/scripts", user="tsm-manager").stdout
    assert c.read(f"{ws_a}/data/scripts/spells.lua", user="tsm-manager")
    modes = c.sh(f"stat -c '%a %U:%G %n' {ws_a}/data {ws_a}/data/scripts/spells.lua").stdout
    print(f"modos com flags: {' | '.join(modes.splitlines())}")

    # negativo: sem as flags de modo, o Manager não lê
    h9 = f"{REMOTE_PROJECT}/workspaces/dev-a-h9"
    write(plain / "d" / "f.lua", "return 1\n")
    _raw_create(a, plain, f"tsm-test-a:{h9}")
    ids = [s.identifier for s in _raw_sessions(a)]
    a.adapter.flush(ids)
    a.adapter.terminate(ids)
    modes = c.sh(f"stat -c '%a %U:%G %n' {h9}/d {h9}/d/f.lua").stdout
    print(f"modos padrão: {' | '.join(modes.splitlines())}")
    assert c.sh(f"cat {h9}/d/f.lua", user="tsm-manager", check=False).returncode != 0


def _wait_not_watching(pc, role="upload", timeout=120.0):
    return pc.wait_status(role, lambda s: s.status is not Status.WATCHING, timeout,
                          f"{pc.name}/{role} sair de watching")


def test_reconnection_after_network_loss_and_agent_kill(ssh_layout: SshLayout,
                                                           record_property):
    c, a = ssh_layout.container, ssh_layout.a
    up_pc(a)
    ws_a = SshLayout.workspace("dev-a")
    target = a.work / "data" / "scripts" / "spells.lua"

    # 1) queda de rede
    docker("network", "disconnect", "bridge", c.name)
    try:
        t0 = time.monotonic()
        lost = _wait_not_watching(a)
        detect = time.monotonic() - t0
        print(f"\nS5 rede caiu -> {lost.raw_status} (detectado em {detect:.1f}s)")
        target.write_text("-- editado offline (rede)\n", encoding="utf-8")
    finally:
        docker("network", "connect", "bridge", c.name)
    t0 = time.monotonic()
    a.wait_watching(timeout=SSH_TIMEOUT)
    net_recovery = time.monotonic() - t0
    a.tsm("flush", "--role", "upload")
    assert c.read(f"{ws_a}/data/scripts/spells.lua") == "-- editado offline (rede)\n"

    # 2) agentes mortos no servidor
    c.sh("pkill -KILL -u tsm-dev-a -f mutagen-agent || true")
    lost = _wait_not_watching(a)
    print(f"agente morto -> {lost.raw_status}")
    target.write_text("-- editado com agente morto\n", encoding="utf-8")
    t0 = time.monotonic()
    a.wait_watching(timeout=SSH_TIMEOUT)
    agent_recovery = time.monotonic() - t0
    a.tsm("flush", "--role", "upload")
    assert c.read(f"{ws_a}/data/scripts/spells.lua") == "-- editado com agente morto\n"

    print(f"recuperação: rede={net_recovery:.1f}s agente={agent_recovery:.1f}s")
    record_property("network_recovery_s", round(net_recovery, 1))
    record_property("agent_recovery_s", round(agent_recovery, 1))


def test_symlink_in_shared_is_not_materialized(ssh_layout: SshLayout):
    c, a = ssh_layout.container, ssh_layout.a
    c.sh(f"ln -s /etc/passwd {SshLayout.shared}/data/passwd-link && "
         f"chown -h tsm-manager:tsm-readers {SshLayout.shared}/data/passwd-link")
    up_pc(a)
    cache = manifest(a.cache, include_links=True)
    assert not any("passwd" in k for k in cache)
    assert not (a.cache / "data" / "passwd-link").exists()
    shared = {k: v for k, v in c.manifest(SshLayout.shared).items() if v != "link"}
    assert manifest(a.cache) == shared


def test_case_collision_and_reserved_names(ssh_layout: SshLayout):
    c, a = ssh_layout.container, ssh_layout.a
    shared = SshLayout.shared
    c.sh(f"cd {shared}/data/scripts && echo '-- maiuscula' > Spells.lua && "
         f"echo '-- reservado' > aux.lua && echo '-- ok' > ok.lua && "
         f"chown tsm-manager:tsm-readers Spells.lua aux.lua ok.lua && chmod 0640 *.lua")
    a.tsm("up")
    a.wait_status("download", lambda s: s.status is Status.WATCHING or s.status.halted,
                  SSH_TIMEOUT)
    code = a.tsm("flush", "--role", "download", expect=None)[0]
    s = a.sessions()["download"]
    problems = [(p.path, p.error[:160]) for p in s.problems]
    print(f"\nS7 flush rc={code} status={s.raw_status} conflitos={s.conflicts} "
          f"problemas={problems}")
    cache = manifest(a.cache)
    print(f"cache data/scripts: {sorted(k for k in cache if k.startswith('data/scripts'))}")
    assert s.status is Status.WATCHING
    assert problems or s.conflicts, "a colisão precisa ser reportada"
    remote = c.manifest(shared)
    assert cache.get("data/scripts/ok.lua") == remote["data/scripts/ok.lua"]
    assert cache.get("data/scripts/creatures.lua") == remote["data/scripts/creatures.lua"]
    _, out, _ = a.tsm("status")
    assert "problema" in out or "conflito" in out


def test_changed_host_key_is_refused(ssh_layout: SshLayout):
    c, a = ssh_layout.container, ssh_layout.a
    up_pc(a)
    ws_a = SshLayout.workspace("dev-a")
    known_before = (a.ssh_home / ".ssh" / "known_hosts").read_bytes()

    c.sh("rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null && pkill -HUP -x sshd; "
         "pkill -KILL -u tsm-dev-a || true")
    _wait_not_watching(a)
    ws_before = c.manifest(ws_a)
    (a.work / "data" / "scripts" / "spells.lua").write_text("-- não deve subir\n",
                                                            encoding="utf-8")
    time.sleep(20)
    s = a.sessions()["upload"]
    print(f"\nS8 sessão existente após troca: {s.raw_status} erro={s.last_error}")
    assert s.status is not Status.WATCHING
    assert c.manifest(ws_a) == ws_before

    a.tsm("teardown")
    code, _, err = a.tsm("up", expect=1)
    print(f"novo up: rc={code} {err.strip()[-300:]}")
    assert c.manifest(ws_a) == ws_before
    assert (a.ssh_home / ".ssh" / "known_hosts").read_bytes() == known_before


def test_collect_ssh_commands(ssh_layout: SshLayout, record_property, tmp_path_factory):
    c, a = ssh_layout.container, ssh_layout.a
    c.setup("clear-agents")
    c.setup("reset")
    up_pc(a)
    a.tsm("pause")
    a.tsm("resume")
    a.wait_watching(timeout=SSH_TIMEOUT)
    lines = c.audit_log()
    commands = sorted({ln.split("\t", 2)[2] for ln in lines if ln.count("\t") >= 2})
    out = tmp_path_factory.getbasetemp() / "s9-ssh-commands.txt"
    out.write_text("\n".join(commands) + "\n", encoding="utf-8")
    print("\nS9 comandos executados via SSH:\n  " + "\n  ".join(commands))
    record_property("ssh_commands", commands)
    assert any("synchronizer" in cmd for cmd in commands)
