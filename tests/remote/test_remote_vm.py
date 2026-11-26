"""Validação na VM ARM64 real (contas tsm-poc-*), via config SSH gerenciada."""

from __future__ import annotations

import threading
import time

import pytest

from tsm_client.adapters.mutagen import Status
from tsm_client.treehash import manifest

from .conftest import RemoteLayout

pytestmark = [pytest.mark.remote, pytest.mark.timeout(1200)]

TIMEOUT = 300.0


def write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def filt(m, matcher):
    return {k: v for k, v in m.items() if not matcher.is_ignored(k, v == "dir")}


def up_pc(pc) -> None:
    pc.tsm("up")
    pc.wait_watching(timeout=TIMEOUT)
    pc.tsm("flush")


def test_two_devices_four_sessions_real_arm64(remote_layout: RemoteLayout, record_property):
    lay = remote_layout
    a, b = lay.a, lay.b
    t0 = time.monotonic()
    for pc in (a, b):
        up_pc(pc)
    record_property("up_seconds", round(time.monotonic() - t0, 1))
    arch = lay.sh(a, "uname -m; ls .mutagen/agents/*/mutagen-agent").stdout
    print(f"\nV1 alvo: {' | '.join(arch.split())}")
    assert "aarch64" in arch and "mutagen-agent" in arch

    m = lay.matcher()
    for pc, dev in ((a, "dev-a"), (b, "dev-b")):
        assert {r: s.status for r, s in pc.sessions().items()} == {
            "upload": Status.WATCHING, "download": Status.WATCHING}
        assert filt(lay.manifest(pc, lay.workspace(dev)), m) == manifest(pc.work, m)
        assert manifest(pc.cache) == lay.manifest(pc, lay.shared)

    # subconjunto do teste SSH: edição, exclusão, ignores e loop de flush
    shared_before = lay.manifest(a, lay.shared)
    ws_b_before = lay.manifest(b, lay.workspace("dev-b"))
    for rel in (".env", "logs/a.log", "build/x", "data/x.tmp"):
        write(a.work / rel, "ignorado\n")
    (a.work / "data" / "scripts" / "creatures.lua").unlink()
    write(a.work / "data" / "novo.lua", "return 1\n")
    a.tsm("flush", "--role", "upload")
    remote = lay.manifest(a, lay.workspace("dev-a"))
    assert remote == filt(remote, m)
    assert filt(remote, m) == manifest(a.work, m)

    mismatches = []
    target = a.work / "data" / "scripts" / "spells.lua"
    for i in range(20):
        target.write_text(f"-- vm {i}\n", encoding="utf-8")
        a.tsm("flush", "--role", "upload")
        if filt(lay.manifest(a, lay.workspace("dev-a")), m) != manifest(a.work, m):
            mismatches.append(i)
    assert mismatches == []
    assert lay.manifest(b, lay.workspace("dev-b")) == ws_b_before
    assert lay.manifest(a, lay.shared) == shared_before


def _raw(pc, alpha, beta_url) -> list[str]:
    adapter = pc.adapter
    adapter.runner([str(adapter.executable), "sync", "create", "--no-global-configuration",
                    "--mode=one-way-replica", "--name=crua", str(alpha), beta_url], timeout=TIMEOUT)
    time.sleep(10)
    ids = [s.identifier for s in adapter.list_sessions(label_selector=None) if s.name == "crua"]
    for s in adapter.list_sessions(label_selector=None):
        if s.name == "crua":
            print(f"  crua -> {beta_url}: {s.raw_status} erro={s.last_error} "
                  f"problemas={len(s.problems)}")
    adapter.terminate(ids)
    return ids


def test_server_permissions_are_the_boundary(remote_layout: RemoteLayout):
    lay = remote_layout
    a, b = lay.a, lay.b
    up_pc(a)
    up_pc(b)
    shared_before = lay.manifest(a, lay.shared)
    ws_b_before = lay.manifest(b, lay.workspace("dev-b"))

    evil = lay.root / "evil"
    lay.extra_roots.append(evil)
    write(evil / "data" / "scripts" / "spells.lua", "-- indevido\n")
    print()
    _raw(a, evil, f"tsm-poc-a:{lay.shared}")
    _raw(a, evil, f"tsm-poc-a:{lay.workspace('dev-b')}")
    assert lay.manifest(a, lay.shared) == shared_before
    assert lay.manifest(b, lay.workspace("dev-b")) == ws_b_before
    assert lay.sh(a, f"ls {lay.target.root}/projects/demo/workspaces",
                  check=False).returncode != 0

    # na VM: modos 0640/0750 e o Manager no grupo do dispositivo
    ws_a = lay.workspace("dev-a")
    modes = lay.sh(a, f"stat -c '%a %G' {ws_a}/data {ws_a}/data/scripts/spells.lua").stdout
    print(f"modos: {' | '.join(modes.splitlines())}")
    assert modes.split()[0] == "750" and modes.split()[2] == "640"
    groups = lay.sh(a, "id -nG tsm-poc-manager").stdout.split()
    assert "tsm-poc-dev-a" in groups and "tsm-poc-dev-b" in groups


def test_reconnect_after_own_agents_are_killed(remote_layout: RemoteLayout, record_property):
    lay = remote_layout
    a = lay.a
    up_pc(a)
    # "[t]" impede que o padrão case com a linha de comando do próprio shell desta sessão
    lay.sh(a, "pkill -KILL -u tsm-poc-dev-a -f 'mutagen-agen[t] synchronizer' || true")
    lost = a.wait_status("upload", lambda s: s.status is not Status.WATCHING, 120,
                         "upload sair de watching")
    print(f"\nV3 agente morto -> {lost.raw_status}")
    (a.work / "data" / "scripts" / "spells.lua").write_text("-- offline na VM\n",
                                                            encoding="utf-8")
    t0 = time.monotonic()
    a.wait_watching(timeout=TIMEOUT)
    recovery = time.monotonic() - t0
    a.tsm("flush", "--role", "upload")
    content = lay.sh(a, f"cat {lay.workspace('dev-a')}/data/scripts/spells.lua").stdout
    assert content == "-- offline na VM\n"
    print(f"recuperação: {recovery:.1f}s")
    record_property("recovery_s", round(recovery, 1))


def _ps(lay, pc) -> list[str]:
    """Agentes ``mutagen-agent synchronizer`` (sem o ``sh -c`` que os inicia).

    Filtra pelos argumentos, não pelo nome do processo: sob emulação QEMU (ensaio no
    contêiner) o nome é ``qemu-aarch64``.
    """
    out = lay.sh(pc, "ps -eo user=,pcpu=,rss=,etime=,args=", check=False).stdout
    rows = []
    for ln in out.splitlines():
        if "mutagen-agent synchronizer" in ln and " sh -c " not in f" {ln} ":
            rows.append(" ".join(ln.split()[:4]))
    return rows


def test_agent_resource_usage(remote_layout: RemoteLayout, record_property):
    lay = remote_layout
    a, b = lay.a, lay.b
    for pc in (a, b):
        up_pc(pc)
    time.sleep(15)
    idle = _ps(lay, a)
    print(f"\nV4 repouso (usuário %cpu rss_kB etime): {idle}")

    for i in range(300):
        write(a.work / "data" / "carga" / f"f{i:03}.lua", f"return {i}\n" * 50)
    samples: list[list[str]] = []
    done = threading.Event()

    def sample() -> None:
        while not done.is_set():
            samples.append(_ps(lay, b))
            time.sleep(1)

    th = threading.Thread(target=sample, daemon=True)
    th.start()
    t0 = time.monotonic()
    try:
        a.tsm("flush", "--role", "upload")
    finally:
        done.set()
        th.join(timeout=30)
    elapsed = time.monotonic() - t0

    def peak(rows: list[list[str]]) -> tuple[float, int]:
        cpu = max((float(r.split()[1]) for s in rows for r in s), default=0.0)
        rss = max((int(r.split()[2]) for s in rows for r in s), default=0)
        return cpu, rss

    cpu, rss = peak([*samples, idle])
    print(f"carga: 300 arquivos em {elapsed:.1f}s; pico %cpu={cpu} rss={rss} kB; "
          f"amostras={len(samples)}")
    record_property("idle", idle)
    record_property("peak_cpu", cpu)
    record_property("peak_rss_kb", rss)
    assert len(idle) >= 4  # 4 sessões -> 4 agentes (2 por conta)
