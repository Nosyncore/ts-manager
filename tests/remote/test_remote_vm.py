"""Validação na VM ARM64 real (contas tsm-poc-*), via config SSH gerenciada."""

from __future__ import annotations

import time
from dataclasses import dataclass

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


@dataclass(frozen=True)
class AgentStat:
    cpu_s: float  # utime + stime acumulados
    rss_kb: int   # VmRSS
    hwm_kb: int   # VmHWM: pico de RSS registrado pelo kernel


# Lê /proc dos agentes da própria conta. O padrão "[t]" impede que o pgrep case com a linha
# de comando deste script.
_AGENTS_SCRIPT = r"""
echo "tck $(getconf CLK_TCK)"
for p in $(pgrep -u "$(id -u)" -f 'mutagen-agen[t] synchronizer'); do
  s=$(sed 's/^.*) //' "/proc/$p/stat" 2>/dev/null) || continue
  set -- $s
  rss=$(awk '/^VmRSS:/{print $2}' "/proc/$p/status" 2>/dev/null)
  hwm=$(awk '/^VmHWM:/{print $2}' "/proc/$p/status" 2>/dev/null)
  cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
  printf 'p\t%s\t%s\t%s\t%s\t%s\n' "$p" "$((${12} + ${13}))" "${rss:-0}" "${hwm:-0}" "$cmd"
done
"""


def _agents(lay, pc) -> dict[tuple[str, int], AgentStat]:
    """Agentes ``mutagen-agent synchronizer`` da conta do PC (sem o ``sh -c`` que os inicia).

    Filtra pelos argumentos, não pelo nome do processo: sob emulação QEMU (ensaio no
    contêiner) o nome é ``qemu-aarch64``. CPU em segundos a partir de ``/proc/<pid>/stat``:
    ``ps pcpu`` é a média desde o início do processo e não mede uma janela.
    """
    tck = 100
    out: dict[tuple[str, int], AgentStat] = {}
    for ln in lay.sh(pc, _AGENTS_SCRIPT).stdout.splitlines():
        if ln.startswith("tck "):
            tck = int(ln.split()[1])
            continue
        if not ln.startswith("p\t"):
            continue
        _, pid, ticks, rss, hwm, cmd = ln.split("\t", 5)
        if " sh -c " in f" {cmd} ":
            continue
        out[(pc.name, int(pid))] = AgentStat(int(ticks) / tck, int(rss), int(hwm))
    return out


def _snapshot(lay) -> dict[tuple[str, int], AgentStat]:
    return {**_agents(lay, lay.a), **_agents(lay, lay.b)}


def _cpu_delta(before, after) -> float:
    assert before.keys() == after.keys(), "agentes reiniciaram durante a medição"
    return sum(after[k].cpu_s - before[k].cpu_s for k in before)


IDLE_WINDOW_S = 30.0
LOAD_FILES = 300


def test_agent_resource_usage(remote_layout: RemoteLayout, record_property):
    lay = remote_layout
    a, b = lay.a, lay.b
    for pc in (a, b):
        up_pc(pc)
    time.sleep(15)

    # repouso: CPU consumida numa janela fixa, 4 sessões em watching
    s0, t0 = _snapshot(lay), time.monotonic()
    assert len(s0) == 4, s0  # 4 sessões -> 4 agentes (2 por conta)
    time.sleep(IDLE_WINDOW_S)
    s1, t1 = _snapshot(lay), time.monotonic()
    idle_cpu = _cpu_delta(s0, s1)
    idle_pct = 100 * idle_cpu / (t1 - t0)
    idle_rss = sorted(v.rss_kb for v in s1.values())
    print(f"\nV4 repouso ({t1 - t0:.0f}s): CPU agentes={idle_cpu:.2f}s "
          f"({idle_pct:.2f}% de 1 vCPU); "
          f"RSS kB={idle_rss} (total {sum(idle_rss) / 1024:.1f} MB)")

    # carga: escrita + flush do upload; CPU por diferença e pico de RSS pelo VmHWM
    t2 = time.monotonic()
    for i in range(LOAD_FILES):
        write(a.work / "data" / "carga" / f"f{i:03}.lua", f"return {i}\n" * 50)
    a.tsm("flush", "--role", "upload")
    s2, t3 = _snapshot(lay), time.monotonic()
    load_cpu = _cpu_delta(s1, s2)
    load_pct = 100 * load_cpu / (t3 - t2)
    hwm = sorted(v.hwm_kb for v in s2.values())
    print(f"carga: {LOAD_FILES} arquivos em {t3 - t2:.1f}s; CPU agentes={load_cpu:.2f}s "
          f"({load_pct:.1f}% de 1 vCPU em média); pico RSS (VmHWM) kB={hwm}")

    record_property("idle_window_s", round(t1 - t0, 1))
    record_property("idle_cpu_s", round(idle_cpu, 2))
    record_property("idle_cpu_pct_1vcpu", round(idle_pct, 2))
    record_property("idle_rss_kb", idle_rss)
    record_property("load_elapsed_s", round(t3 - t2, 1))
    record_property("load_cpu_s", round(load_cpu, 2))
    record_property("load_cpu_pct_1vcpu", round(load_pct, 1))
    record_property("peak_rss_kb", hwm)
