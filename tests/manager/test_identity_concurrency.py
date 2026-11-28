"""Publicações e autenticações simultâneas no Manager real (SQLite em WAL).

``tsm-manager serve`` como processo; 8 dispositivos aprovados pela semente, cada um com a
própria chave e o próprio endereço de loopback. Depois de uma barreira, cada thread faz um
login, publica um arquivo próprio pelo HTTP e faz mais 3 logins com ``GET /me`` entre eles
(cada requisição autenticada também grava o último acesso do dispositivo). Nenhuma
requisição pode falhar nem o log do ``serve`` pode mostrar ``database is locked``.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from pathlib import Path

import pytest

from tests.identity_seed import Seed
from tests.manager.identity_http import Device, Http
from tests.manager.server import Server
from tsm_common.rules import ProjectRules, rules_digest
from tsm_manager.config import load_manager_config
from tsm_manager.services import Manager

pytestmark = pytest.mark.integration

DEVICES = 8
EXTRA_LOGINS = 3


@pytest.fixture
def env(tmp_path):
    srv = Server(tmp_path, projects=("demo",))
    srv.cli("migrate")
    srv.init_project("demo")
    srv.start()
    operator = Manager(load_manager_config(srv.cfg))
    try:
        yield srv, Seed(operator.identity, tmp_path / "keys")
    finally:
        srv.stop()
        operator.close()


def test_concurrent_publications_and_logins(env):
    srv, seed = env
    devices: list[tuple[Device, dict]] = []
    for i in range(DEVICES):
        sd = seed.device(f"dev{i}")
        dev = Device(Http(srv.port, f"127.0.0.{40 + i}"), sd.signer, sd.name,
                     device_id=sd.device_id)
        assert dev.login().status == 200
        conn = dev.get("/connection/config?project=demo").body
        devices.append((dev, conn))
    head = devices[0][0].get("/projects/demo").body["head"]["commit"]

    bodies = []
    for i, (_, conn) in enumerate(devices):
        rel = f"data/conc/dev{i}.lua"
        data = f"-- dev {i}\nvalor = {i}\n".encode()
        target = Path(conn["paths"]["workspace"]) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        bodies.append({"idempotency_key": str(uuid.uuid4()), "base": {"commit": head},
                       "rules_digest": rules_digest(ProjectRules()),
                       "changes": [{"path": rel, "op": "put", "size": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest()}]})

    barrier = threading.Barrier(DEVICES)
    results: list[dict] = [{} for _ in devices]

    def work(i: int) -> None:
        dev, conn = devices[i]
        res = results[i]
        try:
            barrier.wait(60)

            def timed_login() -> None:
                t0 = time.perf_counter()
                res.setdefault("logins", []).append(dev.login().status)
                res.setdefault("latency", []).append(time.perf_counter() - t0)

            timed_login()
            pub = dev.post(f"/projects/demo/bindings/{conn['binding_id']}/publish", bodies[i])
            res["publish"] = (pub.status, (pub.body or {}).get("status"))
            for _ in range(EXTRA_LOGINS):
                res.setdefault("me", []).append(dev.get("/me").status)
                timed_login()
        except Exception as exc:
            res["error"] = repr(exc)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(DEVICES)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join(300)
    total = time.perf_counter() - t0

    assert not [r["error"] for r in results if "error" in r], results
    assert [r["publish"] for r in results] == [(200, "published")] * DEVICES, results
    assert all(r["logins"] == [200] * (1 + EXTRA_LOGINS) for r in results), results
    assert all(r["me"] == [200] * EXTRA_LOGINS for r in results), results

    revs = devices[0][0].get("/projects/demo/revisions?limit=50").body["revisions"]
    assert sorted(r["revision"] for r in revs) == list(range(1, DEVICES + 2))
    log = srv.log.read_text("utf-8", "replace")
    assert "database is locked" not in log and "Traceback" not in log, log[-4000:]
    assert "verify: ok" in srv.cli("verify").stdout
    slowest = max(x for r in results for x in r["latency"])
    print(f"\nconcorrência: {DEVICES} publicações e {DEVICES * (1 + EXTRA_LOGINS)} logins "
          f"em {total:.2f} s; login mais lento {slowest:.2f} s")
