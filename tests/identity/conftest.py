"""Integração do ``tsm`` com identidade real: Manager ``version: 2`` como processo.

``ssh-keygen`` (geração, assinatura e verificação), ``icacls``, SQLite, Git, HTTP e Mutagen
reais; ``LocalProvisioner`` (``transport: local``). Cada "PC" tem o próprio ``<home>`` e sai
do próprio endereço de loopback (``127.0.0.N``): em loopback o rate limit do Manager conta
por endereço, e os dispositivos de teste não devem dividir as fichas.
"""

from __future__ import annotations

import functools
import hashlib
import http.client
import io
import json
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.manager.conftest import DEMO
from tests.manager.server import Server
from tsm_client.adapters.manager import UrllibTransport
from tsm_client.cli import run
from tsm_client.enroll import Toolkit


class SourceTransport(UrllibTransport):
    """O transporte do Client, saindo de um endereço de loopback fixo."""

    def __init__(self, source: str) -> None:
        super().__init__()

        class Handler(urllib.request.HTTPHandler):
            handler_order = 400  # antes do HTTPHandler padrão (500)

            def http_open(self, req):
                return self.do_open(functools.partial(http.client.HTTPConnection,
                                                      source_address=(source, 0)), req)

        self._opener.add_handler(Handler())


class Pc:
    def __init__(self, root: Path, n: int, srv: Server) -> None:
        self.root = root
        self.home = root / "home"
        self.n = n
        self.srv = srv
        self.transport = SourceTransport(f"127.0.0.{20 + n}")

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.srv.port}"

    @property
    def work(self) -> Path:
        return self.root / "work"

    def tsm(self, *args: str, expect: int | None = 0) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = run(["--home", str(self.home), *args], toolkit=Toolkit(transport=self.transport),
                   out=out, err=err)
        if expect is not None:
            assert code == expect, (f"tsm {' '.join(args)} -> {code}\n{out.getvalue()}"
                                    f"{err.getvalue()}")
        return code, out.getvalue(), err.getvalue()

    def json(self, *args: str) -> Any:
        return json.loads(self.tsm(*args, "--json")[1])


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    if not root.exists():
        return "ausente"
    for p in sorted(root.rglob("*")):
        h.update(p.relative_to(root).as_posix().encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


@pytest.fixture(scope="session", autouse=True)
def personal_ssh_untouched() -> Iterator[None]:
    """O ~/.ssh pessoal fica idêntico durante toda a suíte."""
    personal = Path.home() / ".ssh"
    before = tree_hash(personal)
    yield
    assert tree_hash(personal) == before, "o ~/.ssh pessoal foi alterado"


@pytest.fixture(scope="module")
def srv(tmp_path_factory) -> Iterator[Server]:
    s = Server(tmp_path_factory.mktemp("tsm-identity"))
    s.cli("migrate")
    s.cli("init-project", "--project", "demo", "--from", str(DEMO))
    s.start()
    try:
        yield s
    finally:
        s.stop()
