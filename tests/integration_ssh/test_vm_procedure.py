"""Ensaio do procedimento da VM (deploy/poc-ssh) num contêiner linux/arm64.

Não substitui a execução na VM real: valida que o script gerado
provisiona, que os testes de validação passam contra ele e que o rollback remove tudo.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import uuid

import pytest

from tests.conftest import REPO_ROOT

from .conftest import IMAGE, PLATFORM, docker, wait_until

pytestmark = [pytest.mark.ssh, pytest.mark.timeout(3600)]

UBUNTU_LIKE_SSHD = """Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM no
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
"""


def _load_prepare():
    path = REPO_ROOT / "scripts" / "poc_remote_prepare.py"
    spec = importlib.util.spec_from_file_location("poc_remote_prepare", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def vm_like(sshd):  # depende de sshd só para garantir a imagem construída
    name = f"tsm-vmlike-{uuid.uuid4().hex[:8]}"
    docker("run", "-d", "--platform", PLATFORM, "--name", name, "-p", "127.0.0.1::22", IMAGE)
    try:
        docker("exec", "-i", name, "sh", "-c", "cat > /etc/ssh/sshd_config && mkdir -p "
               "/etc/ssh/sshd_config.d && pkill -HUP -x sshd", input=UBUNTU_LIKE_SSHD)
        wait_until(lambda: docker("exec", name, "pgrep", "-x", "sshd", check=False).returncode == 0,
                   60, 0.5, "sshd")
        port = int(docker("port", name, "22/tcp").stdout.strip().splitlines()[0].rsplit(":", 1)[1])
        keys = docker("exec", name, "sh", "-c", "cat /etc/ssh/ssh_host_*_key.pub").stdout
        yield name, port, keys
    finally:
        docker("rm", "-f", name, check=False)


def _run_script(name: str, script: str) -> subprocess.CompletedProcess[str]:
    return docker("exec", "-i", name, "sh", "-s", input=script, check=False, timeout=300)


def test_vm_procedure_provision_remote_tests_and_rollback(vm_like, tmp_path, record_property):
    name, port, host_keys = vm_like
    prepare = _load_prepare()
    keys_dir = tmp_path / "remote-keys"
    pubs = prepare.ensure_keys(keys_dir, prepare.DEFAULT_SSH_DIR)
    script = prepare.render(pubs)
    assert "BEGIN OPENSSH PRIVATE KEY" not in script  # só chaves públicas no script

    first = _run_script(name, script)
    assert first.returncode == 0, first.stderr
    print(f"\nprovision: {first.stdout.strip()}")
    again = _run_script(name, script)
    assert again.returncode != 0 and "rollback" in again.stderr  # não reaplica por cima

    known = tmp_path / "known_hosts"
    known.write_text("".join(f"[127.0.0.1]:{port} {' '.join(k.split()[:2])}\n"
                             for k in host_keys.splitlines() if k.strip()), encoding="utf-8")
    env = {**os.environ, "TSM_REMOTE_ROOT": "/srv/ts-poc", "TSM_REMOTE_KEYS": str(keys_dir),
           "TSM_REMOTE_HOSTNAME": "127.0.0.1", "TSM_REMOTE_PORT": str(port),
           "TSM_REMOTE_KNOWN_HOSTS": str(known)}
    env.pop("TSM_REMOTE_ALIAS", None)
    run = subprocess.run([sys.executable, "-m", "pytest", "-m", "remote", "tests/remote", "-rs",
                          "-q", "-s", "-p", "no:cacheprovider"],
                         cwd=REPO_ROOT, env=env, capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=3000)
    tail = "\n".join(run.stdout.splitlines()[-40:])
    print(tail)
    assert run.returncode == 0, tail
    assert "skipped" not in run.stdout.splitlines()[-1]

    rb = REPO_ROOT / "deploy" / "poc-ssh" / "rollback.sh"
    for _ in range(2):  # idempotente
        out = _run_script(name, rb.read_text(encoding="utf-8"))
        assert out.returncode == 0, out.stderr
    leftovers = docker("exec", name, "sh", "-c",
                       "getent passwd | grep -c tsm-poc; getent group | grep -c tsm-poc; "
                       "ls /srv/ts-poc 2>&1 | head -1; grep -c tsm-poc /etc/ssh/sshd_config; "
                       "sshd -t && echo sshd-ok", check=False).stdout.split("\n")
    print(f"pós-rollback: {leftovers}")
    assert leftovers[0] == "0" and leftovers[1] == "0"
    assert "No such file" in leftovers[2]
    assert leftovers[3] == "0" and "sshd-ok" in leftovers[4]
