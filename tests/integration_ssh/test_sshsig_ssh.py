"""Verificador SSHSIG com o ``ssh-keygen`` do Ubuntu 24.04 (OpenSSH 9.6) no contêiner.

O Manager roda como ``tsm-manager`` dentro da imagem de teste (reconstruída com o código
atual: ``TSM_REBUILD_MANAGER_IMAGE=1``). As assinaturas vêm do OpenSSH do Git for Windows,
no host: vetores gravados e assinaturas novas feitas durante o teste. Os temporários do
verificador ficam em ``/srv/ts/manager/tmp/sshsig``.
"""

from __future__ import annotations

import json

import pytest

from tests.conftest import FIXTURES, REPO_ROOT
from tests.integration_ssh.conftest import VENV, MgrContainer, docker
from tests.sshsig_signer import SigningDevice, generate_key, keygen_path, sign
from tsm_common import protocol as P

pytestmark = [pytest.mark.ssh, pytest.mark.timeout(1800)]

VECTORS = json.loads((FIXTURES / "sshsig" / "vectors.json").read_text("utf-8"))
DRIVER = REPO_ROOT / "tests" / "integration_ssh" / "sshsig_driver.py"
REMOTE_DRIVER = "/opt/tsm-test/sshsig_driver.py"
DATABASE = "/srv/ts/manager/manager.db"
KEYGEN = keygen_path()


class Driver:
    def __init__(self, c: MgrContainer) -> None:
        self.c = c

    def __call__(self, op: str, **fields) -> dict:
        out = self.c.sh(f"{VENV}/python {REMOTE_DRIVER} {DATABASE}", user="tsm-manager",
                        input=json.dumps({"op": op, **fields}), timeout=120).stdout
        return json.loads(out)


@pytest.fixture
def driver(mgr_container: MgrContainer) -> Driver:
    c = mgr_container
    c.sh("rm -rf /srv/ts/manager && install -d -o tsm-manager -g tsm-manager -m 0700 "
         "/srv/ts/manager && install -d -m 0755 /opt/tsm-test")
    docker("cp", str(DRIVER), f"{c.name}:{REMOTE_DRIVER}")
    c.sh(f"chmod 0644 {REMOTE_DRIVER}")
    return Driver(c)


def test_container_openssh_version(mgr_container):
    out = mgr_container.sh("ssh -V 2>&1; command -v ssh-keygen").stdout
    assert out.startswith("OpenSSH_9.6p1 Ubuntu")
    assert out.splitlines()[-1] == "/usr/bin/ssh-keygen"


def test_recorded_windows_vectors_on_ubuntu(driver):
    driver("setup")
    results = driver("verify", cases=VECTORS["cases"])["results"]
    assert dict(zip([c["name"] for c in VECTORS["cases"]], results, strict=True)) == {
        c["name"]: c["valid"] for c in VECTORS["cases"]}
    assert driver("work_dir") == {"entries": [], "mode": "0o700"}


def test_fresh_windows_signature_on_ubuntu(tmp_path, driver):
    driver("setup")
    private, public = generate_key(KEYGEN, tmp_path / "client" / ".ssh", "device")
    message = "tsm-auth-v1\nassinada agora no Windows\n"
    signature = sign(KEYGEN, private, message.encode("ascii"), home=tmp_path / "client")
    cases = [{"public_key": public, "message_text": message, "signature": signature},
             {"public_key": public, "message_text": message + "x", "signature": signature}]
    assert driver("verify", cases=cases)["results"] == [True, False]


def test_self_check_on_ubuntu(driver):
    driver("setup")
    assert driver("self_check") == {"ok": True}


def test_domain_flow_with_windows_signatures(tmp_path, driver):
    setup = driver("setup")
    device = SigningDevice(KEYGEN, tmp_path / "client" / "ssh")

    reg = driver("register_challenge", public_key=device.public)
    assert reg["server_id"] == setup["server_id"]
    registration = driver("register", invite=setup["invite"],
                          challenge_id=reg["challenge_id"], signature=device.answer(reg))
    assert (registration["status"], registration["fingerprint"]) == (
        "pending", device.fingerprint)

    pending = driver("login_challenge", fingerprint=device.fingerprint)
    assert driver("login", challenge_id=pending["challenge_id"],
                  signature=device.answer(pending))["scope"] == "pending"

    driver("approve", device_id=registration["device_id"], fingerprint=device.fingerprint)
    login = driver("login_challenge", fingerprint=device.fingerprint)
    signature = device.answer(login)
    assert driver("login", challenge_id=login["challenge_id"], signature=signature) == {
        "scope": "full", "is_admin": True, "device_id": registration["device_id"]}

    replay = driver("login", challenge_id=login["challenge_id"], signature=signature)
    assert replay == {"error": P.UNAUTHORIZED}
    other = driver("login_challenge", fingerprint=device.fingerprint)
    as_register = device.sign(device.message(other, purpose="register"))
    assert driver("login", challenge_id=other["challenge_id"], signature=as_register) == {
        "error": "unauthorized"}

    assert driver("work_dir") == {"entries": [], "mode": "0o700"}

