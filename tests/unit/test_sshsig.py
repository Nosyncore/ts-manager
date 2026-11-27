"""Verificador SSHSIG sobre ``ssh-keygen -Y verify``, com executor falso (sem processo real)."""

from __future__ import annotations

import base64
import json
import logging
import os
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tsm_common.authmsg import NAMESPACE, AuthMessage, parse_expires
from tsm_common.sshkeys import parse_public_key
from tsm_manager.adapters import sshsig
from tsm_manager.adapters.sshsig import (
    Completed,
    SshKeygenVerifier,
    SshsigUnavailable,
    default_executable,
    normalize_signature,
    work_dir_for,
)

FIXTURES = REPO_ROOT / "tests" / "fixtures"
VECTORS = json.loads((FIXTURES / "sshsig" / "vectors.json").read_text("utf-8"))
CASES = {case["name"]: case for case in VECTORS["cases"]}
VALID = CASES["valid_login"]
KEY = VALID["public_key"]
FINGERPRINT = parse_public_key(KEY).fingerprint
MESSAGE = VALID["message_text"].encode("ascii")
SIGNATURE = VALID["signature"]
OTHER_KEY_LINE = VECTORS["keys"]["b"]


def good_line(fingerprint: str = FINGERPRINT) -> bytes:
    return (f'Good "ts-manager-auth" signature for tsm-device with ED25519 key '
            f"{fingerprint}\n").encode("ascii")


@dataclass
class Call:
    argv: list[str]
    stdin: bytes
    env: dict[str, str]
    cwd: Path
    timeout: float
    files: dict[str, bytes]


class FakeRunner:
    """Registra cada chamada (com os arquivos do diretório) e devolve o resultado pedido."""

    def __init__(self, result: Completed | None = None, *, exc: BaseException | None = None,
                 respond=None) -> None:
        self.result = result or Completed(0, good_line())
        self.exc = exc
        self.respond = respond
        self.calls: list[Call] = []

    def __call__(self, argv, stdin, env, cwd, timeout) -> Completed:
        cwd = Path(cwd)
        files = {p.name: p.read_bytes() for p in cwd.iterdir()}
        call = Call(list(argv), stdin, dict(env), cwd, timeout, files)
        self.calls.append(call)
        if self.exc is not None:
            raise self.exc
        if self.respond is not None:
            return self.respond(call)
        return self.result


@pytest.fixture
def exe(tmp_path) -> Path:
    return tmp_path / "bin" / "ssh-keygen"


@pytest.fixture
def work_dir(tmp_path) -> Path:
    return tmp_path / "root" / "manager" / "tmp" / "sshsig"


def make(exe: Path, work_dir: Path, runner: FakeRunner, **kw) -> SshKeygenVerifier:
    kw.setdefault("windows", False)
    return SshKeygenVerifier(exe, work_dir, runner=runner, **kw)


def leftovers(work_dir: Path) -> list[str]:
    return sorted(p.name for p in work_dir.iterdir()) if work_dir.exists() else []


# ------------------------------------------------------------------ execução


def test_valid_signature_runs_fixed_argv_with_message_on_stdin(exe, work_dir):
    runner = FakeRunner()
    assert make(exe, work_dir, runner).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE) is True
    [call] = runner.calls
    assert call.argv == [str(exe), "-Y", "verify", "-f", str(call.cwd / "allowed_signers"),
                         "-I", "tsm-device", "-n", "ts-manager-auth",
                         "-s", str(call.cwd / "signature")]
    assert call.stdin == MESSAGE
    assert call.timeout == 5.0


def test_allowed_signers_has_one_line_with_normalized_key_and_namespace(exe, work_dir):
    runner = FakeRunner()
    make(exe, work_dir, runner).verify(KEY + "  ", NAMESPACE, MESSAGE, SIGNATURE)
    [call] = runner.calls
    normalized = parse_public_key(KEY).openssh
    assert "dev-a" not in call.files["allowed_signers"].decode()
    assert call.files["allowed_signers"] == (
        f'tsm-device namespaces="ts-manager-auth" {normalized}\n'.encode("ascii"))
    assert call.files["signature"] == SIGNATURE.encode("ascii")
    assert set(call.files) == {"allowed_signers", "signature"}


def test_signature_with_crlf_and_without_final_newline_is_normalized(exe, work_dir):
    runner = FakeRunner()
    verifier = make(exe, work_dir, runner)
    assert verifier.verify(KEY, NAMESPACE, MESSAGE, SIGNATURE.replace("\n", "\r\n"))
    assert verifier.verify(KEY, NAMESPACE, MESSAGE, SIGNATURE.rstrip("\n"))
    assert [c.files["signature"] for c in runner.calls] == [SIGNATURE.encode("ascii")] * 2


def test_environment_is_built_from_scratch(exe, work_dir, monkeypatch):
    monkeypatch.setenv("TSM_SENTINEL", "não deve vazar")
    runner = FakeRunner()
    make(exe, work_dir, runner).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE)
    [call] = runner.calls
    here = str(call.cwd)
    assert call.env == {"LC_ALL": "C", "LANG": "C", "PATH": str(exe.parent), "HOME": here,
                        "TMP": here, "TEMP": here, "TMPDIR": here}


def test_environment_on_windows_adds_only_systemroot(exe, work_dir, monkeypatch):
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    runner = FakeRunner()
    make(exe, work_dir, runner, windows=True).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE)
    [call] = runner.calls
    here = str(call.cwd)
    assert call.env == {"LC_ALL": "C", "LANG": "C", "PATH": str(exe.parent), "HOME": here,
                        "TMP": here, "TEMP": here, "TMPDIR": here,
                        "SYSTEMROOT": r"C:\Windows"}


def test_timeout_is_configurable(exe, work_dir):
    runner = FakeRunner()
    make(exe, work_dir, runner, timeout_s=1.5).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE)
    assert runner.calls[0].timeout == 1.5


def test_call_directory_lives_under_work_dir_and_is_removed(exe, work_dir):
    runner = FakeRunner()
    verifier = make(exe, work_dir, runner)
    verifier.verify(KEY, NAMESPACE, MESSAGE, SIGNATURE)
    verifier.verify(KEY, NAMESPACE, MESSAGE, SIGNATURE)
    first, second = (c.cwd for c in runner.calls)
    assert first.parent == work_dir and second.parent == work_dir
    assert first.name.startswith("v-") and first != second
    assert leftovers(work_dir) == []


@pytest.mark.skipif(os.name == "nt", reason="modos POSIX")
def test_work_dir_and_files_are_private(exe, work_dir):
    seen = {}

    def respond(call: Call) -> Completed:
        seen["dir"] = call.cwd.stat().st_mode & 0o777
        seen["files"] = {(call.cwd / n).stat().st_mode & 0o777 for n in call.files}
        return Completed(0, good_line())

    make(exe, work_dir, FakeRunner(respond=respond)).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE)
    assert seen == {"dir": 0o700, "files": {0o600}}
    assert work_dir.stat().st_mode & 0o777 == 0o700


# ------------------------------------------------------------------ resultados e falhas


def test_rejected_signature_is_false_without_failure_log(exe, work_dir, caplog):
    caplog.set_level(logging.DEBUG, logger="tsm_manager.sshsig")
    runner = FakeRunner(Completed(255, b""))
    assert make(exe, work_dir, runner).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE) is False
    assert caplog.records == []
    assert leftovers(work_dir) == []


@pytest.mark.parametrize(("result", "category"), [
    (Completed(0, good_line("SHA256:" + "A" * 43)), "unexpected_output"),
    (Completed(0, b""), "unexpected_output"),
    (Completed(0, good_line() + b"mais uma linha\n"), "unexpected_output"),
    (Completed(0, b"\xff\xfe"), "unexpected_output"),
    (Completed(1, good_line()), "unexpected_exit"),
    (Completed(-9, b""), "unexpected_exit"),
])
def test_unexpected_results_are_false_and_logged(exe, work_dir, caplog, result, category):
    caplog.set_level(logging.DEBUG, logger="tsm_manager.sshsig")
    runner = FakeRunner(result)
    assert make(exe, work_dir, runner).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE) is False
    assert [r.getMessage() for r in caplog.records] == [
        f"falha ao verificar assinatura SSHSIG: {category}"]
    assert leftovers(work_dir) == []


def test_good_line_with_crlf_is_accepted(exe, work_dir):
    runner = FakeRunner(Completed(0, good_line().replace(b"\n", b"\r\n")))
    assert make(exe, work_dir, runner).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE) is True


@pytest.mark.parametrize(("exc", "category"), [
    (subprocess.TimeoutExpired(["ssh-keygen"], 5.0), "timeout"),
    (FileNotFoundError(2, "No such file", "ssh-keygen"), "unavailable"),
    (PermissionError(13, "denied"), "unavailable"),
    (subprocess.SubprocessError("quebrou"), "unavailable"),
])
def test_process_failures_are_false_and_log_only_the_category(exe, work_dir, caplog, exc,
                                                              category):
    caplog.set_level(logging.DEBUG, logger="tsm_manager.sshsig")
    runner = FakeRunner(exc=exc)
    assert make(exe, work_dir, runner).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE) is False
    assert [r.getMessage() for r in caplog.records] == [
        f"falha ao verificar assinatura SSHSIG: {category}"]
    text = caplog.text
    for secret in (KEY.split()[1], SIGNATURE.splitlines()[1], "tsm-auth-v1", str(work_dir),
                   str(exe), "No such file", "quebrou"):
        assert secret not in text
    assert leftovers(work_dir) == []


def test_work_dir_that_cannot_be_created_is_a_failure(tmp_path, exe, caplog):
    caplog.set_level(logging.DEBUG, logger="tsm_manager.sshsig")
    blocker = tmp_path / "arquivo"
    blocker.write_text("não é diretório")
    runner = FakeRunner()
    verifier = make(exe, blocker / "sshsig", runner)
    assert verifier.verify(KEY, NAMESPACE, MESSAGE, SIGNATURE) is False
    assert runner.calls == []
    assert [r.getMessage() for r in caplog.records] == [
        "falha ao verificar assinatura SSHSIG: workdir"]


def test_write_failure_is_a_workdir_failure_and_cleans_up(exe, work_dir, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger="tsm_manager.sshsig")

    def broken(path, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(sshsig, "_write_new", broken)
    runner = FakeRunner()
    assert make(exe, work_dir, runner).verify(KEY, NAMESPACE, MESSAGE, SIGNATURE) is False
    assert runner.calls == []
    assert [r.getMessage() for r in caplog.records] == [
        "falha ao verificar assinatura SSHSIG: workdir"]
    assert leftovers(work_dir) == []


def test_concurrency_is_limited_and_excess_is_busy(exe, work_dir, caplog):
    caplog.set_level(logging.DEBUG, logger="tsm_manager.sshsig")
    entered, release = threading.Event(), threading.Event()

    def respond(call: Call) -> Completed:
        entered.set()
        release.wait(5)
        return Completed(0, good_line())

    verifier = make(exe, work_dir, FakeRunner(respond=respond), max_concurrent=1,
                    timeout_s=0.05)
    results: list[bool] = []
    worker = threading.Thread(
        target=lambda: results.append(verifier.verify(KEY, NAMESPACE, MESSAGE, SIGNATURE)))
    worker.start()
    try:
        assert entered.wait(5)
        assert verifier.verify(KEY, NAMESPACE, MESSAGE, SIGNATURE) is False
    finally:
        release.set()
        worker.join(5)
    assert results == [True]
    assert [r.getMessage() for r in caplog.records] == [
        "falha ao verificar assinatura SSHSIG: busy"]


# ------------------------------------------------------------------ validação antes do processo


def _wrap(text: str) -> str:
    lines = [text[i:i + 70] for i in range(0, len(text), 70)]
    return "\n".join(["-----BEGIN SSH SIGNATURE-----", *lines,
                      "-----END SSH SIGNATURE-----"]) + "\n"


def _armor(body: bytes) -> str:
    return _wrap(base64.b64encode(body).decode())


def _sshsig(version: int = 1, size: int = 120, magic: bytes = b"SSHSIG") -> bytes:
    head = magic + struct.pack(">I", version)
    return head + b"\x00" * (size - len(head))


def _noncanonical_padding() -> str:
    text = base64.b64encode(_sshsig(size=121)).decode()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet[alphabet.index(text[-3]) | 1]
    return _wrap(text[:-3] + last + "==")


_BODY_LINES = SIGNATURE.strip("\n").split("\n")[1:-1]

BAD_SIGNATURES = {
    "não é texto": b"-----BEGIN SSH SIGNATURE-----",
    "vazia": "",
    "longa demais": SIGNATURE + "A" * 4096,
    "sem cabeçalho": "\n".join(SIGNATURE.split("\n")[1:]),
    "sem rodapé": CASES["truncated_armor"]["signature"],
    "texto depois do rodapé": SIGNATURE + "extra\n",
    "espaço antes": " " + SIGNATURE,
    "linha em branco no corpo": SIGNATURE.replace("\n", "\n\n", 2),
    "sem corpo": "-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n",
    "caractere fora do base64": SIGNATURE.replace(_BODY_LINES[1][:4], "!!!!", 1),
    "\\r solto": SIGNATURE.replace("\n", "\r", 1),
    "linha do corpo longa": "\n".join(["-----BEGIN SSH SIGNATURE-----", "".join(_BODY_LINES),
                                       "-----END SSH SIGNATURE-----"]),
    "padding no meio": _armor(_sshsig()).replace(
        base64.b64encode(_sshsig()).decode()[:4], "AA==", 1),
    "tamanho não múltiplo de 4": SIGNATURE.replace(_BODY_LINES[-1],
                                                    _BODY_LINES[-1].rstrip("=")[:-1]),
    "bits de padding não canônicos": _noncanonical_padding(),
    "outro magic": _armor(_sshsig(magic=b"SSHSIX")),
    "versão 2": _armor(_sshsig(version=2)),
    "curta demais": _armor(_sshsig(size=63)),
    "decodificada longa demais": _armor(_sshsig(size=2049)),
}


@pytest.mark.parametrize("name", sorted(BAD_SIGNATURES))
def test_malformed_signature_is_refused_before_the_process(exe, work_dir, name):
    runner = FakeRunner()
    signature = BAD_SIGNATURES[name]
    assert normalize_signature(signature) is None
    assert make(exe, work_dir, runner).verify(KEY, NAMESPACE, MESSAGE, signature) is False
    assert runner.calls == []
    assert leftovers(work_dir) == []


def test_well_formed_structures_pass_the_validation():
    assert normalize_signature(_armor(_sshsig(size=64))) is not None
    assert normalize_signature(_armor(_sshsig(size=2048))) is not None
    assert normalize_signature(SIGNATURE) == SIGNATURE


RSA = json.loads((FIXTURES / "sshkeys" / "vectors.json").read_text("utf-8"))["other"][0]["line"]
_KEY_B64 = KEY.split()[1]

BAD_INPUTS = {
    "outro namespace": dict(namespace="other-namespace"),
    "namespace vazio": dict(namespace=""),
    "chave rsa": dict(public_key=RSA),
    "chave com opções": dict(public_key=f"restrict ssh-ed25519 {_KEY_B64}"),
    "chave com linha injetada": dict(public_key=f"ssh-ed25519 {_KEY_B64}\n{OTHER_KEY_LINE}"),
    "chave com namespaces no comentário": dict(
        public_key=f'ssh-ed25519 {_KEY_B64} namespaces="*"\nx'),
    "chave que não é texto": dict(public_key=None),
    "mensagem vazia": dict(message=b""),
    "mensagem em texto": dict(message=MESSAGE.decode()),
    "mensagem longa demais": dict(message=b"a" * 1025),
    "assinatura None": dict(signature=None),
}


@pytest.mark.parametrize("name", sorted(BAD_INPUTS))
def test_invalid_inputs_are_refused_before_the_process(exe, work_dir, name):
    args = dict(public_key=KEY, namespace=NAMESPACE, message=MESSAGE, signature=SIGNATURE)
    args.update(BAD_INPUTS[name])
    runner = FakeRunner()
    assert make(exe, work_dir, runner).verify(**args) is False
    assert runner.calls == []


def test_message_at_the_size_limit_reaches_the_process(exe, work_dir):
    runner = FakeRunner(Completed(255, b""))
    make(exe, work_dir, runner).verify(KEY, NAMESPACE, b"a" * 1024, SIGNATURE)
    assert len(runner.calls) == 1


# ------------------------------------------------------------------ construção e manutenção


def test_relative_executable_is_refused(work_dir):
    with pytest.raises(ValueError, match="absoluto"):
        SshKeygenVerifier(Path("ssh-keygen"), work_dir)


@pytest.mark.parametrize("kw", [dict(timeout_s=0), dict(timeout_s=-1), dict(max_concurrent=0)])
def test_invalid_limits_are_refused(exe, work_dir, kw):
    with pytest.raises(ValueError):
        SshKeygenVerifier(exe, work_dir, **kw)


def test_default_executable_per_platform():
    assert default_executable(windows=True) == r"C:\Program Files\Git\usr\bin\ssh-keygen.exe"
    assert default_executable(windows=False) == "/usr/bin/ssh-keygen"
    assert default_executable() == default_executable(windows=os.name == "nt")


def test_work_dir_is_next_to_the_database(tmp_path):
    database = tmp_path / "root" / "manager" / "manager.db"
    assert work_dir_for(database) == tmp_path / "root" / "manager" / "tmp" / "sshsig"


def test_purge_stale_removes_only_old_call_directories(exe, work_dir):
    verifier = make(exe, work_dir, FakeRunner())
    assert verifier.purge_stale() == 0
    work_dir.mkdir(parents=True)
    old, new, other = work_dir / "v-antigo", work_dir / "v-recente", work_dir / "outro"
    for d in (old, new, other):
        d.mkdir()
        (d / "signature").write_text("x")
    (work_dir / "v-arquivo").write_text("não é diretório")
    past = time.time() - 3600
    for path in (old, other, work_dir / "v-arquivo"):
        os.utime(path, (past, past))
    assert verifier.purge_stale() == 1
    assert leftovers(work_dir) == ["outro", "v-arquivo", "v-recente"]
    assert verifier.purge_stale(older_than_s=0) == 1
    assert leftovers(work_dir) == ["outro", "v-arquivo"]


def _self_check_runner(accept_good: bool, accept_bad: bool) -> FakeRunner:
    fingerprint = parse_public_key(sshsig.SELF_CHECK_KEY).fingerprint

    def respond(call: Call) -> Completed:
        good = call.stdin == sshsig.SELF_CHECK_MESSAGE
        accept = accept_good if good else accept_bad
        return Completed(0, good_line(fingerprint)) if accept else Completed(255, b"")

    return FakeRunner(respond=respond)


def test_self_check_passes_when_good_is_accepted_and_bad_refused(exe, work_dir):
    runner = _self_check_runner(True, False)
    make(exe, work_dir, runner).self_check()
    assert [c.stdin == sshsig.SELF_CHECK_MESSAGE for c in runner.calls] == [True, False]
    assert all(c.files["signature"] == sshsig.SELF_CHECK_SIGNATURE.encode() for c in
               runner.calls)


@pytest.mark.parametrize(("good", "bad"), [(False, False), (True, True), (False, True)])
def test_self_check_fails_with_the_executable_path(exe, work_dir, good, bad):
    with pytest.raises(SshsigUnavailable) as info:
        make(exe, work_dir, _self_check_runner(good, bad)).self_check()
    assert str(exe) in str(info.value)


def test_self_check_vector_is_well_formed():
    assert parse_public_key(sshsig.SELF_CHECK_KEY).openssh == sshsig.SELF_CHECK_KEY
    assert normalize_signature(sshsig.SELF_CHECK_SIGNATURE) == sshsig.SELF_CHECK_SIGNATURE


# ------------------------------------------------------------------ vetores gravados


def test_vector_messages_are_the_canonical_ones():
    assert VECTORS["namespace"] == NAMESPACE
    assert {c["name"] for c in VECTORS["cases"]} == {
        "valid_login", "valid_register", "other_namespace", "other_message", "other_key",
        "other_server_id", "other_purpose", "truncated_armor", "truncated_body"}
    for case in VECTORS["cases"]:
        fields = dict(case["message"])
        fields["expires"] = parse_expires(fields["expires"])
        assert AuthMessage(**fields).to_bytes() == case["message_text"].encode("ascii")
        assert case["public_key"] == VECTORS["keys"]["a"]
        assert case["valid"] is (case["rejected_by"] is None)


def test_vectors_pass_the_validation_unless_marked_otherwise():
    for case in VECTORS["cases"]:
        accepted = normalize_signature(case["signature"]) is not None
        assert accepted is (case["rejected_by"] != "validation"), case["name"]


def test_vectors_differ_only_in_what_their_name_says():
    login = CASES["valid_login"]
    assert CASES["other_message"]["signature"] == login["signature"]
    assert CASES["other_message"]["message"]["nonce"] != login["message"]["nonce"]
    assert CASES["other_purpose"]["signature"] == CASES["valid_register"]["signature"]
    for name in ("other_namespace", "other_key", "other_server_id", "truncated_body"):
        assert CASES[name]["message"] == login["message"]
        assert CASES[name]["signature"] != login["signature"]


def test_no_private_key_in_fixtures():
    for path in FIXTURES.rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes(), path
