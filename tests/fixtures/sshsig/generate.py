"""Refaz ``vectors.json`` com o ``ssh-keygen`` real (padrão: OpenSSH do Git for Windows).

Uso: ``.venv\\Scripts\\python tests\\fixtures\\sshsig\\generate.py``

As chaves privadas nascem num diretório temporário apagado no fim; só chaves públicas,
mensagens e assinaturas são gravadas. As mensagens são as canônicas de
``tsm_common.authmsg``, com servidor, desafio, nonce e expiração fixos.
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.sshsig_signer import generate_key, keygen_path, openssh_version, sign  # noqa: E402
from tsm_common.authmsg import (  # noqa: E402
    NAMESPACE,
    AuthMessage,
    encode_nonce,
    format_expires,
)
from tsm_common.sshkeys import parse_public_key  # noqa: E402

OUT = Path(__file__).with_name("vectors.json")
SERVER_ID = "5e1f0000-0000-4000-8000-00000000c0de"
OTHER_SERVER_ID = "0bad0000-0000-4000-8000-00000000c0de"
CHALLENGE_ID = "c4a11e00-0000-4000-8000-000000000001"
NONCE = encode_nonce(bytes(range(32)))
OTHER_NONCE = encode_nonce(bytes(range(32, 64)))
EXPIRES = datetime(2026, 11, 27, 12, 0, 0, tzinfo=UTC)
OTHER_NAMESPACE = "other-namespace"
LINE = 70


def fields(msg: AuthMessage) -> dict[str, str]:
    out = asdict(msg)
    out["expires"] = format_expires(msg.expires)
    return out


def truncate_body(armor: str, chars: int) -> str:
    lines = armor.strip("\n").split("\n")
    body = "".join(lines[1:-1])[:chars]
    wrapped = [body[i:i + LINE] for i in range(0, len(body), LINE)]
    return "\n".join([lines[0], *wrapped, lines[-1]]) + "\n"


def main() -> None:
    keygen = keygen_path()
    with tempfile.TemporaryDirectory(prefix="tsm-sshsig-vectors-") as tmp:
        work = Path(tmp)
        key_a, pub_a = generate_key(keygen, work / "keys", "dev-a")
        key_b, pub_b = generate_key(keygen, work / "keys", "dev-b")
        fp_a = parse_public_key(pub_a).fingerprint
        login = AuthMessage(SERVER_ID, "login", CHALLENGE_ID, NONCE, fp_a, EXPIRES)
        register = replace(login, purpose="register")
        other_server = replace(login, server_id=OTHER_SERVER_ID)
        other_nonce = replace(login, nonce=OTHER_NONCE)

        def sig(private: Path, msg: AuthMessage, namespace: str = NAMESPACE) -> str:
            return sign(keygen, private, msg.to_bytes(), home=work / "home",
                        namespace=namespace)

        login_a = sig(key_a, login)
        register_a = sig(key_a, register)
        cases = [
            ("valid_login", login, login_a, True, None),
            ("valid_register", register, register_a, True, None),
            ("other_namespace", login, sig(key_a, login, OTHER_NAMESPACE), False,
             "ssh-keygen"),
            ("other_message", other_nonce, login_a, False, "ssh-keygen"),
            ("other_key", login, sig(key_b, login), False, "ssh-keygen"),
            ("other_server_id", login, sig(key_a, other_server), False, "ssh-keygen"),
            ("other_purpose", login, register_a, False, "ssh-keygen"),
            ("truncated_armor", login, login_a.strip("\n").rsplit("\n", 1)[0] + "\n", False,
             "validation"),
            ("truncated_body", login, truncate_body(login_a, 200), False, "ssh-keygen"),
        ]
        version = openssh_version(keygen)

    data = {
        "source": (f"generate.py: ssh-keygen -t ed25519 e -Y sign ({version}); "
                   "só chaves públicas e assinaturas"),
        "namespace": NAMESPACE,
        "keys": {"a": pub_a, "b": pub_b},
        "cases": [
            {"name": name, "public_key": pub_a, "message": fields(msg),
             "message_text": msg.to_bytes().decode("ascii"), "signature": signature,
             "valid": valid, "rejected_by": rejected_by}
            for name, msg, signature, valid, rejected_by in cases
        ],
    }
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
                   newline="\n")
    print(f"{OUT} ({len(cases)} casos)")


if __name__ == "__main__":
    main()
