"""Prepara a validação na VM: chaves de teste locais e o script de provisionamento.

Não se conecta a nada. Gera:
- ``<keys-dir>/id_ed25519_tsm_poc_dev_a`` e ``..._dev_b`` (Ed25519, só para teste);
- ``<out>``: ``deploy/poc-ssh/provision.sh`` precedido das chaves PÚBLICAS e do projeto
  fictício (tar.gz em base64), pronto para revisão e execução pelo operador:

    ssh <alias-admin> 'sudo sh -s' < .poc/remote-provision.sh

Rollback: ``ssh <alias-admin> 'sudo sh -s' < deploy/poc-ssh/rollback.sh``
"""

from __future__ import annotations

import argparse
import base64
import io
import shlex
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "demo-project"
TEMPLATE = REPO_ROOT / "deploy" / "poc-ssh" / "provision.sh"
DEFAULT_SSH_DIR = Path(r"C:\Program Files\Git\usr\bin")
KEYS = {"PUBKEY_A": "tsm-poc-dev-a", "PUBKEY_B": "tsm-poc-dev-b"}


def key_path(keys_dir: Path, user: str) -> Path:
    return keys_dir / f"id_ed25519_{user.replace('-', '_')}"


def ensure_keys(keys_dir: Path, ssh_dir: Path) -> dict[str, str]:
    keys_dir.mkdir(parents=True, exist_ok=True)
    keygen = ssh_dir / ("ssh-keygen.exe" if (ssh_dir / "ssh-keygen.exe").exists() else "ssh-keygen")
    pubs: dict[str, str] = {}
    for var, user in KEYS.items():
        priv = key_path(keys_dir, user)
        if not priv.exists():
            subprocess.run([str(keygen), "-q", "-t", "ed25519", "-N", "", "-C",
                            f"{user}@tsm-poc", "-f", str(priv)], check=True, capture_output=True)
        pubs[var] = priv.with_suffix(".pub").read_text(encoding="ascii").strip()
    return pubs


def demo_tarball() -> str:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path in sorted(DEMO.rglob("*")):
            info = tf.gettarinfo(str(path), arcname=path.relative_to(DEMO).as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode = 0o755 if path.is_dir() else 0o644
            if path.is_dir():
                tf.addfile(info)
            else:
                with open(path, "rb") as fh:
                    tf.addfile(info, fh)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def render(pubs: dict[str, str]) -> str:
    template = TEMPLATE.read_text(encoding="utf-8")
    shebang, _, body = template.partition("\n")
    header = [shebang, "# --- gerado por scripts/poc_remote_prepare.py: revise antes de rodar ---"]
    header += [f"{var}={shlex.quote(value)}" for var, value in pubs.items()]
    header.append(f"DEMO_TGZ_B64={shlex.quote(demo_tarball())}")
    return "\n".join(header) + "\n" + body


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--keys-dir", type=Path, default=REPO_ROOT / ".poc" / "remote-keys")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / ".poc" / "remote-provision.sh")
    ap.add_argument("--ssh-dir", type=Path, default=DEFAULT_SSH_DIR)
    args = ap.parse_args(argv)

    pubs = ensure_keys(args.keys_dir, args.ssh_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(render(pubs).encode("utf-8"))  # LF preservado
    print(f"chaves de teste: {args.keys_dir}")
    print(f"script gerado:   {args.out}")
    print("revise o script e, com autorização, execute:")
    print(f"  ssh <alias-admin> 'sudo sh -s' < {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
