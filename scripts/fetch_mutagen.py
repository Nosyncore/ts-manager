"""Baixa a versão fixada do Mutagen, confere a integridade e extrai em ``.tools/``.

Passos:
1. baixa ``SHA256SUMS`` e confere o hash fixado em ``pins.py``;
2. opcionalmente confere ``SHA256SUMS.gpg`` com uma chave fornecida (``--gpg-key``),
   usando um ``GNUPGHOME`` temporário (nunca o chaveiro pessoal);
3. baixa o arquivo da plataforma e confere o hash contra ``SHA256SUMS`` e contra o pin;
4. extrai, confere os hashes dos arquivos extraídos (quando fixados) e confirma
   que o pacote de agentes contém os agentes exigidos (``linux_arm64``).

Uso: ``python scripts/fetch_mutagen.py [--tools-dir .tools] [--platform windows_amd64]``
"""

from __future__ import annotations

import argparse
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from tsm_client.adapters.mutagen import pins

REPO_ROOT = Path(__file__).resolve().parent.parent


def _download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:
        return resp.read()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_sums(text: str) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            sums[parts[1].lstrip("*")] = parts[0].lower()
    return sums


def _verify_gpg(sums: bytes, signature: bytes, key_file: Path) -> None:
    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg não encontrado no PATH; não é possível verificar a assinatura")
    with tempfile.TemporaryDirectory(prefix="tsm-gnupg-") as home:
        env = {"GNUPGHOME": home, "PATH": str(Path(gpg).parent)}
        base = [gpg, "--batch", "--no-tty", "--homedir", home]
        subprocess.run([*base, "--import", str(key_file)], check=True, env=env, capture_output=True)
        sums_path = Path(home) / pins.SHA256SUMS_NAME
        sig_path = Path(home) / (pins.SHA256SUMS_NAME + ".gpg")
        sums_path.write_bytes(sums)
        sig_path.write_bytes(signature)
        out = subprocess.run(
            [*base, "--status-fd", "1", "--verify", str(sig_path), str(sums_path)],
            env=env,
            capture_output=True,
            text=True,
        )
        good = f"VALIDSIG {pins.SIGNING_KEY_FINGERPRINT}"
        if out.returncode != 0 or good not in out.stdout:
            raise SystemExit(f"assinatura GPG inválida/de outra chave:\n{out.stdout}{out.stderr}")


def _extract(asset: pins.ReleaseAsset, data: bytes, dest: Path) -> None:
    if asset.archive.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                _check_member_name(info.filename)
            zf.extractall(dest)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(dest, filter="data")


def _check_member_name(name: str) -> None:
    p = Path(name)
    if p.is_absolute() or ".." in p.parts or "/" in name.strip("/") or "\\" in name:
        raise SystemExit(f"entrada inesperada no arquivo: {name!r}")


def _agents_in_bundle(bundle: Path) -> set[str]:
    with tarfile.open(bundle, mode="r:gz") as tf:
        return {m.name for m in tf.getmembers()}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--tools-dir", type=Path, default=REPO_ROOT / ".tools")
    ap.add_argument("--platform", default=None, choices=sorted(pins.ASSETS))
    ap.add_argument("--gpg-key", type=Path, default=None, help="chave pública oficial (opcional)")
    ap.add_argument("--force", action="store_true", help="reinstala mesmo se já existir")
    args = ap.parse_args(argv)

    platform_name = args.platform or pins.host_platform()
    asset = pins.ASSETS[platform_name]
    dest = pins.install_dir(args.tools_dir.resolve(), platform_name)
    exe = dest / asset.executable

    if exe.exists() and not args.force:
        print(f"já instalado: {exe} (use --force para reinstalar)")
        return 0

    print(f"Mutagen v{pins.MUTAGEN_VERSION} [{platform_name}]")
    sums_raw = _download(pins.RELEASE_BASE_URL + pins.SHA256SUMS_NAME)
    if _sha256(sums_raw) != pins.SHA256SUMS_SHA256:
        raise SystemExit("SHA256SUMS não confere com o hash fixado; abortando")
    print("  SHA256SUMS: hash fixado confere")

    if args.gpg_key:
        sig = _download(pins.RELEASE_BASE_URL + pins.SHA256SUMS_NAME + ".gpg")
        _verify_gpg(sums_raw, sig, args.gpg_key)
        print(f"  SHA256SUMS.gpg: assinatura válida ({pins.SIGNING_KEY_FINGERPRINT})")
    else:
        print("  SHA256SUMS.gpg: não verificado (chave pública oficial não fornecida)")

    sums = _parse_sums(sums_raw.decode("ascii"))
    if sums.get(asset.archive) != asset.archive_sha256:
        raise SystemExit(f"{asset.archive}: pin diverge do SHA256SUMS; abortando")

    data = _download(pins.RELEASE_BASE_URL + asset.archive)
    if _sha256(data) != asset.archive_sha256:
        raise SystemExit(f"{asset.archive}: hash do download não confere; abortando")
    print(f"  {asset.archive}: hash confere")

    staging = dest.with_name(dest.name + ".partial")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    _extract(asset, data, staging)

    for name, expected in asset.extracted_sha256.items():
        if _sha256((staging / name).read_bytes()) != expected:
            raise SystemExit(f"{name}: hash do arquivo extraído não confere; abortando")
    agents = _agents_in_bundle(staging / pins.AGENT_BUNDLE_NAME)
    missing = [a for a in pins.REQUIRED_AGENTS if a not in agents]
    if missing:
        raise SystemExit(f"pacote de agentes sem {missing}; abortando")
    print(f"  agentes presentes: {', '.join(pins.REQUIRED_AGENTS)} (de {len(agents)})")

    if dest.exists():
        shutil.rmtree(dest)
    staging.rename(dest)
    print(f"instalado em {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
