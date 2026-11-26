"""Versão do Mutagen fixada e hashes de integridade.

Os hashes dos arquivos de release vêm do ``SHA256SUMS`` publicado no release
oficial v0.18.1 (baixado via HTTPS do GitHub). O próprio ``SHA256SUMS`` também
tem o hash fixado aqui, para que uma troca do arquivo no servidor seja detectada.

A assinatura ``SHA256SUMS.gpg`` foi feita pela chave cujo fingerprint está em
``SIGNING_KEY_FINGERPRINT``. A chave pública não foi encontrada em fonte oficial
(GitHub do mantenedor, keys.openpgp.org) em 2026-11-26; por isso a verificação
GPG é opcional e só ocorre se o operador fornecer a chave (``--gpg-key``).
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path

MUTAGEN_VERSION = "0.18.1"
RELEASE_BASE_URL = f"https://github.com/mutagen-io/mutagen/releases/download/v{MUTAGEN_VERSION}/"

SHA256SUMS_NAME = "SHA256SUMS"
SHA256SUMS_SHA256 = "acceb020427a1e46730424ef92a65ad0e9bebfc08e63dbcd74510d3cf41fe2f0"
SIGNING_KEY_FINGERPRINT = "34E4B7729CFC6FB4E776CB3B781D56DB8AFBBFEA"

AGENT_BUNDLE_NAME = "mutagen-agents.tar.gz"
# Agentes que precisam existir no pacote (alvo do MVP: VM Ubuntu ARM64).
REQUIRED_AGENTS = ("linux_arm64", "linux_amd64")


@dataclass(frozen=True)
class ReleaseAsset:
    platform: str
    archive: str
    archive_sha256: str
    executable: str
    # Hashes dos arquivos extraídos, quando conhecidos (permitem auditoria pelo `doctor`).
    extracted_sha256: dict[str, str]


ASSETS: dict[str, ReleaseAsset] = {
    "windows_amd64": ReleaseAsset(
        platform="windows_amd64",
        archive=f"mutagen_windows_amd64_v{MUTAGEN_VERSION}.zip",
        archive_sha256="76f8223d5e6b607efdd9516473669ae5492e4f142887352d59bc6934d1f07a2d",
        executable="mutagen.exe",
        extracted_sha256={
            "mutagen.exe": "d9829413dfd47304ded128fb6696c92e9726c0dafd95c46f1909443ee17299ff",
            AGENT_BUNDLE_NAME: "390fef4f7e4ffd6041f59ec646176b8f4082e6d325a48c5c6d9654abe9a422ba",
        },
    ),
    "linux_amd64": ReleaseAsset(
        platform="linux_amd64",
        archive=f"mutagen_linux_amd64_v{MUTAGEN_VERSION}.tar.gz",
        archive_sha256="7735286c778cc438418209f24d03a64f3a0151c8065ef0fe079cfaf093af6f8f",
        executable="mutagen",
        extracted_sha256={},
    ),
    "linux_arm64": ReleaseAsset(
        platform="linux_arm64",
        archive=f"mutagen_linux_arm64_v{MUTAGEN_VERSION}.tar.gz",
        archive_sha256="bcba735aebf8cbc11da9b3742118a665599ac697fa06bc5751cac8dcd540db8a",
        executable="mutagen",
        extracted_sha256={},
    ),
}


def host_platform() -> str:
    """Plataforma Mutagen (``<os>_<arch>``) da máquina atual."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if system not in ("windows", "linux") or arch is None:
        raise RuntimeError(f"plataforma sem binário Mutagen fixado: {system}/{machine}")
    return f"{system}_{arch}"


def install_dir(tools_root: Path, platform_name: str | None = None) -> Path:
    """Diretório onde a versão fixada é extraída: ``<tools>/mutagen/v<ver>/<plataforma>``."""
    return tools_root / "mutagen" / f"v{MUTAGEN_VERSION}" / (platform_name or host_platform())


def executable_path(tools_root: Path, platform_name: str | None = None) -> Path:
    name = platform_name or host_platform()
    return install_dir(tools_root, name) / ASSETS[name].executable


def find_tools_root(start: Path) -> Path | None:
    """Procura ``.tools/mutagen/v<ver>`` subindo a partir de ``start``."""
    for candidate in (start, *start.parents):
        if (candidate / ".tools" / "mutagen" / f"v{MUTAGEN_VERSION}").is_dir():
            return candidate / ".tools"
    return None
