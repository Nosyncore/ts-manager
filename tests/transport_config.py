"""``Config`` de transporte montado em código, para os testes sem Manager.

Os testes de transporte (sincronização local e por SSH, salvaguardas, reconexão) não usam
identidade: montam o ``Config`` que o ``tsm`` usaria e o entregam à CLI por
``tsm_client.cli.run(..., config=…)``. Os endpoints passam pelas mesmas regras da carga de
um ``<home>``: caminhos locais canônicos, remotos ``alias:/caminho`` e nenhum diretório
próprio do Client (daemon, HOME do ssh) sobreposto a um endpoint.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from tsm_client.config import Config, MutagenSettings, check_own_dirs
from tsm_client.paths import Endpoint, canonical_local, parse_endpoint
from tsm_client.rules import ProjectRules
from tsm_client.sessions import Binding


@dataclass(frozen=True)
class BindingSpec:
    """Um vínculo de transporte: caminhos locais relativos valem a partir de ``base``."""

    id: str
    local: str | os.PathLike[str]
    cache: str | os.PathLike[str]
    workspace: str | os.PathLike[str]
    shared: str | os.PathLike[str]
    rules: ProjectRules = field(default_factory=ProjectRules)
    project_id: str = "demo"


def _endpoint(raw: str | os.PathLike[str], base: Path) -> Endpoint:
    text = os.fspath(raw)
    if ":" not in text and not text.startswith(("\\", "/")):
        return Endpoint(None, canonical_local(str(base / text)))
    return parse_endpoint(text)


def _local(raw: str | os.PathLike[str] | None, base: Path) -> Path | None:
    if raw is None:
        return None
    text = os.fspath(raw)
    return Path(canonical_local(text if os.path.isabs(text) else str(base / text)))


def transport_config(base: Path, *, device_id: str, data_directory: str | os.PathLike[str],
                     bindings: Sequence[BindingSpec],
                     executable: str | os.PathLike[str] | None = None,
                     ssh_path: str | os.PathLike[str] | None = None,
                     ssh_home: str | os.PathLike[str] | None = None) -> Config:
    data_dir = _local(data_directory, base)
    assert data_dir is not None
    settings = MutagenSettings(data_directory=data_dir, executable=_local(executable, base),
                               ssh_path=_local(ssh_path, base), ssh_home=_local(ssh_home, base))
    built = [Binding(id=b.id, project_id=b.project_id, local=_endpoint(b.local, base),
                     cache=_endpoint(b.cache, base), workspace=_endpoint(b.workspace, base),
                     shared=_endpoint(b.shared, base), rules=b.rules) for b in bindings]
    check_own_dirs(settings, None, built)
    # ``path`` só orienta a busca do Mutagen fixado (``.tools`` acima de ``base``); não há
    # arquivo de config em disco.
    return Config(path=base.resolve() / "config", device_id=device_id, mutagen=settings,
                  bindings=tuple(built))
