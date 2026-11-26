"""Configuração comum: testes com Mutagen/SSH/VM reais só rodam quando selecionados por ``-m``."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
GATED = ("integration", "ssh", "remote")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    expr = config.getoption("markexpr") or ""
    for item in items:
        for marker in GATED:
            if item.get_closest_marker(marker) and marker not in expr:
                item.add_marker(pytest.mark.skip(reason=f"rode com -m {marker}"))


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def mutagen_exe() -> Path:
    """Binário do Mutagen fixado em ``.tools`` (``scripts/fetch_mutagen.py``)."""
    from tsm_client.adapters.mutagen import pins

    root = pins.find_tools_root(REPO_ROOT)
    exe = pins.executable_path(root) if root else None
    if exe is None or not exe.is_file():
        pytest.fail("Mutagen fixado ausente: rode 'python scripts/fetch_mutagen.py'")
    return exe
