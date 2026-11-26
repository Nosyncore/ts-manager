import pytest

from tsm_client.adapters.mutagen import pins


def test_pinned_version_and_assets():
    assert pins.MUTAGEN_VERSION == "0.18.1"
    for name, asset in pins.ASSETS.items():
        assert asset.platform == name
        assert pins.MUTAGEN_VERSION in asset.archive
        assert len(asset.archive_sha256) == 64
    assert "linux_arm64" in pins.REQUIRED_AGENTS


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [("Windows", "AMD64", "windows_amd64"), ("Linux", "x86_64", "linux_amd64"),
     ("Linux", "aarch64", "linux_arm64")],
)
def test_host_platform(monkeypatch, system, machine, expected):
    monkeypatch.setattr(pins.platform, "system", lambda: system)
    monkeypatch.setattr(pins.platform, "machine", lambda: machine)
    assert pins.host_platform() == expected


def test_host_platform_unsupported(monkeypatch):
    monkeypatch.setattr(pins.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(pins.platform, "machine", lambda: "arm64")
    with pytest.raises(RuntimeError):
        pins.host_platform()


def test_paths_and_discovery(tmp_path):
    tools = tmp_path / ".tools"
    d = pins.install_dir(tools, "windows_amd64")
    assert d == tools / "mutagen" / "v0.18.1" / "windows_amd64"
    assert pins.executable_path(tools, "windows_amd64").name == "mutagen.exe"
    assert pins.executable_path(tools, "linux_arm64").name == "mutagen"
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert pins.find_tools_root(nested) is None
    d.mkdir(parents=True)
    assert pins.find_tools_root(nested) == tools
