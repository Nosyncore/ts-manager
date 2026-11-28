import json

import pytest

from tests.transport_config import BindingSpec, transport_config
from tsm_client.config import (
    ConfigError,
    MutagenSettings,
    check_own_dirs,
    read_home_config,
    verify_project_folder,
)
from tsm_client.home import Home
from tsm_client.paths import Endpoint
from tsm_client.rules import ProjectRules
from tsm_client.sessions import Binding


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def spec(**kw) -> BindingSpec:
    data = {"id": "demo-pca", "local": "pcA/work", "cache": "pcA/cache",
            "workspace": "server/projects/demo/workspaces/devA",
            "shared": "server/projects/demo/shared", "rules": ProjectRules(ignore=("*.bak",))}
    data.update(kw)
    return BindingSpec(**data)


@pytest.fixture
def cfg(tmp_path):
    return transport_config(tmp_path, device_id="pca", data_directory="pcA/mutagen-data",
                            executable=tmp_path / "m.exe", bindings=[spec()])


def test_transport_config_resolves_relative_paths(tmp_path, cfg):
    b = cfg.bindings[0]
    assert b.local.path == str((tmp_path / "pcA" / "work").resolve())
    assert b.workspace.path == str((tmp_path / "server/projects/demo/workspaces/devA").resolve())
    assert cfg.mutagen.data_directory == (tmp_path / "pcA" / "mutagen-data").resolve()
    assert b.rules.ignore == ("*.bak",)
    assert not cfg.collab_enabled and cfg.home is None and cfg.manager is None


def test_remote_endpoints_kept(tmp_path):
    cfg = transport_config(tmp_path, device_id="pca", data_directory="m", bindings=[
        spec(workspace="tsm-a:/srv/ts/projects/demo/workspaces/a",
             shared="tsm-a:/srv/ts/projects/demo/shared")])
    assert cfg.bindings[0].workspace.host == "tsm-a"


def _settings(tmp_path, **kw) -> MutagenSettings:
    base = {"data_directory": tmp_path / "m", "executable": None, "ssh_path": None,
            "ssh_home": None}
    base.update(kw)
    return MutagenSettings(**base)


def _binding(tmp_path) -> Binding:
    return Binding(id="b", project_id="demo", local=Endpoint(None, str(tmp_path / "work")),
                   cache=Endpoint(None, str(tmp_path / "cache")),
                   workspace=Endpoint(None, str(tmp_path / "ws")),
                   shared=Endpoint(None, str(tmp_path / "shared")), rules=ProjectRules())


@pytest.mark.parametrize("key", ["data_directory", "ssh_home"])
def test_own_dirs_cannot_be_inside_an_endpoint(tmp_path, key):
    settings = _settings(tmp_path, **{key: tmp_path / "work" / "x"})
    with pytest.raises(ConfigError, match=key):
        check_own_dirs(settings, None, [_binding(tmp_path)])


def test_state_directory_cannot_overlap_an_endpoint(tmp_path):
    with pytest.raises(ConfigError, match="state_directory"):
        check_own_dirs(_settings(tmp_path), tmp_path / "cache", [_binding(tmp_path)])
    check_own_dirs(_settings(tmp_path), tmp_path / "state", [_binding(tmp_path)])


@pytest.mark.parametrize("version", [1, 2])
def test_old_config_in_home_is_refused_with_migration_message(tmp_path, version):
    home = Home(tmp_path / "home")
    home.root.mkdir()
    write(home.config_path, {"version": version, "device_id": "pca", "mutagen": {},
                             "bindings": []})
    with pytest.raises(ConfigError) as exc:
        read_home_config(home)
    msg = str(exc.value)
    assert f"version {version}" in msg and "não é mais aceita" in msg and "tsm enroll" in msg


# ---------- ts-project.json ----------


def test_project_file_ok(tmp_path, cfg):
    work = tmp_path / "pcA" / "work"
    work.mkdir(parents=True)
    write(work / "ts-project.json", {"project_id": "demo", "version": 1})
    verify_project_folder(cfg.bindings[0])


def test_project_folder_missing(cfg):
    with pytest.raises(ConfigError, match="não existe"):
        verify_project_folder(cfg.bindings[0])


def test_project_file_missing(tmp_path, cfg):
    (tmp_path / "pcA" / "work").mkdir(parents=True)
    with pytest.raises(ConfigError, match="ts-project.json"):
        verify_project_folder(cfg.bindings[0])


def test_project_id_mismatch(tmp_path, cfg):
    work = tmp_path / "pcA" / "work"
    work.mkdir(parents=True)
    write(work / "ts-project.json", {"project_id": "outro", "version": 1})
    with pytest.raises(ConfigError, match="project_id"):
        verify_project_folder(cfg.bindings[0])


@pytest.mark.parametrize("content", ["[]", "{", '{"project_id": "demo", "version": 9}',
                                     '{"version": 1}'])
def test_project_file_invalid(tmp_path, cfg, content):
    work = tmp_path / "pcA" / "work"
    work.mkdir(parents=True)
    (work / "ts-project.json").write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        verify_project_folder(cfg.bindings[0])
