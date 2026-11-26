import json

import pytest

from tsm_client.config import ConfigError, load_config, verify_project_folder


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def cfg_data(tmp_path):
    return {
        "version": 1,
        "device_id": "pca",
        "mutagen": {"data_directory": "pcA/mutagen-data", "executable": str(tmp_path / "m.exe")},
        "bindings": [
            {
                "id": "demo-pca",
                "project_id": "demo",
                "local": "pcA/work",
                "cache": "pcA/cache",
                "workspace": "server/projects/demo/workspaces/devA",
                "shared": "server/projects/demo/shared",
                "rules": {"ignore": ["*.bak"]},
            }
        ],
    }


def test_load_resolves_relative_paths_against_config_dir(tmp_path, cfg_data):
    cfg = load_config(write(tmp_path / "pcA.json", cfg_data))
    b = cfg.bindings[0]
    assert b.local.path == str((tmp_path / "pcA" / "work").resolve())
    assert cfg.mutagen.data_directory == (tmp_path / "pcA" / "mutagen-data").resolve()
    assert b.rules.ignore == ("*.bak",)
    assert cfg.device_id == "pca"


def test_remote_endpoints_kept(tmp_path, cfg_data):
    cfg_data["bindings"][0]["workspace"] = "tsm-test-a:/srv/ts/projects/demo/workspaces/dev-a"
    cfg = load_config(write(tmp_path / "c.json", cfg_data))
    assert cfg.bindings[0].workspace.host == "tsm-test-a"


@pytest.mark.parametrize("missing", ["version", "device_id", "mutagen", "bindings"])
def test_required_top_level_fields(tmp_path, cfg_data, missing):
    del cfg_data[missing]
    with pytest.raises(ConfigError, match=missing):
        load_config(write(tmp_path / "c.json", cfg_data))


@pytest.mark.parametrize("missing", ["id", "project_id", "local", "cache", "workspace", "shared"])
def test_required_binding_fields(tmp_path, cfg_data, missing):
    del cfg_data["bindings"][0][missing]
    with pytest.raises(ConfigError, match=missing):
        load_config(write(tmp_path / "c.json", cfg_data))


def test_unknown_fields_rejected(tmp_path, cfg_data):
    cfg_data["bindings"][0]["mode"] = "two-way-safe"
    with pytest.raises(ConfigError, match="mode"):
        load_config(write(tmp_path / "c.json", cfg_data))


def test_wrong_version(tmp_path, cfg_data):
    cfg_data["version"] = 2
    with pytest.raises(ConfigError, match="version"):
        load_config(write(tmp_path / "c.json", cfg_data))


def test_invalid_json(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("{nope", encoding="utf-8")
    with pytest.raises(ConfigError, match="JSON"):
        load_config(p)


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="não encontrado"):
        load_config(tmp_path / "nao-existe.json")


def test_data_directory_inside_endpoint_rejected(tmp_path, cfg_data):
    cfg_data["mutagen"]["data_directory"] = "pcA/work/.mutagen"
    with pytest.raises(ConfigError, match="data_directory"):
        load_config(write(tmp_path / "c.json", cfg_data))


def test_ssh_home_inside_endpoint_rejected(tmp_path, cfg_data):
    cfg_data["mutagen"]["ssh_home"] = "pcA/cache/home"
    with pytest.raises(ConfigError, match="ssh_home"):
        load_config(write(tmp_path / "c.json", cfg_data))


def test_invalid_rules_reported_as_config_error(tmp_path, cfg_data):
    cfg_data["bindings"][0]["rules"] = {"ignore": ["../x"]}
    with pytest.raises(ConfigError, match="rules"):
        load_config(write(tmp_path / "c.json", cfg_data))


def test_invalid_endpoint_reported_as_config_error(tmp_path, cfg_data):
    cfg_data["bindings"][0]["workspace"] = "user@host:/srv"
    with pytest.raises(ConfigError, match="workspace"):
        load_config(write(tmp_path / "c.json", cfg_data))


def test_duplicate_binding_ids(tmp_path, cfg_data):
    cfg_data["bindings"].append(dict(cfg_data["bindings"][0]))
    with pytest.raises(ConfigError, match="duplicado"):
        load_config(write(tmp_path / "c.json", cfg_data))


# ---------- ts-project.json ----------


@pytest.fixture
def cfg(tmp_path, cfg_data):
    return load_config(write(tmp_path / "pcA.json", cfg_data))


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
