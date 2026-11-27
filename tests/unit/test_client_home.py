"""Diretório do Client: resolução, layout e proteção contra diretório alheio."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.unit.client_fakes import RecordingAcl
from tsm_client.home import (
    MARKER,
    Home,
    HomeError,
    default_home,
    home_state,
    prepare_home,
    resolve_home,
)


def test_default_home_per_platform():
    assert default_home({"LOCALAPPDATA": r"C:\Users\x\AppData\Local"}, "win32") == \
        Path(r"C:\Users\x\AppData\Local") / "tsm"
    assert default_home({"XDG_DATA_HOME": "/data"}, "linux") == Path("/data/tsm")
    assert default_home({"HOME": "/home/x"}, "linux") == Path("/home/x/.local/share/tsm")
    with pytest.raises(HomeError, match="LOCALAPPDATA"):
        default_home({}, "win32")


def test_resolution_order(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert resolve_home(str(a), {"TSM_HOME": str(b)}).root == a
    assert resolve_home(None, {"TSM_HOME": str(b)}).root == b
    assert resolve_home(None, {"LOCALAPPDATA": str(tmp_path)}).root == tmp_path / "tsm"


@pytest.mark.parametrize("bad", ["relativo", "C:\\x\\..\\y", "\\\\srv\\share\\tsm", ""])
def test_invalid_home_refused(bad):
    with pytest.raises(HomeError):
        resolve_home(bad, {})


def test_layout(tmp_path):
    h = Home(tmp_path)
    assert h.config_path == tmp_path / "config.json"
    assert h.ssh_home == tmp_path / "ssh"
    assert h.key_path == tmp_path / "ssh" / ".ssh" / "id_ed25519"
    assert h.pub_path == tmp_path / "ssh" / ".ssh" / "id_ed25519.pub"
    assert h.ssh_config == tmp_path / "ssh" / ".ssh" / "config"
    assert h.known_hosts == tmp_path / "ssh" / ".ssh" / "known_hosts"
    assert h.mutagen_data == tmp_path / "mutagen-data"
    assert h.state == tmp_path / "state"
    assert h.session_file == tmp_path / "state" / "session.json"
    assert h.refused_file == tmp_path / "state" / "refused"
    assert h.connection_file("b-1") == tmp_path / "state" / "connections" / "b-1.json"
    assert h.default_cache("demo") == tmp_path / "cache" / "demo"


def test_prepare_new_home(tmp_path):
    acl = RecordingAcl()
    h = Home(tmp_path / "novo")
    prepare_home(h, acl)
    for d in (h.root, h.ssh_dir, h.mutagen_data, h.state):
        assert d.is_dir()
    assert (h.root / MARKER).is_file()
    assert acl.dirs == [h.root, h.ssh_dir]
    assert home_state(h) == "ours"


def test_prepare_empty_home_and_reuse(tmp_path):
    acl = RecordingAcl()
    h = Home(tmp_path)
    assert home_state(h) == "empty"
    prepare_home(h, acl)
    again = RecordingAcl()
    prepare_home(h, again)  # já é do tsm: não reaplica a ACL no <home>
    assert again.dirs == [h.ssh_dir]


def test_foreign_directory_refused(tmp_path):
    (tmp_path / "documento.txt").write_text("x")
    acl = RecordingAcl()
    h = Home(tmp_path)
    assert home_state(h) == "foreign"
    with pytest.raises(HomeError, match="não é um diretório do tsm"):
        prepare_home(h, acl)
    assert acl.dirs == []


def test_home_with_config_v3_is_ours(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"version": 3}))
    assert home_state(Home(tmp_path)) == "ours"
    (tmp_path / "config.json").write_text(json.dumps({"version": 2}))
    assert home_state(Home(tmp_path)) == "foreign"
    (tmp_path / "config.json").write_text("{quebrado")
    assert home_state(Home(tmp_path)) == "foreign"


def test_home_must_be_directory(tmp_path):
    f = tmp_path / "arquivo"
    f.write_text("x")
    with pytest.raises(HomeError, match="diretório"):
        prepare_home(Home(f), RecordingAcl())


def test_local_folder_must_not_overlap_home(tmp_path):
    h = Home(tmp_path / "home")
    h.check_outside(tmp_path / "proj")
    for bad in (tmp_path / "home" / "proj", tmp_path):
        with pytest.raises(HomeError, match="sobrepor"):
            h.check_outside(bad)
