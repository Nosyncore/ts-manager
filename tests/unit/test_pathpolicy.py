"""Política de caminhos publicáveis."""

from __future__ import annotations

import unicodedata

import pytest

from tsm_common.pathpolicy import (
    check_path,
    check_paths,
    collision_key,
    find_collisions,
)


@pytest.mark.parametrize("path", [
    "ts-project.json", "data/scripts/spells.lua", "data/a b/c.lua", "data/ação.lua",
    "data/.hidden", "data/CONSOLE.lua", "data/com10.lua", "data/auxiliar.lua", "a" * 200,
])
def test_accepted(path):
    assert check_path(path) is None


@pytest.mark.parametrize(("path", "fragment"), [
    ("", "vazio"),
    ("/etc/passwd", "absoluto"),
    ("C:/x.lua", "absoluto"),
    ("c:x", "absoluto"),
    ("\\\\srv\\x", "barra invertida"),
    ("data\\x.lua", "barra invertida"),
    ("data//x.lua", "vazio"),
    ("data/", "vazio"),
    ("./x", "'.'"),
    ("data/../x", "'..'"),
    ("data/a<b.lua", "inválido"),
    ("data/a>b", "inválido"),
    ('data/a"b', "inválido"),
    ("data/a|b", "inválido"),
    ("data/a?b", "inválido"),
    ("data/a*b", "inválido"),
    ("data/a:b", "inválido"),
    ("data/a\x01b", "controle"),
    ("data/a\x7fb", "controle"),
    ("data/x.", "ponto ou espaço"),
    ("data/x ", "ponto ou espaço"),
    ("data./x", "ponto ou espaço"),
    ("CON", "reservado"),
    ("data/con.txt", "reservado"),
    ("data/Aux.Lua", "reservado"),
    ("data/nul.tar.gz", "reservado"),
    ("data/COM1.lua", "reservado"),
    ("data/lpt9", "reservado"),
    ("data/COM¹", "reservado"),
    ("prn/x.lua", "reservado"),
    (".tsm/revision.json", "reservado ao Manager"),
    (".TSM/x", "reservado ao Manager"),
    ("a" * 201, "mais de 200"),
    (unicodedata.normalize("NFD", "data/ação.lua"), "NFC"),
])
def test_rejected(path, fragment):
    reason = check_path(path)
    assert reason is not None and fragment in reason, reason


def test_max_chars_configurable():
    assert check_path("a" * 50, max_chars=40) is not None
    assert check_path("a" * 40, max_chars=40) is None


def test_check_paths_reports_each():
    issues = check_paths(["ok.lua", "CON", "a:b"])
    assert [i.path for i in issues] == ["CON", "a:b"]


def test_case_collision_files():
    issues = find_collisions(["data/Spells.lua", "data/spells.lua", "data/x.lua"])
    assert len(issues) == 1 and "colide" in issues[0].reason


def test_case_collision_directories():
    issues = find_collisions(["Data/a.lua", "data/b.lua"])
    assert len(issues) == 1


def test_unicode_collision():
    nfd = unicodedata.normalize("NFD", "ação.lua")
    assert collision_key(nfd) == collision_key("ação.lua")
    assert find_collisions(["ação.lua", nfd])


def test_file_dir_collision():
    assert find_collisions(["data/x", "data/x/y.lua"])
    assert find_collisions(["data/X", "data/x/y.lua"])


def test_no_collision():
    assert find_collisions(["a/b.lua", "a/c.lua", "b/b.lua"]) == []
