import pytest

from tsm_client.rules import (
    DEFAULT_IGNORES,
    IgnoreMatcher,
    ProjectRules,
    RulesError,
    ignore_patterns,
    sync_flags,
)


def test_flags_always_include_safety_options():
    flags = sync_flags(ProjectRules())
    assert flags[:3] == ["--ignore-syntax=mutagen", "--ignore-vcs", "--symlink-mode=ignore"]


def test_flags_use_equals_form_for_every_pattern():
    rules = ProjectRules(ignore=("*.bak", "!keep.bak"))
    flags = sync_flags(rules)
    ignores = [f for f in flags if f.startswith("--ignore=")]
    assert ignores == [f"--ignore={p}" for p in ignore_patterns(rules)]
    assert "--ignore=!keep.bak" in flags


def test_defaults_come_last_so_project_cannot_unignore_them():
    pats = ignore_patterns(ProjectRules(ignore=("!.env",)))
    assert pats.index("!.env") < pats.index(".env")
    assert pats[-len(DEFAULT_IGNORES):] == list(DEFAULT_IGNORES)


def test_allow_list_builds_negations():
    pats = ignore_patterns(ProjectRules(allow=("data/",)))
    assert pats[:3] == ["/*", "!/ts-project.json", "!/data/"]


def test_allow_list_does_not_duplicate_project_file():
    pats = ignore_patterns(ProjectRules(allow=("ts-project.json", "data/")))
    assert pats.count("!/ts-project.json") == 1


@pytest.mark.parametrize(
    "bad",
    ["", "  ", "a\nb", "a\rb", "../x", "a/../b", "a,b", 'a"b', "a\\b", "!", "/", "C:/x",
     " x", "x "],
)
def test_invalid_ignore_patterns_rejected(bad):
    with pytest.raises(RulesError):
        ProjectRules(ignore=(bad,))


@pytest.mark.parametrize("bad", ["data/scripts/", "*.lua", "../data", "", "/data", "a,b"])
def test_invalid_allow_entries_rejected(bad):
    with pytest.raises(RulesError):
        ProjectRules(allow=(bad,))


def test_rules_from_dict():
    r = ProjectRules.from_dict({"allow": ["data/"], "ignore": ["*.bak"]})
    assert r.allow == ("data/",) and r.ignore == ("*.bak",)
    with pytest.raises(RulesError):
        ProjectRules.from_dict({"allow": "data/"})
    with pytest.raises(RulesError):
        ProjectRules.from_dict({"unknown": []})


# ---------- matcher (semântica Mutagen, usada por testes e verificação) ----------


@pytest.fixture
def default_matcher():
    return IgnoreMatcher(ignore_patterns(ProjectRules()))


@pytest.mark.parametrize(
    ("path", "is_dir"),
    [
        (".git", True),
        ("sub/.git", True),
        (".env", False),
        ("cfg/.env.local", False),
        ("logs", True),
        ("server.log", False),
        ("build", True),
        ("x/build", True),
        ("a.tmp", False),
        ("__pycache__", True),
        ("m.pyc", False),
    ],
)
def test_default_ignores(default_matcher, path, is_dir):
    assert default_matcher.is_ignored(path, is_dir)


@pytest.mark.parametrize(
    ("path", "is_dir"),
    [("data", True), ("data/scripts/spells.lua", False), ("ts-project.json", False),
     ("README.md", False), ("build.lua", False), ("logs.lua", False)],
)
def test_default_does_not_ignore_sources(default_matcher, path, is_dir):
    assert not default_matcher.is_ignored(path, is_dir)


def test_dir_only_pattern_does_not_match_file(default_matcher):
    assert not default_matcher.is_ignored("build", is_dir=False)


def test_allow_list_semantics():
    m = IgnoreMatcher(ignore_patterns(ProjectRules(allow=("data/",))))
    assert not m.is_ignored("data", True)
    assert not m.is_ignored("data/scripts/spells.lua", False)
    assert not m.is_ignored("ts-project.json", False)
    assert m.is_ignored("README.md", False)
    assert m.is_ignored("other", True)
    assert m.is_ignored("data/x.tmp", False)


def test_ignored_dir_hides_children():
    m = IgnoreMatcher(["logs/", "!logs/keep.txt"])
    assert m.is_ignored("logs/keep.txt", False)


def test_anchored_and_slash_patterns():
    m = IgnoreMatcher(["/top.txt", "data/gen/*.lua", "**/deep.txt"], ignore_vcs=False)
    assert m.is_ignored("top.txt", False)
    assert not m.is_ignored("sub/top.txt", False)
    assert m.is_ignored("data/gen/a.lua", False)
    assert not m.is_ignored("data/gen/sub/a.lua", False)
    assert not m.is_ignored("x/data/gen/a.lua", False)
    assert m.is_ignored("a/b/deep.txt", False)


def test_negation_last_match_wins():
    m = IgnoreMatcher(["*.lua", "!keep.lua"], ignore_vcs=False)
    assert m.is_ignored("a.lua", False)
    assert not m.is_ignored("keep.lua", False)


def test_character_class_and_question_mark():
    m = IgnoreMatcher(["file?.[ab]"], ignore_vcs=False)
    assert m.is_ignored("file1.a", False)
    assert not m.is_ignored("file12.a", False)
    assert not m.is_ignored("file1.c", False)
