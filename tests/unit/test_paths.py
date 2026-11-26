import os
import subprocess
import sys

import pytest

from tsm_client.paths import (
    Endpoint,
    PathError,
    canonical_local,
    canonical_remote,
    endpoints_overlap,
    parse_endpoint,
)

WINDOWS = sys.platform == "win32"


# ---------- canonicalização local ----------


def test_relative_path_rejected():
    with pytest.raises(PathError, match="absoluto"):
        canonical_local("work/a")


def test_dotdot_rejected(tmp_path):
    with pytest.raises(PathError, match=r"\.\."):
        canonical_local(str(tmp_path / "a" / ".." / "b"))


def test_empty_rejected():
    with pytest.raises(PathError):
        canonical_local("")


@pytest.mark.skipif(not WINDOWS, reason="UNC só existe no Windows")
@pytest.mark.parametrize("p", ["\\\\server\\share\\dir", "//server/share/dir", "\\\\?\\C:\\x"])
def test_unc_and_device_paths_rejected(p):
    assert p.startswith(("\\\\", "//"))
    with pytest.raises(PathError, match="UNC"):
        canonical_local(p)


@pytest.mark.skipif(not WINDOWS, reason="caminho sem unidade só existe no Windows")
def test_drive_relative_rejected():
    with pytest.raises(PathError):
        canonical_local("\\sem\\unidade")


def test_canonical_normalizes_separators_and_trailing(tmp_path):
    raw = str(tmp_path).replace(os.sep, "/") + "//sub/"
    assert canonical_local(raw) == canonical_local(str(tmp_path / "sub"))


@pytest.mark.skipif(not WINDOWS, reason="case-insensitive só no Windows")
def test_canonical_case_insensitive_key_on_windows(tmp_path):
    a = canonical_local(str(tmp_path / "Work"))
    b = canonical_local(str(tmp_path / "work"))
    assert endpoints_overlap(Endpoint(None, a), Endpoint(None, b))


def test_root_symlink_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError as exc:  # sem privilégio no Windows
        pytest.skip(f"sem privilégio para symlink: {exc}")
    with pytest.raises(PathError, match="link"):
        canonical_local(str(link))


@pytest.mark.skipif(not WINDOWS, reason="junction só existe no Windows")
def test_root_junction_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "junction"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True,
                   capture_output=True)
    with pytest.raises(PathError, match="link"):
        canonical_local(str(link))


def test_nonexistent_path_is_allowed(tmp_path):
    p = canonical_local(str(tmp_path / "ainda-nao-existe"))
    assert p.endswith("ainda-nao-existe")


# ---------- remoto ----------


@pytest.mark.parametrize("p", ["/srv/ts/projects/demo/workspaces/dev-a", "/srv/ts/"])
def test_remote_path_ok(p):
    assert canonical_remote(p).startswith("/srv/ts")
    assert not canonical_remote(p).endswith("/") or canonical_remote(p) == "/"


@pytest.mark.parametrize("p", ["srv/ts", "/srv/../etc", "/srv/ts\nx", "", "/srv/ts\\x", "~/x"])
def test_remote_path_rejected(p):
    with pytest.raises(PathError):
        canonical_remote(p)


def test_remote_root_rejected():
    with pytest.raises(PathError, match="raiz"):
        canonical_remote("/")


def test_parse_endpoint_remote():
    ep = parse_endpoint("tsm-test-a:/srv/ts/projects/demo/workspaces/dev-a")
    assert ep == Endpoint("tsm-test-a", "/srv/ts/projects/demo/workspaces/dev-a")
    assert ep.is_remote
    assert ep.url == "tsm-test-a:/srv/ts/projects/demo/workspaces/dev-a"


@pytest.mark.parametrize(
    "spec",
    ["-oProxyCommand=x:/srv", "user@host:/srv", "host:22:/srv", "ho st:/srv", "h:relative"],
)
def test_parse_endpoint_rejects_unsafe_hosts(spec):
    with pytest.raises(PathError):
        parse_endpoint(spec)


def test_parse_endpoint_local(tmp_path):
    ep = parse_endpoint(str(tmp_path / "w"))
    assert not ep.is_remote
    assert ep.url == ep.path


# ---------- sobreposição ----------


def _local(tmp_path, *parts):
    return Endpoint(None, canonical_local(str(tmp_path.joinpath(*parts))))


def test_overlap_equal(tmp_path):
    assert endpoints_overlap(_local(tmp_path, "a"), _local(tmp_path, "a"))


def test_overlap_ancestor_and_descendant(tmp_path):
    assert endpoints_overlap(_local(tmp_path, "a"), _local(tmp_path, "a", "b"))
    assert endpoints_overlap(_local(tmp_path, "a", "b"), _local(tmp_path, "a"))


def test_no_overlap_on_prefix_only(tmp_path):
    assert not endpoints_overlap(_local(tmp_path, "work"), _local(tmp_path, "work2"))


def test_no_overlap_siblings(tmp_path):
    assert not endpoints_overlap(_local(tmp_path, "a"), _local(tmp_path, "b"))


def test_remote_overlap_same_host_only():
    a = Endpoint("h1", "/srv/ts/shared")
    assert endpoints_overlap(a, Endpoint("h1", "/srv/ts"))
    assert endpoints_overlap(a, Endpoint("H1", "/srv/ts/shared/x"))
    assert not endpoints_overlap(a, Endpoint("h2", "/srv/ts/shared"))
    assert not endpoints_overlap(a, Endpoint("h1", "/srv/ts/shared2"))


def test_remote_paths_are_case_sensitive():
    assert not endpoints_overlap(Endpoint("h", "/srv/A"), Endpoint("h", "/srv/a"))


def test_local_and_remote_never_overlap(tmp_path):
    assert not endpoints_overlap(_local(tmp_path, "a"), Endpoint("h", "/a"))
