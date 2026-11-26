import pytest

from tsm_client.paths import Endpoint, canonical_local
from tsm_client.rules import ProjectRules
from tsm_client.sessions import (
    MODE,
    Binding,
    ExistingSession,
    Role,
    SessionRuleError,
    build_specs,
    validate_specs,
)


def L(tmp_path, *parts):
    return Endpoint(None, canonical_local(str(tmp_path.joinpath(*parts))))


@pytest.fixture
def binding(tmp_path):
    return Binding(
        id="demo-pca",
        project_id="demo",
        local=L(tmp_path, "pcA", "work"),
        cache=L(tmp_path, "pcA", "cache"),
        workspace=L(tmp_path, "server", "workspaces", "devA"),
        shared=L(tmp_path, "server", "shared"),
        rules=ProjectRules(),
    )


@pytest.fixture
def remote_binding(tmp_path):
    return Binding(
        id="demo-pca",
        project_id="demo",
        local=L(tmp_path, "pcA", "work"),
        cache=L(tmp_path, "pcA", "cache"),
        workspace=Endpoint("tsm-test-a", "/srv/ts/projects/demo/workspaces/dev-a"),
        shared=Endpoint("tsm-test-a", "/srv/ts/projects/demo/shared"),
        rules=ProjectRules(),
    )


def test_two_specs_with_fixed_mode_and_directions(binding):
    up, down = build_specs(binding)
    assert (up.role, down.role) == (Role.UPLOAD, Role.DOWNLOAD)
    assert up.mode == down.mode == MODE == "one-way-replica"
    assert (up.alpha, up.beta) == (binding.local, binding.workspace)
    assert (down.alpha, down.beta) == (binding.shared, binding.cache)


def test_names_and_labels_deterministic(binding):
    up, down = build_specs(binding)
    assert up.name == "tsm-demo-pca-up" and down.name == "tsm-demo-pca-down"
    assert up.labels["tsm-managed"] == "true"
    assert up.labels["tsm-binding"] == "demo-pca"
    assert up.labels["tsm-role"] == "upload" and down.labels["tsm-role"] == "download"
    assert build_specs(binding) == (up, down)
    assert len(up.spec_hash) == 12 and up.spec_hash != down.spec_hash


def test_spec_hash_changes_with_configuration(binding, tmp_path):
    other = Binding(**{**binding.__dict__, "rules": ProjectRules(ignore=("*.bak",))})
    assert build_specs(other)[0].spec_hash != build_specs(binding)[0].spec_hash


def test_flags_contain_rules(binding):
    up, down = build_specs(binding)
    for spec in (up, down):
        assert "--ignore-vcs" in spec.flags and "--symlink-mode=ignore" in spec.flags
    assert not any(f.startswith("--default-file-mode") for f in up.flags)


def test_remote_posix_beta_gets_group_readable_modes(remote_binding):
    up, down = build_specs(remote_binding)
    assert "--default-file-mode-beta=0640" in up.flags
    assert "--default-directory-mode-beta=0750" in up.flags
    assert not any(f.startswith("--default-file-mode") for f in down.flags)


def test_remote_read_only_shared_is_not_probed(remote_binding, binding):
    up, down = build_specs(remote_binding)
    assert "--probe-mode-alpha=assume" in down.flags
    assert not any(f.startswith("--probe-mode") for f in up.flags)
    assert not any(f.startswith("--probe-mode") for f in build_specs(binding)[1].flags)


@pytest.mark.parametrize("bad", ["", "Demo", "-x", "a_b", "a" * 49, "a b"])
def test_invalid_binding_id(binding, bad):
    with pytest.raises(SessionRuleError):
        Binding(**{**binding.__dict__, "id": bad})


def test_local_and_cache_must_be_local(binding):
    with pytest.raises(SessionRuleError, match="local"):
        Binding(**{**binding.__dict__, "local": Endpoint("h", "/w")})
    with pytest.raises(SessionRuleError, match="cache"):
        Binding(**{**binding.__dict__, "cache": Endpoint("h", "/c")})


def test_cache_inside_local_rejected(binding, tmp_path):
    with pytest.raises(SessionRuleError, match="sobrep"):
        validate_specs(build_specs(Binding(**{**binding.__dict__,
                                                "cache": L(tmp_path, "pcA", "work", ".cache")})))


def test_local_inside_cache_rejected(binding, tmp_path):
    with pytest.raises(SessionRuleError):
        validate_specs(build_specs(Binding(**{**binding.__dict__,
                                                "local": L(tmp_path, "pcA", "cache", "w")})))


def test_workspace_equal_shared_rejected(binding):
    with pytest.raises(SessionRuleError):
        validate_specs(build_specs(Binding(**{**binding.__dict__, "workspace": binding.shared})))


def test_workspace_inside_shared_rejected(binding, tmp_path):
    inside = L(tmp_path, "server", "shared", "w")
    with pytest.raises(SessionRuleError):
        validate_specs(build_specs(Binding(**{**binding.__dict__, "workspace": inside})))


def test_workspace_equal_local_rejected(binding):
    with pytest.raises(SessionRuleError):
        validate_specs(build_specs(Binding(**{**binding.__dict__, "workspace": binding.local})))


def test_valid_binding_passes(binding):
    validate_specs(build_specs(binding))


def test_two_bindings_sharing_workspace_rejected(binding, tmp_path):
    b2 = Binding(**{**binding.__dict__, "id": "demo-pcb",
                    "local": L(tmp_path, "pcB", "work"), "cache": L(tmp_path, "pcB", "cache")})
    with pytest.raises(SessionRuleError, match="workspaces|sobrep"):
        validate_specs([*build_specs(binding), *build_specs(b2)])


def test_two_bindings_can_share_the_shared_alpha(binding, tmp_path):
    b2 = Binding(**{**binding.__dict__, "id": "demo-pcb",
                    "local": L(tmp_path, "pcB", "work"), "cache": L(tmp_path, "pcB", "cache"),
                    "workspace": L(tmp_path, "server", "workspaces", "devB")})
    validate_specs([*build_specs(binding), *build_specs(b2)])


def test_collision_with_existing_session_endpoint(binding, tmp_path):
    other = ExistingSession(name="alheia", alpha=L(tmp_path, "x"),
                            beta=L(tmp_path, "pcA", "cache", "sub"))
    with pytest.raises(SessionRuleError, match="alheia"):
        validate_specs(build_specs(binding), existing=[other])


def test_existing_session_whose_beta_is_our_local_rejected(binding, tmp_path):
    other = ExistingSession(name="alheia", alpha=L(tmp_path, "x"), beta=binding.local)
    with pytest.raises(SessionRuleError):
        validate_specs(build_specs(binding), existing=[other])


def test_existing_session_with_same_name_is_still_checked(binding):
    # nome igual não identifica a sessão; uma alheia homônima continua sendo checada
    up, down = build_specs(binding)
    same = ExistingSession(name=up.name, alpha=up.alpha, beta=up.beta)
    with pytest.raises(SessionRuleError):
        validate_specs([up, down], existing=[same])


def test_unrelated_existing_session_ok(binding, tmp_path):
    other = ExistingSession(name="alheia", alpha=L(tmp_path, "y"), beta=L(tmp_path, "z"))
    validate_specs(build_specs(binding), existing=[other])


def test_remote_workspaces_on_different_paths_ok(remote_binding):
    b2 = Binding(**{**remote_binding.__dict__, "id": "demo-pcb",
                    "local": Endpoint(None, remote_binding.local.path + "B"),
                    "cache": Endpoint(None, remote_binding.cache.path + "B"),
                    "workspace": Endpoint("tsm-test-b", "/srv/ts/projects/demo/workspaces/dev-b"),
                    "shared": Endpoint("tsm-test-b", "/srv/ts/projects/demo/shared")})
    validate_specs([*build_specs(remote_binding), *build_specs(b2)])
