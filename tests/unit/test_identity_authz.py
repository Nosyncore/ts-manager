"""Matriz de autorização, célula a célula, e pertinência a projeto."""

from __future__ import annotations

import pytest

from tests.unit.identity_fakes import (
    seed_user,
)
from tsm_common import protocol as P
from tsm_manager.identity import authz
from tsm_manager.identity.authz import Operation as Op
from tsm_manager.identity.base import IdentityError, Principal

PENDING = Principal("s1", "u1", "developer", "d1", "SHA256:x", "pending")
PENDING_ADMIN = Principal("s2", "u2", "admin", "d2", "SHA256:y", "pending")
DEV = Principal("s3", "u3", "developer", "d3", "SHA256:z", "full")
ADMIN = Principal("s4", "u4", "admin", "d4", "SHA256:w", "full")

ALLOW = None

# (operação, membro, dono do vínculo) → resultado para cada coluna da matriz
MATRIX = [
    # operação, member, owns, sem sessão, pending, developer, admin
    (Op.ME, False, False, P.UNAUTHORIZED, ALLOW, ALLOW, ALLOW),
    (Op.LOGOUT, False, False, P.UNAUTHORIZED, ALLOW, ALLOW, ALLOW),
    (Op.CONNECTION_CONFIG, True, True, P.UNAUTHORIZED, P.PENDING_APPROVAL, ALLOW, ALLOW),
    (Op.CONNECTION_CONFIG, True, False, P.UNAUTHORIZED, P.PENDING_APPROVAL, P.NOT_FOUND,
     P.NOT_FOUND),
    (Op.CONNECTION_CONFIG, False, False, P.UNAUTHORIZED, P.PENDING_APPROVAL, P.NOT_FOUND,
     P.NOT_FOUND),
    (Op.PROJECT_READ, True, False, P.UNAUTHORIZED, P.PENDING_APPROVAL, ALLOW, ALLOW),
    (Op.PROJECT_READ, False, False, P.UNAUTHORIZED, P.PENDING_APPROVAL, P.NOT_FOUND, ALLOW),
    (Op.PUBLISH, True, True, P.UNAUTHORIZED, P.PENDING_APPROVAL, ALLOW, ALLOW),
    (Op.PUBLISH, True, False, P.UNAUTHORIZED, P.PENDING_APPROVAL, P.FORBIDDEN, P.FORBIDDEN),
    (Op.PUBLISH, False, False, P.UNAUTHORIZED, P.PENDING_APPROVAL, P.NOT_FOUND, P.FORBIDDEN),
    (Op.ADMIN, True, True, P.UNAUTHORIZED, P.PENDING_APPROVAL, P.FORBIDDEN, ALLOW),
    (Op.ADMIN, False, False, P.UNAUTHORIZED, P.PENDING_APPROVAL, P.FORBIDDEN, ALLOW),
]

CELLS = [
    pytest.param(op, member, owns, principal, expected,
                 id=f"{op.value}-member{int(member)}-owns{int(owns)}-{label}")
    for op, member, owns, *results in MATRIX
    for (label, principal), expected in zip(
        [("anon", None), ("pending", PENDING), ("developer", DEV), ("admin", ADMIN)],
        results, strict=True)
]


@pytest.mark.parametrize("op,member,owns,principal,expected", CELLS)
def test_matrix_cell(op, member, owns, principal, expected):
    assert authz.check(principal, op, member=member, owns_binding=owns) == expected


@pytest.mark.parametrize("op", [Op.CONNECTION_CONFIG, Op.PROJECT_READ, Op.PUBLISH, Op.ADMIN])
def test_pending_admin_is_still_pending(op):
    assert authz.check(PENDING_ADMIN, op, member=True, owns_binding=True) == \
        P.PENDING_APPROVAL


def test_require_raises_with_the_code():
    authz.require(ADMIN, Op.ADMIN)
    with pytest.raises(IdentityError) as err:
        authz.require(DEV, Op.ADMIN)
    assert (err.value.code, err.value.http_status) == (P.FORBIDDEN, 403)
    with pytest.raises(IdentityError) as err:
        authz.require(PENDING, Op.PROJECT_READ)
    assert (err.value.code, err.value.http_status) == (P.PENDING_APPROVAL, 403)
    with pytest.raises(IdentityError) as err:
        authz.require(None, Op.ME)
    assert err.value.http_status == 401


def test_operations_reserved_to_the_server_cli_are_not_in_the_api():
    assert {o.value for o in Op} == {"me", "logout", "connection_config", "project_read",
                                     "publish", "admin"}


def test_project_access_from_the_database(ctx):
    seed_user(ctx, "u1", project="demo")
    seed_user(ctx, "u1", did="dev-u1-b")                       # segundo dispositivo, sem vínculo
    seed_user(ctx, "u2", project="demo", device_status="revoked")
    seed_user(ctx, "u3", project="outro")
    p1 = Principal("s", "u1", "developer", "dev-u1", "fp", "full")
    p1b = Principal("s", "u1", "developer", "dev-u1-b", "fp", "full")
    p2 = Principal("s", "u2", "developer", "dev-u2", "fp", "full")
    p3 = Principal("s", "u3", "developer", "dev-u3", "fp", "full")
    assert authz.project_access(ctx, p1, "demo") == authz.Access(True, "b-dev-u1")
    assert authz.project_access(ctx, p1b, "demo") == authz.Access(True, None)
    assert authz.project_access(ctx, p2, "demo") == authz.Access(False, None)
    assert authz.project_access(ctx, p3, "demo") == authz.Access(False, None)
    assert authz.project_access(ctx, None, "demo") == authz.Access(False, None)


def test_binding_ownership():
    assert authz.owns(DEV, "d3")
    assert not authz.owns(DEV, "d4")
    assert not authz.owns(None, "d3")
