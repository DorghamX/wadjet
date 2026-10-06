"""Exhaustive permission matrix test (section 7, T1.4).

Every role against every permission, in both scopes (project and global), plus
cross-project isolation: a grant on project A never leaks to project B, and a
token for project A cannot act for project B.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text

from app.permissions import PERMISSION_TEMPLATES, Permission, can

ROLES = (
    "none",
    "viewer",
    "developer",
    "triager",
    "project_admin",
    "group_viewer",
    "admin",
)

#: Permissions checked without a project (section 7: gates and users admin).
GLOBAL_PERMS = frozenset({Permission.GATES_ADMIN, Permission.USERS_ADMIN})

#: The template each role is granted on the test project.
ROLE_TEMPLATES = {
    "none": frozenset(),
    "viewer": PERMISSION_TEMPLATES["viewer"],
    "developer": PERMISSION_TEMPLATES["developer"],
    "triager": PERMISSION_TEMPLATES["triager"],
    "project_admin": PERMISSION_TEMPLATES["project_admin"],
    "group_viewer": PERMISSION_TEMPLATES["viewer"],  # granted through the group
    "admin": None,  # None = global admin, everything is True
}


@pytest.fixture(scope="module")
def matrix_users(
    regular_user_id: int,
    viewer_user_id: int,
    developer_user_id: int,
    triager_user_id: int,
    project_admin_user_id: int,
    group_member_user_id: int,
    admin_user_id: int,
) -> dict[str, int]:
    """Map of role name to the user id that carries that role."""
    return {
        "none": regular_user_id,
        "viewer": viewer_user_id,
        "developer": developer_user_id,
        "triager": triager_user_id,
        "project_admin": project_admin_user_id,
        "group_viewer": group_member_user_id,
        "admin": admin_user_id,
    }


def _expected(role: str, perm: Permission) -> bool:
    """The answer the matrix demands for role x permission."""
    template = ROLE_TEMPLATES[role]
    if template is None:  # global admin
        return True
    if perm in GLOBAL_PERMS:
        # Only a global admin holds gates.admin / users.admin.
        return False
    return perm in template


@pytest.mark.parametrize("perm", list(Permission), ids=lambda p: p.value)
@pytest.mark.parametrize("role", ROLES)
def test_project_scope_matrix(
    matrix_users: dict[str, int],
    role: str,
    perm: Permission,
    engine: Engine,
    project_id: int,
) -> None:
    """role x permission on the test project matches the expected answer."""
    user_id = matrix_users[role]
    assert can(engine, user_id, perm, project_id) is _expected(role, perm)


@pytest.mark.parametrize("perm", list(Permission), ids=lambda p: p.value)
@pytest.mark.parametrize("role", ROLES)
def test_global_scope_matrix(
    matrix_users: dict[str, int],
    role: str,
    perm: Permission,
    engine: Engine,
) -> None:
    """Without a project only a global admin holds any permission."""
    user_id = matrix_users[role]
    expected = role == "admin"
    assert can(engine, user_id, perm, None) is expected


@pytest.fixture(scope="module")
def isolation_project_id(engine: Engine, admin_user_id: int) -> int:
    """A second project nobody but the admin is granted on."""
    with engine.begin() as conn:
        return conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES ('matrix-isolation', 'Matrix Isolation', :uid) RETURNING id"
            ),
            {"uid": admin_user_id},
        ).scalar_one()


@pytest.mark.parametrize("perm", list(Permission), ids=lambda p: p.value)
@pytest.mark.parametrize("role", ROLES)
def test_grants_do_not_leak_across_projects(
    matrix_users: dict[str, int],
    role: str,
    perm: Permission,
    engine: Engine,
    isolation_project_id: int,
) -> None:
    """A grant on the test project means nothing on a different project."""
    user_id = matrix_users[role]
    expected = role == "admin"
    assert can(engine, user_id, perm, isolation_project_id) is expected


def test_templates_are_subsets_of_each_other() -> None:
    """viewer c developer c triager c project_admin: strictly growing scopes."""
    viewer = PERMISSION_TEMPLATES["viewer"]
    developer = PERMISSION_TEMPLATES["developer"]
    triager = PERMISSION_TEMPLATES["triager"]
    project_admin = PERMISSION_TEMPLATES["project_admin"]
    assert viewer < developer < triager < project_admin


def test_only_project_admin_holds_project_admin(
    matrix_users: dict[str, int], engine: Engine, project_id: int
) -> None:
    """The permission the guide calls out specifically stays with admins."""
    for role in ("none", "viewer", "developer", "triager", "group_viewer"):
        assert can(engine, matrix_users[role], Permission.PROJECT_ADMIN, project_id) is False
    assert can(engine, matrix_users["project_admin"], Permission.PROJECT_ADMIN, project_id) is True
    assert can(engine, matrix_users["admin"], Permission.PROJECT_ADMIN, project_id) is True
