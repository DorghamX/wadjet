"""Permission system: can() function for checking permissions.

Section 7 of the build guide: one can() function used by every route, service, and template.
"""

from __future__ import annotations

from enum import Enum

from sqlalchemy import Engine, text


class Permission(str, Enum):
    """All permissions defined in section 7."""

    PROJECT_BROWSE = "project.browse"
    ISSUE_COMMENT = "issue.comment"
    ISSUE_ASSIGN = "issue.assign"
    ISSUE_REQUEST = "issue.request"
    FLAG_CONFIRM = "flag.confirm"
    FLAG_FALSE_POSITIVE = "flag.false_positive"
    FLAG_ACCEPTED_RISK = "flag.accepted_risk"
    FLAG_WONT_FIX = "flag.wont_fix"
    FLAG_REOPEN = "flag.reopen"
    PROJECT_ADMIN = "project.admin"
    GATES_ADMIN = "gates.admin"
    USERS_ADMIN = "users.admin"


#: Global admin has all permissions
GLOBAL_ADMIN_PERMISSIONS = set(Permission)


#: Permission templates for grants (section 7)
PERMISSION_TEMPLATES = {
    "viewer": {Permission.PROJECT_BROWSE},
    "developer": {
        Permission.PROJECT_BROWSE,
        Permission.ISSUE_COMMENT,
        Permission.ISSUE_REQUEST,
        Permission.ISSUE_ASSIGN,
    },
    "triager": {
        Permission.PROJECT_BROWSE,
        Permission.ISSUE_COMMENT,
        Permission.ISSUE_REQUEST,
        Permission.ISSUE_ASSIGN,
        Permission.FLAG_CONFIRM,
        Permission.FLAG_FALSE_POSITIVE,
        Permission.FLAG_ACCEPTED_RISK,
        Permission.FLAG_WONT_FIX,
        Permission.FLAG_REOPEN,
    },
    "project_admin": {
        Permission.PROJECT_BROWSE,
        Permission.ISSUE_COMMENT,
        Permission.ISSUE_REQUEST,
        Permission.ISSUE_ASSIGN,
        Permission.FLAG_CONFIRM,
        Permission.FLAG_FALSE_POSITIVE,
        Permission.FLAG_ACCEPTED_RISK,
        Permission.FLAG_WONT_FIX,
        Permission.FLAG_REOPEN,
        Permission.PROJECT_ADMIN,
    },
}


def can(
    engine: Engine,
    user_id: int,
    permission: Permission,
    project_id: int | None = None,
) -> bool:
    """Check if a user has a permission, optionally scoped to a project.

    Effective permissions = union of direct and group grants (section 7).

    Args:
        engine: Database engine
        user_id: The user's ID
        permission: The permission to check
        project_id: Project ID for project-scoped permissions, or None for global

    Returns:
        True if the user has the permission, False otherwise
    """
    with engine.begin() as conn:
        # Check if user is a global admin
        is_admin = conn.execute(
            text("SELECT is_admin FROM users WHERE id = :uid AND is_active = TRUE"),
            {"uid": user_id},
        ).scalar()
        if is_admin:
            return True

        # For global permissions (gates.admin, users.admin), check if user has them
        # via any project grant (we don't have a separate global grants table yet)
        if project_id is None:
            # Global permission check: look for grants on any project
            # This is a simplified check - in reality you'd have a separate global grants table
            # For now, only admins have global permissions
            return False

        # Check project-scoped permission
        # Direct grants
        direct_grant = conn.execute(
            text(
                """
            SELECT 1 FROM project_grants
            WHERE project_id = :pid
              AND subject_type = 'user'
              AND subject_id = :uid
              AND permission = :perm
            """
            ),
            {"pid": project_id, "uid": user_id, "perm": permission.value},
        ).scalar()

        if direct_grant:
            return True

        # Group grants
        group_grant = conn.execute(
            text(
                """
            SELECT 1 FROM project_grants pg
            JOIN group_members gm ON gm.group_id = pg.subject_id
            WHERE pg.project_id = :pid
              AND pg.subject_type = 'group'
              AND gm.user_id = :uid
              AND pg.permission = :perm
            """
            ),
            {"pid": project_id, "uid": user_id, "perm": permission.value},
        ).scalar()

        return bool(group_grant)
