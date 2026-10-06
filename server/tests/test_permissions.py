"""Tests for the permission system (section 7)."""

from __future__ import annotations

from sqlalchemy import Engine

from app.permissions import (
    PERMISSION_TEMPLATES,
    Permission,
    can,
)


def test_admin_has_all_permissions(engine: Engine, admin_user_id: int) -> None:
    """A global admin has every permission."""
    for perm in Permission:
        assert can(engine, admin_user_id, perm) is True


def test_viewer_can_only_browse(engine: Engine, viewer_user_id: int, project_id: int) -> None:
    """A viewer has only project.browse on a project."""
    assert can(engine, viewer_user_id, Permission.PROJECT_BROWSE, project_id) is True
    assert can(engine, viewer_user_id, Permission.ISSUE_COMMENT, project_id) is False
    assert can(engine, viewer_user_id, Permission.FLAG_CONFIRM, project_id) is False


def test_developer_can_comment_and_request(
    engine: Engine, developer_user_id: int, project_id: int
) -> None:
    """A developer has browse, comment, request, assign."""
    assert can(engine, developer_user_id, Permission.PROJECT_BROWSE, project_id) is True
    assert can(engine, developer_user_id, Permission.ISSUE_COMMENT, project_id) is True
    assert can(engine, developer_user_id, Permission.ISSUE_REQUEST, project_id) is True
    assert can(engine, developer_user_id, Permission.ISSUE_ASSIGN, project_id) is True
    assert can(engine, developer_user_id, Permission.FLAG_CONFIRM, project_id) is False


def test_triager_can_flag(engine: Engine, triager_user_id: int, project_id: int) -> None:
    """A triager has all flag.* permissions."""
    assert can(engine, triager_user_id, Permission.FLAG_CONFIRM, project_id) is True
    assert can(engine, triager_user_id, Permission.FLAG_FALSE_POSITIVE, project_id) is True
    assert can(engine, triager_user_id, Permission.FLAG_ACCEPTED_RISK, project_id) is True
    assert can(engine, triager_user_id, Permission.FLAG_WONT_FIX, project_id) is True
    assert can(engine, triager_user_id, Permission.FLAG_REOPEN, project_id) is True


def test_project_admin_has_project_admin(
    engine: Engine, project_admin_user_id: int, project_id: int
) -> None:
    """A project admin has project.admin."""
    assert can(engine, project_admin_user_id, Permission.PROJECT_ADMIN, project_id) is True


def test_no_permission_without_grant(engine: Engine, regular_user_id: int, project_id: int) -> None:
    """A user with no grants has no permissions on a project."""
    assert can(engine, regular_user_id, Permission.PROJECT_BROWSE, project_id) is False
    assert can(engine, regular_user_id, Permission.ISSUE_COMMENT, project_id) is False


def test_group_grants_give_permissions(
    engine: Engine, group_member_user_id: int, project_id: int, group_id: int
) -> None:
    """A user in a group with a grant gets that permission."""
    # Group has viewer permission on the project
    assert can(engine, group_member_user_id, Permission.PROJECT_BROWSE, project_id) is True
    # Group doesn't have comment permission
    assert can(engine, group_member_user_id, Permission.ISSUE_COMMENT, project_id) is False


def test_permission_templates_exist() -> None:
    """All four permission templates are defined."""
    assert "viewer" in PERMISSION_TEMPLATES
    assert "developer" in PERMISSION_TEMPLATES
    assert "triager" in PERMISSION_TEMPLATES
    assert "project_admin" in PERMISSION_TEMPLATES


def test_viewer_template_permissions() -> None:
    """Viewer template has only project.browse."""
    assert PERMISSION_TEMPLATES["viewer"] == {Permission.PROJECT_BROWSE}


def test_developer_template_permissions() -> None:
    """Developer template has browse, comment, request, assign."""
    assert PERMISSION_TEMPLATES["developer"] == {
        Permission.PROJECT_BROWSE,
        Permission.ISSUE_COMMENT,
        Permission.ISSUE_REQUEST,
        Permission.ISSUE_ASSIGN,
    }


def test_triager_template_permissions() -> None:
    """Triager template is developer + all flag.* permissions."""
    assert PERMISSION_TEMPLATES["triager"] == {
        Permission.PROJECT_BROWSE,
        Permission.ISSUE_COMMENT,
        Permission.ISSUE_REQUEST,
        Permission.ISSUE_ASSIGN,
        Permission.FLAG_CONFIRM,
        Permission.FLAG_FALSE_POSITIVE,
        Permission.FLAG_ACCEPTED_RISK,
        Permission.FLAG_WONT_FIX,
        Permission.FLAG_REOPEN,
    }


def test_project_admin_template_permissions() -> None:
    """Project admin template has everything in the project."""
    assert PERMISSION_TEMPLATES["project_admin"] == {
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
    }
