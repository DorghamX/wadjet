"""Admin pages (section 7 ``users.admin``; section 14 routes).

``/admin/users``, ``/admin/groups`` and ``/admin/permissions`` are three
views of one area, so they share one shell and one tab row - the way the
settings tabs are six views of one project.

``/admin`` itself is a redirect (the choice is logged in
``docs/decisions.md``): the top-bar link gets a single canonical landing
and the tabs already show everything the area holds, so there is no index
page to keep in sync with them.

A session may open a page; the global ``users.admin`` permission (section
7) is required for every page and every form post, and anyone without it
gets one 403 that names the permission. Writes call the service functions
in ``app.api.users``, so a form post and a ``PATCH`` cannot disagree about
what "deactivate" means.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import Engine

from app.api.users import (
    UserOut,
    add_member,
    create_group,
    create_user,
    list_groups,
    list_users,
    remove_member,
    update_group,
    update_user,
    user_choices,
)
from app.audit import read_audit
from app.permissions import PERMISSION_TEMPLATES, Permission, can
from app.projects import MEMBER_COLUMNS
from app.web.routes import PageUser, render, require_page_user
from app.web.settings import TEMPLATE_CHOICES

router = APIRouter(include_in_schema=False)

#: The tab row every admin page wears, in order.
TABS: tuple[tuple[str, str], ...] = (
    ("users", "Users"),
    ("groups", "Groups"),
    ("permissions", "Permissions"),
    ("audit", "Audit"),
)

TAB_LABELS = dict(TABS)

#: What a ``?saved=<code>`` redirect tells the reader (design copy: plain
#: verbs, specific about what changed).
NOTICES = {
    "created": "User created. They can sign in with that username now.",
    "updated": "User saved.",
    "group_created": "Group created. Add its members.",
    "group": "Group saved.",
    "member_added": "That user is now a member of the group.",
    "member_removed": "That user was removed from the group.",
}

#: Section 7's permission names as the matrix headings. The design's own
#: "Members and permissions" labels come first (``MEMBER_COLUMNS``), then
#: the three the grant matrix never has to show.
PERMISSION_LABELS: dict[str, str] = {
    **dict(MEMBER_COLUMNS),
    "issue.request": "Request",
    "gates.admin": "Gates",
    "users.admin": "Users",
}

#: Section 7's "Allows" column, in the guide's words, so the matrix can be
#: read without leaving the page.
PERMISSION_ALLOWS: dict[str, str] = {
    "project.browse": "See the project, its issues and its analyses.",
    "issue.comment": "Comment.",
    "issue.assign": "Assign an issue to a project member.",
    "issue.request": "Send an action request - the default for anyone with browse.",
    "flag.confirm": "Mark an issue confirmed.",
    "flag.false_positive": "Mark an issue a false positive.",
    "flag.accepted_risk": "Mark an issue an accepted risk.",
    "flag.wont_fix": "Mark an issue won't fix.",
    "flag.reopen": "Return a flagged issue to open.",
    "project.admin": "Settings, exclusions, tokens, gate selection and members.",
    "gates.admin": "Global: create and edit quality gates.",
    "users.admin": "Global: manage users and groups.",
}


# --- the shell --------------------------------------------------------------


def _notice(request: Request) -> str | None:
    """The sentence a redirect carries, or nothing for a plain visit."""
    code = request.query_params.get("saved")
    if code is None:
        return None
    return NOTICES.get(code, "Saved.")


def _can_admin(engine: Engine, user: PageUser) -> bool:
    """``users.admin`` (section 7): global, so no project id to pass."""
    return can(engine, user.id, Permission.USERS_ADMIN)


def _guard(request: Request, user: PageUser) -> HTMLResponse | None:
    """403 naming the permission, or ``None`` when the caller may continue."""
    if _can_admin(request.app.state.engine, user):
        return None
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "admin",
            "title": "Admin is restricted",
            "message": "Managing users, groups and permissions needs the users.admin "
            "permission. Only an admin has it - ask one to make the change.",
        },
        status_code=403,
    )


def _missing(request: Request, user: PageUser, what: str) -> HTMLResponse:
    """404: no user or group with that id (only admins get this far)."""
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "admin",
            "title": f"{what} not found",
            "message": f"There is no {what.lower()} with that id. It may have been deleted.",
        },
        status_code=404,
    )


def _page(
    request: Request,
    user: PageUser,
    tab: str,
    *,
    notice: str | None = None,
    error: str | None = None,
    status_code: int = 200,
    **extra: Any,
) -> HTMLResponse:
    """Render one admin tab inside the shared shell, admins only."""
    forbidden = _guard(request, user)
    if forbidden is not None:
        return forbidden
    context: dict[str, Any] = {
        "user": user,
        "nav": "admin",
        "tab": tab,
        "tab_label": TAB_LABELS[tab],
        "tabs": [{"slug": slug, "label": label, "on": slug == tab} for slug, label in TABS],
        "notice": notice,
        "error": error,
        **extra,
    }
    # A tab that carries no preserved form still gets a defined value, so
    # the template never reads an undefined.
    context.setdefault("form", None)
    return render(request, f"admin_{tab}.html", context=context, status_code=status_code)


def _failed(request: Request, user: PageUser, tab: str, exc: Exception, **extra: Any) -> Response:
    """One shape for every refused write: the message, on the page that
    asked for it, with whatever was typed kept on screen (section 14)."""
    if isinstance(exc, HTTPException):
        if exc.status_code == 404:
            return _missing(request, user, "User" if tab == "users" else "Group")
        message = str(exc.detail)
    else:
        message = str(exc)
    return _page(request, user, tab, error=message, status_code=400, **extra)


# --- users ------------------------------------------------------------------


def _people(request: Request) -> list[UserOut]:
    """The user rows, for a re-render after a refused write."""
    with request.app.state.engine.connect() as conn:
        return list_users(conn)


def _users_page(
    request: Request,
    user: PageUser,
    *,
    notice: str | None = None,
    error: str | None = None,
    form: dict[str, Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    return _page(
        request,
        user,
        "users",
        notice=notice,
        error=error,
        status_code=status_code,
        users=_people(request),
        form=form,
    )


@router.get("/admin")
def admin_index(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """The top-bar link's landing: one canonical home, the tabs do the rest."""
    return RedirectResponse(url="/admin/users", status_code=303)


@router.get("/admin/users")
def users_page(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """Every account with its role, status and groups (section 7)."""
    return _users_page(request, user, notice=_notice(request))


@router.post("/admin/users")
async def create_user_page(
    request: Request,
    username: str = Form(""),
    email: str = Form(""),
    display_name: str = Form(""),
    password: str = Form(""),
    is_admin: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Add an account; the service validates it and audits the row."""
    forbidden = _guard(request, user)
    if forbidden is not None:
        return forbidden
    values: dict[str, Any] = {
        "username": username.strip(),
        "email": email.strip(),
        "display_name": display_name.strip(),
        "is_admin": is_admin == "on",
    }
    if not values["username"]:
        return _users_page(
            request, user, error="Give the user a username.", form=values, status_code=400
        )
    if not password:
        return _users_page(
            request,
            user,
            error="Set a password of at least 8 characters.",
            form=values,
            status_code=400,
        )
    try:
        create_user(
            request.app.state.engine,
            username=values["username"],
            email=values["email"],
            password=password,
            display_name=values["display_name"] or None,
            is_admin=values["is_admin"],
            actor_id=user.id,
        )
    except (ValueError, HTTPException) as exc:
        return _failed(request, user, "users", exc, users=_people(request), form=values)
    return RedirectResponse(url="/admin/users?saved=created", status_code=303)


@router.post("/admin/users/{user_id}")
async def save_user_page(
    request: Request,
    user_id: str,
    display_name: str = Form(""),
    email: str = Form(""),
    role: str = Form("member"),
    status: str = Form("active"),
    password: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Edit one row: name, email, role, status, or a new password."""
    forbidden = _guard(request, user)
    if forbidden is not None:
        return forbidden
    if not user_id.isdigit():
        return _missing(request, user, "User")
    values: dict[str, Any] = {
        "user_id": int(user_id),
        "display_name": display_name.strip(),
        "email": email.strip(),
        "role": role,
        "status": status,
    }
    if role not in ("member", "admin") or status not in ("active", "inactive"):
        return _users_page(
            request,
            user,
            error="Pick a role and a status from the list.",
            form=values,
            status_code=400,
        )
    try:
        update_user(
            request.app.state.engine,
            int(user_id),
            email=values["email"] or None,
            display_name=values["display_name"],
            is_admin=role == "admin",
            is_active=status == "active",
            password=password or None,
            actor_id=user.id,
        )
    except (ValueError, HTTPException) as exc:
        return _failed(request, user, "users", exc, users=_people(request), form=values)
    return RedirectResponse(url="/admin/users?saved=updated", status_code=303)


# --- groups -----------------------------------------------------------------


def _group_rows(engine: Engine) -> list[dict[str, Any]]:
    """Groups as the template reads them, each with who is left to add."""
    with engine.connect() as conn:
        groups = list_groups(conn)
        choices = user_choices(conn)
    rows: list[dict[str, Any]] = []
    for group in groups:
        member_ids = {member.id for member in group.members}
        rows.append(
            {
                "id": group.id,
                "name": group.name,
                "description": group.description,
                "members": [
                    {
                        "id": member.id,
                        "username": member.username,
                        "label": member.display_name or member.username,
                    }
                    for member in group.members
                ],
                "choices": [
                    {
                        "id": choice.id,
                        "label": choice.display_name or choice.username,
                        "hint": choice.username,
                    }
                    for choice in choices
                    if choice.id not in member_ids
                ],
            }
        )
    return rows


def _groups_page(
    request: Request,
    user: PageUser,
    *,
    notice: str | None = None,
    error: str | None = None,
    form: dict[str, Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    return _page(
        request,
        user,
        "groups",
        notice=notice,
        error=error,
        status_code=status_code,
        groups=_group_rows(request.app.state.engine),
        form=form,
    )


@router.get("/admin/groups")
def groups_page(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """Every group with its members, and who is left to add (section 7)."""
    return _groups_page(request, user, notice=_notice(request))


@router.post("/admin/groups")
async def create_group_page(
    request: Request,
    name: str = Form(""),
    description: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Start a group; its members are added on the same page."""
    forbidden = _guard(request, user)
    if forbidden is not None:
        return forbidden
    values = {"name": name.strip(), "description": description.strip()}
    if not values["name"]:
        return _groups_page(
            request, user, error="Give the group a name.", form=values, status_code=400
        )
    try:
        create_group(
            request.app.state.engine,
            name=values["name"],
            description=values["description"] or None,
            actor_id=user.id,
        )
    except (ValueError, HTTPException) as exc:
        return _failed(
            request,
            user,
            "groups",
            exc,
            groups=_group_rows(request.app.state.engine),
            form=values,
        )
    return RedirectResponse(url="/admin/groups?saved=group_created", status_code=303)


@router.post("/admin/groups/{group_id}")
async def save_group_page(
    request: Request,
    group_id: str,
    name: str = Form(""),
    description: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Rename a group and/or rewrite its description."""
    forbidden = _guard(request, user)
    if forbidden is not None:
        return forbidden
    if not group_id.isdigit():
        return _missing(request, user, "Group")
    values: dict[str, Any] = {
        "group_id": int(group_id),
        "name": name.strip(),
        "description": description.strip(),
    }
    if not values["name"]:
        return _groups_page(
            request, user, error="Give the group a name.", form=values, status_code=400
        )
    try:
        update_group(
            request.app.state.engine,
            int(group_id),
            name=values["name"],
            description=values["description"],
            actor_id=user.id,
        )
    except (ValueError, HTTPException) as exc:
        return _failed(
            request,
            user,
            "groups",
            exc,
            groups=_group_rows(request.app.state.engine),
            form=values,
        )
    return RedirectResponse(url="/admin/groups?saved=group", status_code=303)


def _membership(
    request: Request, group_id: str, user_id: str, user: PageUser
) -> HTMLResponse | tuple[int, int]:
    """Shared preamble of the two membership posts: ids that must be digits
    come back as a 404 page, anything else as the pair to write."""
    if not group_id.isdigit():
        return _missing(request, user, "Group")
    if not user_id.isdigit():
        return _missing(request, user, "User")
    return int(group_id), int(user_id)


@router.post("/admin/groups/{group_id}/members")
async def add_group_member_page(
    request: Request,
    group_id: str,
    user_id: str = Form(...),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Put a chosen account in the group - a permission change, so audited."""
    forbidden = _guard(request, user)
    if forbidden is not None:
        return forbidden
    ids = _membership(request, group_id, user_id, user)
    if isinstance(ids, Response):
        return ids
    numeric_group, numeric_user = ids
    try:
        add_member(request.app.state.engine, numeric_group, numeric_user, actor_id=user.id)
    except (ValueError, HTTPException) as exc:
        return _failed(request, user, "groups", exc, groups=_group_rows(request.app.state.engine))
    return RedirectResponse(url="/admin/groups?saved=member_added", status_code=303)


@router.post("/admin/groups/{group_id}/members/remove")
async def remove_group_member_page(
    request: Request,
    group_id: str,
    user_id: str = Form(...),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Take a chosen account out of the group, and audit it."""
    forbidden = _guard(request, user)
    if forbidden is not None:
        return forbidden
    ids = _membership(request, group_id, user_id, user)
    if isinstance(ids, Response):
        return ids
    numeric_group, numeric_user = ids
    try:
        remove_member(request.app.state.engine, numeric_group, numeric_user, actor_id=user.id)
    except (ValueError, HTTPException) as exc:
        return _failed(request, user, "groups", exc, groups=_group_rows(request.app.state.engine))
    return RedirectResponse(url="/admin/groups?saved=member_removed", status_code=303)


# --- the permission matrix ---------------------------------------------------


def _matrix() -> dict[str, Any]:
    """Section 7's templates over every permission - read-only (section 7)."""
    permissions = list(Permission)
    return {
        "columns": [
            {
                "permission": permission.value,
                "label": PERMISSION_LABELS.get(permission.value, permission.value),
            }
            for permission in permissions
        ],
        "templates": [
            {
                "value": value,
                "label": label,
                "hint": hint,
                "cells": [
                    {
                        "permission": permission.value,
                        "yes": permission in PERMISSION_TEMPLATES[value],
                    }
                    for permission in permissions
                ],
            }
            for value, label, hint in TEMPLATE_CHOICES
        ],
        "legend": [
            {
                "permission": permission.value,
                "label": PERMISSION_LABELS.get(permission.value, permission.value),
                "allows": PERMISSION_ALLOWS.get(permission.value, "See section 7."),
            }
            for permission in permissions
        ],
    }


@router.get("/admin/permissions")
def permissions_page(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """What each grant template gives, straight from ``app.permissions``."""
    return _page(request, user, "permissions", notice=_notice(request), **_matrix())


@router.get("/admin/audit")
def audit_page(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """Paginated audit log, admin only (section 13)."""
    forbidden = _guard(request, user)
    if forbidden is not None:
        return forbidden
    engine = request.app.state.engine
    limit = int(request.query_params.get("limit", "50"))
    action_filter = request.query_params.get("action")
    entries = read_audit(
        engine,
        action=action_filter if action_filter else None,
        limit=limit,
    )
    return _page(
        request,
        user,
        "audit",
        notice=_notice(request),
        entries=entries,
        limit=limit,
    )
