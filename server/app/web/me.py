"""The profile page (section 15: ``/me``), with the password change.

The page serves the same two edits the API already offers through
``PATCH /api/v1/me`` and ``POST /api/v1/me/password`` (section 14): the
display name, and the password with its 8-character minimum. A password
change revokes every session on the account (section 2: DB-backed
sessions), so a stolen session dies with the old password.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import text

from app.audit import write_audit
from app.db import expire_sessions_for_user
from app.security import hash_password, verify_password
from app.web.routes import PageUser, render, require_page_user

router = APIRouter(include_in_schema=False)

MIN_PASSWORD_LENGTH = 8


def _profile_email(request: Request, user_id: int) -> str:
    """The account's email address; the page shows it read-only."""
    with request.app.state.engine.connect() as conn:
        row = conn.execute(
            text("SELECT email FROM users WHERE id = :uid"),
            {"uid": user_id},
        ).first()
    return str(row[0]) if row else ""


def _reload_user(request: Request, user: PageUser) -> PageUser:
    """A fresh ``PageUser`` after a write, so the form shows what is stored."""
    with request.app.state.engine.connect() as conn:
        row = conn.execute(
            text("SELECT username, display_name, is_admin FROM users WHERE id = :uid"),
            {"uid": user.id},
        ).first()
    if row is None:  # pragma: no cover - the session's user cannot vanish mid-request
        return user
    return PageUser(
        id=user.id,
        username=str(row[0]),
        display_name=row[1],
        is_admin=bool(row[2]),
    )


@router.get("/me")
def me_form(request: Request, user: PageUser = Depends(require_page_user)) -> HTMLResponse:
    """The profile page; ``require_page_user`` sends strangers to ``/login``."""
    return render(
        request,
        "me.html",
        context={"user": user, "email": _profile_email(request, user.id)},
    )


@router.post("/me")
async def me_save(request: Request, user: PageUser = Depends(require_page_user)) -> HTMLResponse:
    """Save the display name. An empty (or whitespace) name changes nothing."""
    form = await request.form()
    name = str(form.get("display_name") or "").strip()
    if name:
        with request.app.state.engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET display_name = :name WHERE id = :uid"),
                {"name": name[:255], "uid": user.id},
            )
        write_audit(
            request.app.state.engine,
            action="user.update",
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
            details={"fields": ["display_name"]},
            ip=request.client.host if request.client else None,
        )
        user = _reload_user(request, user)
        message: str | None = "Details saved."
    else:
        message = None
    return render(
        request,
        "me.html",
        context={
            "user": user,
            "email": _profile_email(request, user.id),
            "message": message,
        },
    )


@router.post("/me/password")
async def me_password(
    request: Request, user: PageUser = Depends(require_page_user)
) -> HTMLResponse:
    """Change the password; the old one must match and the new one must be
    long enough. Every session on this account is revoked afterwards."""
    form = await request.form()
    current = str(form.get("current_password") or "")
    new = str(form.get("new_password") or "")

    with request.app.state.engine.connect() as conn:
        row: Any = conn.execute(
            text("SELECT password_hash FROM users WHERE id = :uid"),
            {"uid": user.id},
        ).first()
    stored_hash = str(row[0]) if row else ""

    if len(new) < MIN_PASSWORD_LENGTH:
        message = f"Passwords need at least {MIN_PASSWORD_LENGTH} characters."
    elif not verify_password(current, stored_hash):
        message = "Current password is incorrect."
    else:
        with request.app.state.engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET password_hash = :h WHERE id = :uid"),
                {"h": hash_password(new), "uid": user.id},
            )
        write_audit(
            request.app.state.engine,
            action="user.password_change",
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
            ip=request.client.host if request.client else None,
        )
        # Every session dies with the old password (section 2: DB-backed
        # sessions) - including this one, so the user signs in again.
        expire_sessions_for_user(request.app.state.engine, user.id)
        return render(
            request,
            "me.html",
            context={
                "user": user,
                "email": _profile_email(request, user.id),
                "message": "Password changed.",
            },
        )
    return render(
        request,
        "me.html",
        context={"user": user, "email": _profile_email(request, user.id), "message": message},
    )
