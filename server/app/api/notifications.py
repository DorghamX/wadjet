"""Inbox as data (section 12): ``GET /api/v1/notifications`` and
``POST /api/v1/notifications/read``.

The rows are pointers only - ``ref`` names the issue or request the
notification is about - because whatever renders them reads the live
state behind that ref. Marking read takes an optional list of ids; with
no list it means "all of mine", and ids that are not yours change
nothing, exactly as the page's Mark-all button behaves.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from app.deps import get_current_user
from app.notifications import mark_read, notifications_for, unread_count

router = APIRouter()


class NotificationOut(BaseModel):
    """One notification: who, what kind, and what it points at."""

    model_config = ConfigDict(extra="forbid")

    id: int
    type: str
    ref: dict[str, Any]
    read_at: datetime | None = None
    created_at: datetime


class NotificationListOut(BaseModel):
    """A page of the feed, newest first, with the unread count."""

    model_config = ConfigDict(extra="forbid")

    unread: int
    items: list[NotificationOut]


class ReadIn(BaseModel):
    """``POST .../read``: these ids, or every unread one if omitted."""

    model_config = ConfigDict(extra="forbid")

    ids: list[int] | None = None


class ReadOut(BaseModel):
    """How many notifications this call actually marked."""

    model_config = ConfigDict(extra="forbid")

    read: int


def _out(row: dict[str, Any]) -> NotificationOut:
    raw = row["ref"]
    ref = json.loads(raw) if isinstance(raw, str) else (raw or {})
    return NotificationOut(
        id=int(row["id"]),
        type=str(row["type"]),
        ref=ref,
        read_at=row["read_at"],
        created_at=row["created_at"],
    )


@router.get("/api/v1/notifications", response_model=NotificationListOut)
def list_notifications(
    request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> NotificationListOut:
    """This session's notifications, newest first, unread counted."""
    engine = request.app.state.engine
    user_id = int(user["user_id"])
    rows = notifications_for(engine, user_id=user_id)
    return NotificationListOut(
        unread=unread_count(engine, user_id=user_id), items=[_out(row) for row in rows]
    )


@router.post("/api/v1/notifications/read", response_model=ReadOut)
def notifications_read(
    request: Request,
    body: ReadIn,
    user: dict[str, Any] = Depends(get_current_user),
) -> ReadOut:
    """Stamp ``read_at``: the listed ids, or all of this user's."""
    read = mark_read(request.app.state.engine, user_id=int(user["user_id"]), ids=body.ids)
    return ReadOut(read=read)


__all__ = ["router"]
