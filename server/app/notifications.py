"""Notifications (section 4): the pointers behind the inbox.

A notification says only *who to tell*, *what kind*, and *what it is
about* (``ref`` - the issue and request ids). The inbox builds the
sentence from the live rows when it renders, so a request that was
approved, declined or cancelled since reads correctly without anything
rewriting history. Reading a notification stamps ``read_at``; nothing is
ever deleted from here.

``create_notification`` takes a ``Connection``, not an engine, on
purpose: its callers are mid-transaction (a request that fails must not
leave its target a note about it), and the insert belongs to *that*
transaction - one write, one outcome.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from sqlalchemy import Engine, bindparam, text
from sqlalchemy.engine import Connection

#: What a notification may be about. ``mention`` arrives with T5.3, when
#: an @username in a comment starts telling people too.
NOTIFICATION_TYPES = ("request", "mention")

#: How much of the feed one page of the inbox or API shows.
LIMIT = 50


def create_notification(conn: Connection, *, user_id: int, kind: str, ref: dict[str, int]) -> int:
    """Tell one user about one thing, inside the caller's transaction.

    An unknown kind is a programming error, not a user error: it would
    produce a row the inbox cannot render, so it never becomes one.
    """
    if kind not in NOTIFICATION_TYPES:
        raise ValueError(
            f"Unknown notification type {kind!r}; expected one of: {', '.join(NOTIFICATION_TYPES)}"
        )
    new_id = conn.execute(
        text(
            "INSERT INTO notifications (user_id, type, ref) VALUES (:uid, :kind, :ref) RETURNING id"
        ),
        {"uid": user_id, "kind": kind, "ref": json.dumps(ref)},
    ).scalar_one()
    return int(new_id)


def notifications_for(engine: Engine, *, user_id: int, limit: int = LIMIT) -> list[dict[str, Any]]:
    """This user's notifications, newest first, ``ref`` as a dict."""
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT id, type, ref, read_at, created_at FROM notifications "
                    "WHERE user_id = :uid ORDER BY id DESC LIMIT :limit"
                ),
                {"uid": user_id, "limit": limit},
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


def unread_count(engine: Engine, *, user_id: int) -> int:
    """How many of this user's notifications have not been read."""
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT count(*) FROM notifications WHERE user_id = :uid AND read_at IS NULL"),
                {"uid": user_id},
            ).scalar_one()
        )


def mark_read(engine: Engine, *, user_id: int, ids: Sequence[int] | None = None) -> int:
    """Stamp ``read_at`` on this user's notifications; returns how many.

    ``ids=None`` means "all of them" - the inbox's Mark-all button. Ids
    that are not this user's change nothing: you cannot read somebody
    else's mail for them, and the difference must not be observable.
    """
    if ids is not None and not ids:
        return 0
    with engine.begin() as conn:
        sql = "UPDATE notifications SET read_at = now() WHERE user_id = :uid AND read_at IS NULL"
        params: dict[str, Any] = {"uid": user_id}
        if ids is not None:
            sql += " AND id IN :ids"
            params["ids"] = list(ids)
        statement = text(sql)
        if ids is not None:
            statement = statement.bindparams(bindparam("ids", expanding=True))
        return int(conn.execute(statement, params).rowcount)


__all__ = [
    "LIMIT",
    "NOTIFICATION_TYPES",
    "create_notification",
    "notifications_for",
    "mark_read",
    "unread_count",
]
