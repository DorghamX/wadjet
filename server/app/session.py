"""Session management for the Wadjet server.

Uses server-side sessions stored in the DB (section 2).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Engine, text


def create_session(
    engine: Engine,
    user_id: int,
    remember_me: bool = False,
    max_age_days: int = 30,
) -> str:
    """Create a new server-side session and return the session token.

    Sessions are stored in the database with a UUID token, user_id, created_at,
    and expires_at. The token is an HttpOnly, Secure, SameSite=Lax cookie.
    """
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=max_age_days) if remember_me else now + timedelta(days=7)

    session_token = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                """
            INSERT INTO sessions (token, user_id, created_at, expires_at, revoked_at)
            VALUES (:token, :user_id, :created_at, :expires_at, NULL)
            """
            ),
            {
                "token": session_token,
                "user_id": user_id,
                "created_at": now,
                "expires_at": expires,
            },
        )

    return session_token


def get_session(engine: Engine, token: str) -> dict[str, Any] | None:
    """Look up a session by token and return its data if valid and not expired."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                """
            SELECT user_id, created_at, expires_at, revoked_at
            FROM sessions
            WHERE token = :token
            """
            ),
            {"token": token},
        ).first()

    if not result:
        return None

    user_id, created_at, expires_at, revoked_at = result
    if revoked_at is not None:
        return None
    if expires_at and datetime.now(timezone.utc) > expires_at:
        return None

    return {"user_id": user_id, "created_at": created_at, "expires_at": expires_at}


def revoke_session(engine: Engine, token: str) -> bool:
    """Revoke (delete) a session by token. Returns True if a session was revoked."""
    with engine.begin() as conn:
        result = conn.execute(
            text("DELETE FROM sessions WHERE token = :token RETURNING 1"),
            {"token": token},
        ).first()
    return result is not None


def expire_sessions_for_user(engine: Engine, user_id: int) -> int:
    """Expire all active sessions for a given user. Returns number of sessions expired."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                """
            UPDATE sessions
            SET revoked_at = NOW()
            WHERE user_id = :user_id AND revoked_at IS NULL
            """
            ),
            {"user_id": user_id},
        )
    return result.rowcount
