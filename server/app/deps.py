"""Shared FastAPI dependencies (sections 7, 13, 15).

Both dependencies read the engine from ``app.state`` so they work from any
module - the app factory in ``main.py`` and the API routers alike.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.session import get_session
from app.tokens import update_last_used, validate_token

bearer = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> dict[str, Any]:
    """Resolve the current user.

    Auth: session cookie for the UI (section 15), with a Bearer session
    token accepted as a fallback for API clients.
    """
    token = credentials.credentials if credentials is not None else None
    if not token:
        token = request.cookies.get("wadjet_session")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    session = get_session(request.app.state.engine, token)
    if not session or not session.get("user_id"):
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"user_id": session["user_id"], "session_token": token}


def require_project_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> dict[str, Any]:
    """Authenticate an agent endpoint with a Bearer project token (section 13).

    32 random bytes, stored as a SHA-256 hash, constant-time compared;
    refreshes ``last_used_at`` and returns the token's data so a route can
    bind it to its own project.
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Project token required")
    engine = request.app.state.engine
    token_data = validate_token(engine, credentials.credentials)
    if token_data is None:
        raise HTTPException(status_code=401, detail="Invalid, expired or revoked token")
    update_last_used(engine, token_data["id"])
    return token_data
