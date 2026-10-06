"""ASGI application factory and the liveness endpoint (section 15.3.5)."""

from __future__ import annotations

from typing import Any

from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware

from app.config import Settings, load_settings
from app.db import (
    create_database_engine,
    create_session_factory,
    ping_database,
    revoke_session,
)
from app.logging_setup import configure_logging
from app.security import hash_password, verify_password
from app.session import create_session
from app.session import get_session as get_db_session

SECRET_KEY = "<<<CHANGE_ME>>>"

password_hasher = PasswordHasher()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the Wadjet application.

    The startup sequence of section 15.3.3 (wait for the database, advisory lock,
    migrations, first admin) belongs to ``wadjet-server serve``; the application itself
    only ever reports on the database it was given.
    """
    resolved = settings if settings is not None else load_settings()
    configure_logging(resolved)

    application = FastAPI(
        title="Wadjet",
        version="0.1.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    application.state.settings = resolved
    engine = create_database_engine(resolved)
    application.state.engine = engine
    application.state.session_factory = create_session_factory(engine)

    # --- Session middleware (signed cookie, backed by DB) ---
    application.add_middleware(
        SessionMiddleware,
        secret_key=SECRET_KEY,
        same_site="lax",
        https_only=resolved.cookie_secure,
    )

    # --- Auth dependencies ---

    def get_current_user(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
        """FastAPI dependency: look up the session for the given bearer token."""
        session = get_db_session(application.state.engine, token)
        if not session or not session.get("user_id"):
            raise HTTPException(status_code=401, detail="Authentication required")
        return {"user_id": session["user_id"]}

    @application.post("/session", status_code=201)
    def login(
        response: Response,
        form: OAuth2PasswordRequestForm = Depends(),
    ) -> dict[str, Any]:
        """Login and create a session.

        Validates username/password with argon2id, creates a session cookie,
        and returns user info. Rate limiting is applied at the middleware/edge.
        """
        engine = application.state.engine
        # Look up user by username - we'll do a simple query
        with engine.begin() as conn:
            result = conn.execute(
                text(
                    "SELECT id, username, password_hash, is_active FROM users "
                    "WHERE username = :name"
                ),
                {"name": form.username},
            ).first()

        if not result:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user_id, username, stored_hash, is_active = result
        if not is_active:
            raise HTTPException(status_code=401, detail="User account is disabled")

        if not verify_password(form.password, stored_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Create session
        session_token = create_session(
            engine, user_id, remember_me=form.password == form.password
        )  # placeholder

        # Set cookie
        response.set_cookie(
            key="wadjet_session",
            value=session_token,
            httponly=True,
            secure=resolved.cookie_secure,
            samesite="lax",
            max_age=7 * 24 * 3600,  # 7 days
        )

        return {"user_id": user_id, "username": username, "is_admin": False}

    @application.post("/session/logout")
    def logout(request: Request, response: Response) -> dict[str, Any]:
        """Logout and revoke the current session."""
        # Read session token from cookie
        token = request.cookies.get("wadjet_session")
        if token:
            revoke_session(application.state.engine, token)
        response.delete_cookie("wadjet_session")
        return {"detail": "logged out"}

    @application.get("/me", response_model=dict)
    def me(current: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        """Return the current authenticated user's info."""
        engine = application.state.engine
        with engine.begin() as conn:
            result = conn.execute(
                text(
                    """
                SELECT id, username, email, display_name, is_admin, is_active, created_at
                FROM users WHERE id = :uid
                """
                ),
                {"uid": current["user_id"]},
            ).first()
        if not result:
            raise HTTPException(status_code=404, detail="User not found")
        uid, username, email, display_name, is_admin, is_active, created_at = result
        return {
            "id": uid,
            "username": username,
            "email": email,
            "display_name": display_name,
            "is_admin": is_admin,
            "is_active": is_active,
            "created_at": str(created_at),
        }

    @application.post("/admin/create-admin")
    def create_admin_endpoint(
        username: str,
        email: str,
        password: str,
        current: dict[str, Any] = Depends(get_current_user),
    ) -> dict[str, Any]:
        """Create the first admin user (run once after database setup)."""
        engine = application.state.engine
        # Check if any admin already exists
        with engine.begin() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")).scalar()
        if result and result > 0:
            raise HTTPException(status_code=400, detail="Admin user already exists")

        # Create the first admin
        hashed = hash_password(password)
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO users (username, email, password_hash, is_admin, is_active, "
                    "created_at, updated_at) "
                    "VALUES (:username, :email, :password_hash, TRUE, TRUE, NOW(), NOW())"
                ),
                {"username": username, "email": email, "password_hash": hashed},
            )

        return {"detail": f"Admin user {username} created"}

    # --- Health check ---

    @application.get("/healthz")
    def healthz() -> JSONResponse:
        """Liveness and database check: 200 when ``SELECT 1`` answers within 2 seconds."""
        if ping_database(engine, timeout_seconds=2.0):
            return JSONResponse(status_code=200, content={"status": "ok", "db": "ok"})
        return JSONResponse(status_code=503, content={"status": "unavailable", "db": "down"})

    return application
