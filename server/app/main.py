"""ASGI application factory and the liveness endpoint (section 15.3.5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from app.api.agent import router as agent_router
from app.api.analyses import router as analyses_router
from app.api.gates import router as gates_router
from app.api.projects import router as projects_router
from app.audit import write_audit
from app.config import Settings, load_settings
from app.csrf import CsrfMiddleware
from app.db import (
    create_database_engine,
    create_session_factory,
    ping_database,
    revoke_session,
)
from app.deps import get_current_user, require_project_token
from app.logging_setup import configure_logging
from app.ratelimit import rate_limiter
from app.security import hash_password, verify_password
from app.session import create_session
from app.session import get_session as get_db_session
from app.web.routes import (
    NotAuthenticated,
    login_page,
    not_authenticated_handler,
    safe_next,
)
from app.web.routes import router as pages_router

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = "<<<CHANGE_ME>>>"

password_hasher = PasswordHasher()


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

    # --- Static assets and Jinja2 pages (phase 4) ---
    application.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    application.state.templates = Jinja2Templates(directory=BASE_DIR / "templates")
    application.add_exception_handler(NotAuthenticated, not_authenticated_handler)

    # --- Session middleware (signed cookie, backed by DB) ---
    application.add_middleware(
        SessionMiddleware,
        secret_key=SECRET_KEY,
        same_site="lax",
        https_only=resolved.cookie_secure,
    )
    application.add_middleware(CsrfMiddleware, secure=resolved.cookie_secure)

    # --- Auth dependencies (shared module; exposed on state for routes) ---
    application.state.get_current_user = get_current_user
    application.state.require_project_token = require_project_token

    # --- Agent API (section 15.2) ---
    application.include_router(agent_router)
    application.include_router(analyses_router)
    application.include_router(gates_router)

    # --- Project settings (section 10) ---
    application.include_router(projects_router)

    # --- Server-rendered pages (phase 4) ---
    application.include_router(pages_router)

    @application.post("/session", status_code=201)
    def login(
        response: Response,
        request: Request,
        form: OAuth2PasswordRequestForm = Depends(),
    ) -> Any:
        """Login and create a session.

        Validates username/password with argon2id, creates a session cookie,
        and returns user info. Rate limiting is applied at the middleware/edge.

        One handler serves both clients: an API call gets JSON (201), while a
        browser form post (``Accept: text/html``) gets a 303 redirect - or the
        login page again with the error. The credentials, rate limiter and
        audit trail are shared; there is no second login path.
        """
        engine = application.state.engine
        client_ip = request.client.host if request.client else "unknown"
        wants_html = "text/html" in request.headers.get("accept", "")
        next_url = safe_next(request.query_params.get("next"))

        try:
            # Rate limiting: check if locked out
            lockout_remaining = rate_limiter.is_locked_out(form.username, client_ip)
            if lockout_remaining is not None:
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Too many failed attempts. Try again in {int(lockout_remaining)} seconds."
                    ),
                )

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
                # Record failure even for unknown users to prevent user enumeration timing
                rate_limiter.record_failure(form.username, client_ip)
                raise HTTPException(status_code=401, detail="Invalid credentials")
            user_id, username, stored_hash, is_active = result
            if not is_active:
                rate_limiter.record_failure(form.username, client_ip)
                raise HTTPException(status_code=401, detail="User account is disabled")

            if not verify_password(form.password, stored_hash):
                rate_limiter.record_failure(form.username, client_ip)
                raise HTTPException(status_code=401, detail="Invalid credentials")

            # Record success and clear rate limit
            rate_limiter.record_success(form.username, client_ip)
            write_audit(
                engine,
                action="login",
                actor_id=user_id,
                target_type="user",
                target_id=user_id,
                ip=client_ip,
            )

            # Create session
            session_token = create_session(engine, user_id)
        except HTTPException as exc:
            if wants_html:
                return login_page(
                    request,
                    next_url=next_url,
                    error=str(exc.detail),
                    status_code=exc.status_code,
                )
            raise

        if wants_html:
            redirect_response = RedirectResponse(url=next_url, status_code=303)
            redirect_response.set_cookie(
                key="wadjet_session",
                value=session_token,
                httponly=True,
                secure=resolved.cookie_secure,
                samesite="lax",
                max_age=7 * 24 * 3600,  # 7 days
            )
            return redirect_response

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
    def logout(request: Request, response: Response) -> Any:
        """Logout and revoke the current session."""
        wants_html = "text/html" in request.headers.get("accept", "")
        # Read session token from cookie
        token = request.cookies.get("wadjet_session")
        actor_id = None
        if token:
            session = get_db_session(application.state.engine, token)
            if session:
                actor_id = session.get("user_id")
            revoke_session(application.state.engine, token)
        write_audit(
            application.state.engine,
            action="logout",
            actor_id=actor_id,
            target_type="user",
            target_id=actor_id,
            ip=request.client.host if request.client else None,
        )
        if wants_html:
            redirect_response = RedirectResponse(url="/login", status_code=303)
            redirect_response.delete_cookie("wadjet_session")
            return redirect_response
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
