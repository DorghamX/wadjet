"""Server-rendered pages (sections 15.4, 15.6; phase 4 of the build guide).

Page auth differs from API auth: a browser without a session gets a
redirect to the login page instead of a 401 body, so every page route
depends on ``require_page_user`` and lets ``NotAuthenticated`` travel to
the handler registered in ``create_app``.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import text
from starlette.templating import Jinja2Templates

from app.session import get_session

#: The session cookie the whole app (API and pages) shares.
SESSION_COOKIE = "wadjet_session"

#: Where a login-less visit ends up when no explicit ``next`` was given.
DEFAULT_NEXT = "/"

router = APIRouter(include_in_schema=False)


@dataclass(frozen=True)
class PageUser:
    """The fields a layout needs to render a signed-in page."""

    id: int
    username: str
    display_name: str | None
    is_admin: bool


class NotAuthenticated(Exception):
    """No valid session for a page; the handler redirects to ``/login``."""

    def __init__(self, next_url: str) -> None:
        super().__init__(next_url)
        self.next_url = next_url


def safe_next(url: str | None) -> str:
    """Accept only local paths: no scheme, no protocol-relative ``//host``."""
    if url and url.startswith("/") and not url.startswith("//") and "\\" not in url:
        return url
    return DEFAULT_NEXT


def not_authenticated_handler(request: Request, exc: Exception) -> Response:
    """Send a browser without a session to the login page (303)."""
    if not isinstance(exc, NotAuthenticated):  # pragma: no cover - FastAPI contract
        raise exc
    target = f"/login?next={quote(safe_next(exc.next_url), safe='')}"
    return RedirectResponse(url=target, status_code=303)


def load_page_user(request: Request) -> PageUser | None:
    """The signed-in user, or ``None`` when there is no live session.

    Unlike ``get_current_user`` this never raises: pages need to know
    "anonymous" as a state (the login page renders for it).
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    session = get_session(request.app.state.engine, token)
    if not session or not session.get("user_id"):
        return None
    with request.app.state.engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT id, username, display_name, is_admin, is_active FROM users WHERE id = :uid"
            ),
            {"uid": session["user_id"]},
        ).first()
    if not row or not row[4]:
        return None
    return PageUser(
        id=int(row[0]),
        username=str(row[1]),
        display_name=row[2],
        is_admin=bool(row[3]),
    )


def require_page_user(request: Request) -> PageUser:
    """Dependency for pages: signed in, or redirect to ``/login?next=...``."""
    user = load_page_user(request)
    if user is None:
        next_url = request.url.path
        if request.url.query:
            next_url += f"?{request.url.query}"
        raise NotAuthenticated(next_url)
    return user


def render(
    request: Request,
    name: str,
    *,
    context: dict[str, object] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """Render a page inside the base layout (Jinja2 autoescapes everything)."""
    templates: Jinja2Templates = request.app.state.templates
    ctx: dict[str, object] = dict(context or {})
    return templates.TemplateResponse(request, name, ctx, status_code)


def login_page(
    request: Request,
    *,
    next_url: str = DEFAULT_NEXT,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """The sign-in form, re-rendered with ``error`` after a failed attempt."""
    return render(
        request,
        "login.html",
        context={"next_url": safe_next(next_url), "error": error},
        status_code=status_code,
    )


@router.get("/login")
def login_form(request: Request) -> Response:
    """The sign-in page: redirect away when already signed in."""
    next_url = safe_next(request.query_params.get("next"))
    if load_page_user(request) is not None:
        return RedirectResponse(url=next_url, status_code=303)
    return login_page(request, next_url=next_url)


@router.get("/")
def home(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """Home: the base layout with the brand hero (the projects list lands in T4.2)."""
    return render(request, "home.html", context={"user": user, "nav": None})
