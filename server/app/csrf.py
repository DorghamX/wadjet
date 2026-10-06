"""CSRF protection (section 13).

A CSRF token on every state-changing form and HTMX request, using the
double-submit-cookie pattern: the server sets a readable ``wadjet_csrf``
cookie, the client echoes it back in the ``X-CSRF-Token`` header, and unsafe
requests are rejected when the two do not match.

Requests that carry no cookies at all (API clients using ``Authorization``,
health checks) are not subject to the check: a cross-site attacker cannot
forge a request without the browser attaching the victim's cookies, and those
clients have no ambient authority to protect.
"""

from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

CSRF_COOKIE = "wadjet_csrf"
CSRF_HEADER = "X-CSRF-Token"

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

#: Paths exempt from CSRF: agent endpoints authenticate with a Bearer token
#: (no ambient authority) and documentation endpoints never mutate state.
EXEMPT_PREFIXES = (
    "/api/v1/agent",
    "/api/v1/analyses",
    "/healthz",
    "/api/openapi.json",
    "/api/docs",
    "/api/redoc",
)


class CsrfMiddleware(BaseHTTPMiddleware):
    """Issue a CSRF cookie on safe requests; enforce it on unsafe ones."""

    def __init__(self, app: ASGIApp, *, secure: bool = False) -> None:
        super().__init__(app)
        self.secure = secure

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        csrf_cookie = request.cookies.get(CSRF_COOKIE)

        if request.method in SAFE_METHODS:
            response = await call_next(request)
            if not csrf_cookie:
                response.set_cookie(
                    CSRF_COOKIE,
                    secrets.token_urlsafe(32),
                    httponly=False,  # the page and HTMX must read it
                    secure=self.secure,
                    samesite="lax",
                    max_age=7 * 24 * 3600,
                )
            return response

        # Unsafe method from here on.
        if any(request.url.path.startswith(p) for p in EXEMPT_PREFIXES):
            return await call_next(request)

        has_cookies = bool(request.cookies)
        if not has_cookies:
            # No ambient authority to protect (plain API client).
            return await call_next(request)

        supplied = request.headers.get(CSRF_HEADER)
        if not supplied or not csrf_cookie or not secrets.compare_digest(supplied, csrf_cookie):
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or invalid"},
            )

        return await call_next(request)
