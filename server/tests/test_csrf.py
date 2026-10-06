"""CSRF middleware tests (section 13, T1.1)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_safe_request_gets_a_csrf_cookie(app: FastAPI) -> None:
    """A first GET issues the readable double-submit cookie."""
    with TestClient(app) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert "wadjet_csrf" in response.cookies
    # Not HttpOnly: the page and HTMX must be able to read it.
    cookie_header = response.headers.get_list("set-cookie")
    csrf_line = next(c for c in cookie_header if c.startswith("wadjet_csrf="))
    assert "httponly" not in csrf_line.lower()


def test_unsafe_request_without_cookies_reaches_the_endpoint(app: FastAPI) -> None:
    """A cookie-less API client (no ambient authority) is not blocked."""
    with TestClient(app) as client:
        response = client.post("/session", data={"username": "nobody", "password": "wrong"})
    # Reaches the login route: 401 (bad credentials), never 403.
    assert response.status_code == 401


def test_unsafe_request_with_cookie_but_no_header_is_403(app: FastAPI) -> None:
    """A cookie-carrying request that does not echo the token is refused."""
    with TestClient(app) as client:
        client.get("/healthz")  # sets wadjet_csrf
        response = client.post("/session", data={"username": "nobody", "password": "wrong"})
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_unsafe_request_with_wrong_header_is_403(app: FastAPI) -> None:
    """A mismatched token is refused."""
    with TestClient(app) as client:
        client.get("/healthz")
        response = client.post(
            "/session",
            data={"username": "nobody", "password": "wrong"},
            headers={"X-CSRF-Token": "not-the-right-token"},
        )
    assert response.status_code == 403


def test_unsafe_request_with_matching_header_reaches_the_endpoint(
    app: FastAPI,
) -> None:
    """Echoing the cookie value in the header passes the check."""
    with TestClient(app) as client:
        client.get("/healthz")
        csrf = client.cookies.get("wadjet_csrf")
        response = client.post(
            "/session",
            data={"username": "nobody", "password": "wrong"},
            headers={"X-CSRF-Token": csrf},
        )
    assert response.status_code == 401  # past CSRF, rejected for credentials


def test_agent_endpoints_are_exempt(app: FastAPI) -> None:
    """Bearer-token agent endpoints carry no ambient authority: exempt."""
    with TestClient(app) as client:
        client.get("/healthz")
        response = client.post("/api/v1/analyses", json={})
    # Exempt from CSRF: the request falls through to routing (404, not 403).
    assert response.status_code == 404
