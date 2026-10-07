"""Base layout, theme, brand assets and login (phase 4, T4.1).

The design contract is ``wadjet-design.html``: tokens, top bar, the mark
generated from the ``#lg``/``#wm`` symbols, and a word as well as a color
for every status.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.security import hash_password
from app.web.routes import safe_next

ADMIN = {"Accept": "text/html"}


def _signup(
    engine: Engine, username: str, *, display_name: str | None = None, is_admin: bool = False
) -> str:
    """Create a user with a known password and return that password."""
    password = f"pw-{username}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, display_name, "
                "is_admin, is_active) "
                "VALUES (:u, :e, :h, :d, :admin, TRUE)"
            ),
            {
                "u": username,
                "e": f"{username}@example.test",
                "h": hash_password(password),
                "d": display_name,
                "admin": is_admin,
            },
        )
    return password


def _login_html(client: TestClient, username: str, password: str, next_url: str = "/") -> Any:
    """Log in the way the browser form does: html Accept + hidden csrf field."""
    if "wadjet_csrf" not in client.cookies:
        client.get("/login")
    return client.post(
        f"/session?next={next_url}",
        data={
            "username": username,
            "password": password,
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=ADMIN,
        follow_redirects=False,
    )


def test_anonymous_home_redirects_to_login(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/login")
    assert "next=" in location


def test_login_page_renders_form_brand_and_csrf(client: TestClient) -> None:
    response = client.get("/login?next=%2Fprojects")
    assert response.status_code == 200
    body = response.text
    # Form, exactly as a browser needs it (the next path rides in the query).
    assert 'action="/session?next=/projects"' in body
    assert 'name="username"' in body
    assert 'name="password"' in body
    assert 'type="password"' in body
    # The hidden CSRF field carries the double-submit cookie value.
    csrf = client.cookies.get("wadjet_csrf")
    assert csrf
    assert f'name="csrf_token" value="{csrf}"' in body
    # Design assets: stylesheet, the #lg symbol and the favicon link.
    assert "/static/css/wadjet.css" in body
    assert 'id="lg"' in body
    assert "/static/favicon.svg" in body
    # Anonymous pages have no app chrome.
    assert 'class="topbar"' not in body
    assert "Log out" not in body


def test_static_assets_carry_the_design_tokens(client: TestClient) -> None:
    css = client.get("/static/css/wadjet.css")
    assert css.status_code == 200
    assert "--acc:#146fde" in css.text  # iris blue, light
    assert "--acc:#5ea1ff" in css.text  # iris blue, dark
    assert '[data-theme="dark"]' in css.text  # explicit dark choice
    assert "IBM Plex Sans" in css.text
    assert ".topbar" in css.text

    favicon = client.get("/static/favicon.svg")
    assert favicon.status_code == 200
    assert "image/svg" in favicon.headers["content-type"]
    assert 'viewBox="16 26 341 259"' in favicon.text

    # Brand files are generated from the #lg/#wm symbols with literal colors.
    mark = client.get("/static/brand/mark.svg")
    logo = client.get("/static/brand/wadjet.svg")
    assert mark.status_code == logo.status_code == 200
    assert "#e0b567" in mark.text and "var(--" not in mark.text
    assert 'viewBox="16 26 963 259"' in logo.text
    assert "#146fde" in logo.text and "#e0b567" in logo.text


def test_html_login_redirects_home_and_renders_the_shell(
    client: TestClient, engine: Engine
) -> None:
    password = _signup(engine, "shelluser")
    response = _login_html(client, "shelluser", password)
    assert response.status_code == 303
    assert response.headers["location"] == "/"

    home = client.get("/")
    assert home.status_code == 200
    body = home.text
    # T4.2: "/" is the projects list, not a hero stub.
    assert "0 projects" in body
    assert "No projects yet" in body
    assert "shelluser" in body  # the signed-in name in the top bar
    # Top bar with the nav and the shell pieces from the design.
    assert 'class="topbar"' in body
    assert 'href="/projects"' in body
    assert 'href="/gates"' in body
    assert 'href="/inbox"' in body
    assert 'href="/admin"' not in body  # not an admin: no Admin link
    assert 'id="theme-toggle"' in body
    assert 'aria-label="Switch between light and dark theme"' in body
    assert 'class="skip" href="#main"' in body
    assert '<main id="main" class="wrap">' in body
    # Brand hero and the theme bootstrap.
    assert 'id="wm"' in body
    assert 'localStorage.getItem("wadjet-theme")' in body
    assert 'action="/session/logout"' in body


def test_admin_link_only_for_admins(client: TestClient, engine: Engine) -> None:
    password = _signup(engine, "shelladmin", is_admin=True)
    _login_html(client, "shelladmin", password)
    home = client.get("/")
    assert home.status_code == 200
    assert 'href="/admin"' in home.text


def test_login_failure_renders_the_form_with_the_error(client: TestClient, engine: Engine) -> None:
    _signup(engine, "shellbad")
    client.get("/login")  # issues the csrf cookie
    response = client.post(
        "/session?next=%2F",
        data={
            "username": "shellbad",
            "password": "not-it",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=ADMIN,
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert "Sign-in failed" in response.text
    assert "Invalid credentials" in response.text
    assert 'class="topbar"' not in response.text
    # Still anonymous: protected pages keep redirecting.
    assert client.get("/", follow_redirects=False).status_code == 303


def test_login_when_already_signed_in_redirects(client: TestClient, engine: Engine) -> None:
    password = _signup(engine, "shelltwice")
    _login_html(client, "shelltwice", password)
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_logout_form_revokes_the_session(client: TestClient, engine: Engine) -> None:
    password = _signup(engine, "shellout")
    _login_html(client, "shellout", password)
    assert client.get("/").status_code == 200

    response = client.post(
        "/session/logout",
        data={"csrf_token": client.cookies.get("wadjet_csrf")},
        headers=ADMIN,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    # The session is gone, not merely the cookie.
    assert client.get("/", follow_redirects=False).status_code == 303


def test_display_name_is_escaped_everywhere(client: TestClient, engine: Engine) -> None:
    """Phase acceptance: untrusted text never reaches the browser as markup."""
    password = _signup(engine, "shellxss", display_name="<script>alert('xss')</script>")
    _login_html(client, "shellxss", password)
    body = client.get("/").text
    assert "<script>alert" not in body
    assert "&lt;script&gt;alert" in body


def test_safe_next_only_accepts_local_paths() -> None:
    assert safe_next("/projects/issues?x=1") == "/projects/issues?x=1"
    assert safe_next(None) == "/"
    assert safe_next("") == "/"
    assert safe_next("//evil.example") == "/"
    assert safe_next("https://evil.example") == "/"
    assert safe_next("\\\\evil") == "/"
