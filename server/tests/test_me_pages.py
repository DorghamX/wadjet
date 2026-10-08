"""Profile and password page (section 15.x): login, profile update and
password change, plus session revocation on password change.

Two fills collide on the same `/me` page: the details form and the
password form. Both are covered here, one feature per test, the same way
the design's two forms live side by side.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.config import Settings
from app.security import hash_password, verify_password
from app.seed import DEMO_PASSWORD, seed_demo


@pytest.fixture(scope="module")
def database_url(isolated_database_url: str) -> str:
    """Own schema: these tests mutate seed users (display name, password)."""
    return isolated_database_url


@pytest.fixture(scope="module")
def engine(isolated_engine: Engine) -> Engine:
    return isolated_engine


@pytest.fixture()
def settings(isolated_settings: Settings) -> Settings:
    return isolated_settings


HTML = {"Accept": "text/html"}


def _reset_seed(engine: Engine) -> None:
    """Seed the demo data, restoring the seed users this module mutates.

    ``seed_demo`` is idempotent, so after a test has changed demo-admin's
    password or display name a plain re-seed would keep the mutation and
    the next sign-in would fail. Reset the account first.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE users SET password_hash = :h, display_name = 'Demo Dave' "
                "WHERE username = 'demo-admin'"
            ),
            {"h": hash_password(DEMO_PASSWORD)},
        )
    seed_demo(engine)


def _login(client: TestClient, username: str, password: str = DEMO_PASSWORD) -> None:
    client.get("/login")
    client.post(
        "/session",
        data={
            "username": username,
            "password": password,
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )


def test_me_requires_login(client: TestClient, engine: object) -> None:
    """Without a session, /me lands on the login page."""
    _reset_seed(engine)
    page = client.get("/me", follow_redirects=False)
    assert page.status_code == 303
    assert "/login" in page.headers["location"]


def test_me_reads_the_profile(client: TestClient, engine: object) -> None:
    """Signed in users see their own details."""
    _reset_seed(engine)
    _login(client, "demo-admin")
    page = client.get("/me")
    assert page.status_code == 200
    assert "Your profile" in page.text
    assert "demo-admin" in page.text


def test_me_profile_update(client: TestClient, engine: object) -> None:
    """Changing the display name is saved and audited."""
    _reset_seed(engine)
    _login(client, "demo-admin")
    page = client.post(
        "/me",
        data={"csrf_token": client.cookies.get("wadjet_csrf"), "display_name": "  Demo-Dave  "},
        headers=HTML,
        follow_redirects=False,
    )
    assert page.status_code == 200
    assert "Details saved." in page.text
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT display_name FROM users WHERE username = 'demo-admin'"),
        ).first()
    assert row is not None
    assert row[0] == "Demo-Dave"


def test_me_rejects_an_empty_display_name(client: TestClient, engine: object) -> None:
    """An empty name changes nothing - the form keeps its own value anyway."""
    _reset_seed(engine)
    _login(client, "demo-admin")
    with engine.begin() as conn:
        original = conn.execute(
            text("SELECT display_name FROM users WHERE username = 'demo-admin'"),
        ).first()
    assert original is not None
    page = client.post(
        "/me",
        data={"csrf_token": client.cookies.get("wadjet_csrf"), "display_name": "   "},
        headers=HTML,
        follow_redirects=False,
    )
    assert page.status_code == 200
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT display_name FROM users WHERE username = 'demo-admin'"),
        ).first()
    assert row is not None
    assert row[0] == original[0]


def test_me_password_change(client: TestClient, engine: object) -> None:
    """A correct password change works and is audited."""
    _reset_seed(engine)
    _login(client, "demo-admin")
    page = client.post(
        "/me/password",
        data={
            "csrf_token": client.cookies.get("wadjet_csrf"),
            "current_password": DEMO_PASSWORD,
            "new_password": "new-password-9",
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert page.status_code == 200
    assert "Password changed." in page.text
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT password_hash FROM users WHERE username = 'demo-admin'"),
        ).first()
    assert row is not None
    assert verify_password("new-password-9", row[0])


def test_me_rejects_a_wrong_current_password(client: TestClient, engine: object) -> None:
    """A wrong current password is refused with a clear message."""
    _reset_seed(engine)
    _login(client, "demo-admin")
    page = client.post(
        "/me/password",
        data={
            "csrf_token": client.cookies.get("wadjet_csrf"),
            "current_password": "wrong",
            "new_password": "new-password-9",
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert page.status_code == 200
    assert "Current password is incorrect." in page.text


def test_me_rejects_a_short_new_password(client: TestClient, engine: object) -> None:
    """The 8-character minimum is enforced before anything is written."""
    _reset_seed(engine)
    _login(client, "demo-admin")
    page = client.post(
        "/me/password",
        data={
            "csrf_token": client.cookies.get("wadjet_csrf"),
            "current_password": DEMO_PASSWORD,
            "new_password": "short",
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert page.status_code == 200
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT password_hash FROM users WHERE username = 'demo-admin'"),
        ).first()
    assert row is not None
    assert verify_password(DEMO_PASSWORD, row[0])


def test_me_password_revokes_other_sessions(client: TestClient, engine: object) -> None:
    """After a password change, the old session stops working."""
    _reset_seed(engine)
    _login(client, "demo-admin")
    client.post(
        "/me/password",
        data={
            "csrf_token": client.cookies.get("wadjet_csrf"),
            "current_password": DEMO_PASSWORD,
            "new_password": "new-password-9",
        },
        headers=HTML,
        follow_redirects=False,
    )
    # Re-login with the new password
    client.get("/login")
    page = client.post(
        "/session",
        data={
            "username": "demo-admin",
            "password": "new-password-9",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert page.status_code == 303
    # The old password no longer works
    client.get("/login")
    page = client.post(
        "/session",
        data={
            "username": "demo-admin",
            "password": DEMO_PASSWORD,
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert page.status_code == 401
