"""End-to-end authentication tests: login, logout, /me, rate limit (T1.1)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.ratelimit import rate_limiter
from app.security import hash_password


@pytest.fixture(autouse=True)
def _reset_rate_limiter() -> Iterator[None]:
    """Keep the process-wide rate limiter isolated between tests."""
    rate_limiter.reset()
    yield
    rate_limiter.reset()


def _create_user(engine: Engine, username: str, password: str) -> int:
    with engine.begin() as conn:
        return conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:u, :e, :h, FALSE, TRUE) RETURNING id"
            ),
            {
                "u": username,
                "e": f"{username}@example.test",
                "h": hash_password(password),
            },
        ).scalar_one()


def test_login_success_sets_session_cookie(app: FastAPI, engine: Engine) -> None:
    """A correct password creates a session and answers with the user."""
    _create_user(engine, "alice", "correct-horse")
    with TestClient(app) as client:
        response = client.post("/session", data={"username": "alice", "password": "correct-horse"})
    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "alice"
    assert "wadjet_session" in response.cookies


def test_login_wrong_password_is_401(app: FastAPI, engine: Engine) -> None:
    """A wrong password never opens a session."""
    _create_user(engine, "bob", "correct-horse")
    with TestClient(app) as client:
        response = client.post("/session", data={"username": "bob", "password": "wrong"})
    assert response.status_code == 401
    assert "wadjet_session" not in response.cookies


def test_login_unknown_user_is_401(app: FastAPI) -> None:
    """Unknown users get the same error as wrong passwords."""
    with TestClient(app) as client:
        response = client.post("/session", data={"username": "nobody", "password": "whatever"})
    assert response.status_code == 401


def test_login_rate_limit_locks_out(app: FastAPI, engine: Engine) -> None:
    """After the fifth failure the next attempt is refused with 429."""
    _create_user(engine, "carol", "correct-horse")
    with TestClient(app) as client:
        for _ in range(5):
            response = client.post("/session", data={"username": "carol", "password": "nope"})
            assert response.status_code == 401
        response = client.post("/session", data={"username": "carol", "password": "nope"})
    assert response.status_code == 429


def test_me_requires_authentication(app: FastAPI) -> None:
    """/me without a session is 401."""
    with TestClient(app) as client:
        assert client.get("/me").status_code == 401


def test_me_works_after_login(app: FastAPI, engine: Engine) -> None:
    """/me reads the session cookie and answers with the profile."""
    _create_user(engine, "dave", "correct-horse")
    with TestClient(app) as client:
        client.post("/session", data={"username": "dave", "password": "correct-horse"})
        response = client.get("/me")
    assert response.status_code == 200
    assert response.json()["username"] == "dave"


def test_logout_revokes_the_session(app: FastAPI, engine: Engine) -> None:
    """Logging out kills the session: /me stops working immediately."""
    _create_user(engine, "erin", "correct-horse")
    with TestClient(app) as client:
        client.post("/session", data={"username": "erin", "password": "correct-horse"})
        assert client.get("/me").status_code == 200
        # Fetch a page so the CSRF cookie exists, then log out with the header.
        client.get("/healthz")
        csrf = client.cookies.get("wadjet_csrf")
        response = client.post("/session/logout", headers={"X-CSRF-Token": csrf})
        assert response.status_code == 200
        assert client.get("/me").status_code == 401


def test_me_accepts_bearer_session_token(app: FastAPI, engine: Engine) -> None:
    """API clients may pass the session token as a Bearer token instead."""
    _create_user(engine, "frank", "correct-horse")
    with TestClient(app) as client:
        response = client.post("/session", data={"username": "frank", "password": "correct-horse"})
        token = response.cookies.get("wadjet_session")
        client.cookies.clear()
        me = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "frank"


def test_login_writes_the_audit_log(app: FastAPI, engine: Engine) -> None:
    """A successful login is attributed in the audit log (section 13)."""
    from app.audit import read_audit

    uid = _create_user(engine, "grace", "correct-horse")
    with TestClient(app) as client:
        client.post("/session", data={"username": "grace", "password": "correct-horse"})
    entries = read_audit(engine, action="login", actor_id=uid)
    assert entries, "expected a login audit entry"
    assert entries[0]["action"] == "login"


def test_create_admin_cli_command(app: FastAPI, engine: Engine) -> None:
    """``wadjet-server create-admin`` creates the first admin, refuses a second."""
    from typer.testing import CliRunner

    from app.cli import app as cli_app

    runner = CliRunner()
    # The CLI loads settings from the environment; point it at the test schema.
    url = str(engine.url)
    with engine.begin() as conn:
        has_admin = conn.execute(text("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")).scalar()

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("DATABASE_URL", url)
        mp.setenv("WADJET_SECRET_KEY", "test-secret-key-0123456789abcdef0123456789abcdef")
        mp.setenv("WADJET_BASE_URL", "http://testserver")
        result = runner.invoke(
            cli_app,
            [
                "create-admin",
                "--username",
                "cli-admin",
                "--email",
                "cli-admin@example.test",
                "--password",
                "correct-horse",
            ],
        )

    if has_admin:
        # An administrator already exists: the command must refuse, not overwrite.
        assert result.exit_code == 1, result.output
        with engine.begin() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")).scalar()
        assert count == has_admin
    else:
        assert result.exit_code == 0, result.output
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT is_admin FROM users WHERE username = 'cli-admin'")
            ).first()
        assert row is not None and row[0] is True
