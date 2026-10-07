"""First-boot admin bootstrap (section 15.3.3), so the README's
documented quickstart is literally true.

``WADJET_ADMIN_USER``/``WADJET_ADMIN_PASSWORD`` exist for the very first
start: ``wadjet-server serve`` creates that admin once, then the pair
does nothing ever again. The tests use a fresh username each run to
avoid colliding with the session-scoped ``admin_user_id`` fixture.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text

from app.cli import _bootstrap_first_admin
from app.config import Settings
from app.security import verify_password

ADMIN = "t61-first-admin"
TAKEN = "t61-taken-user"
PASSWORD = "bootstrap-password-1234"


def _settings(database_url: str, *, admin_user: str | None, admin_password: str | None) -> Settings:
    return Settings(
        database_url=database_url,
        secret_key="k" * 40,
        base_url="http://localhost:8080",
        admin_user=admin_user,
        admin_password=admin_password,
    )


@pytest.fixture()
def clean_bootstrap_usernames(engine: Engine) -> Iterator[None]:
    """Ensure our test usernames don't exist, and clean up after."""
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM users WHERE username IN (:a, :t)"),
            {"a": ADMIN, "t": TAKEN},
        )
    yield
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM users WHERE username IN (:a, :t)"),
            {"a": ADMIN, "t": TAKEN},
        )


def test_the_first_admin_is_created_exactly_once(
    engine: Engine, database_url: str, clean_bootstrap_usernames: None
) -> None:
    """If no admin with this username exists, create one. Idempotent."""
    settings = _settings(database_url, admin_user=ADMIN, admin_password=PASSWORD)
    _bootstrap_first_admin(engine, settings)

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT email, password_hash, is_admin, is_active FROM users WHERE username = :u"),
            {"u": ADMIN},
        ).one()
    assert row.is_admin is True
    assert row.is_active is True
    assert row.email == f"{ADMIN}@localhost"
    assert verify_password(PASSWORD, row.password_hash)

    # The next start finds an admin and changes nothing.
    _bootstrap_first_admin(engine, settings)
    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM users WHERE username = :u"), {"u": ADMIN}
        ).scalar_one()
    assert count == 1


def test_without_the_env_pair_nothing_happens(
    engine: Engine, database_url: str, clean_bootstrap_usernames: None
) -> None:
    """Empty env pair is a no-op; does not create or remove admins."""
    with engine.connect() as conn:
        before = conn.execute(text("SELECT count(*) FROM users WHERE is_admin")).scalar_one()
    _bootstrap_first_admin(engine, _settings(database_url, admin_user=None, admin_password=None))
    with engine.connect() as conn:
        after = conn.execute(text("SELECT count(*) FROM users WHERE is_admin")).scalar_one()
    # The bootstrap should not change the admin count when env pair is absent.
    assert after == before


def test_a_username_taken_by_a_non_admin_is_left_alone(
    engine: Engine,
    database_url: str,
    clean_bootstrap_usernames: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No crash, no elevation: a hint to ``create-admin`` instead."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:u, :e, 'not-a-real-hash', FALSE, TRUE)"
            ),
            {"u": TAKEN, "e": f"{TAKEN}@localhost"},
        )
    _bootstrap_first_admin(
        engine, _settings(database_url, admin_user=TAKEN, admin_password=PASSWORD)
    )

    assert "already taken" in capsys.readouterr().err
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT is_admin, password_hash FROM users WHERE username = :u"),
            {"u": TAKEN},
        ).one()
    assert row.is_admin is False
    assert row.password_hash == "not-a-real-hash"
