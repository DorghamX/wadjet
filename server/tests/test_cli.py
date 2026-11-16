"""CLI acceptance tests for T0.2: check-db, healthcheck and migrate."""

from __future__ import annotations

import pytest
from sqlalchemy.engine import make_url
from typer.testing import CliRunner

from app.cli import app as cli_app

runner = CliRunner()

SECRET = "never-show-this-password"


def _output(result: object) -> str:
    """stdout and stderr of a click result, whichever layout the click version uses."""
    output = getattr(result, "output", "") or ""
    try:
        stderr = getattr(result, "stderr", "") or ""
    except ValueError:  # pragma: no cover - click < 8.2 mixes the streams
        stderr = ""
    return output + stderr


def _env(database_url: str) -> dict[str, str]:
    return {
        "DATABASE_URL": database_url,
        "WADJET_SECRET_KEY": "k" * 40,
        "WADJET_BASE_URL": "http://localhost:8080",
        "WADJET_COOKIE_SECURE": "false",
    }


def test_check_db_exits_zero_with_a_good_url(database_url: str) -> None:
    result = runner.invoke(cli_app, ["check-db"], env=_env(database_url))
    assert result.exit_code == 0, _output(result)
    assert "Database OK:" in _output(result)


def test_check_db_exits_one_and_redacts_a_wrong_password(database_url: str) -> None:
    bad = make_url(database_url).set(
        username="wadjet_nobody_ever",
        password=SECRET,
    )
    env = _env(bad.render_as_string(hide_password=False))
    result = runner.invoke(cli_app, ["check-db"], env=env)
    assert result.exit_code == 1, _output(result)
    assert SECRET not in _output(result)
    assert "Database check failed:" in _output(result)


def test_check_db_exits_two_when_the_url_is_missing() -> None:
    env = _env("postgresql+psycopg://wadjet:dev@localhost:5432/wadjet")
    env["DATABASE_URL"] = ""
    result = runner.invoke(cli_app, ["check-db"], env=env)
    assert result.exit_code == 2
    assert "Configuration error: DATABASE_URL is not set" in _output(result)


def test_serve_exits_two_when_the_url_is_malformed() -> None:
    env = _env("not-a-url")
    result = runner.invoke(cli_app, ["serve"], env=env)
    assert result.exit_code == 2
    assert "Configuration error:" in _output(result)


def test_migrate_applies_migrations(database_url: str) -> None:
    result = runner.invoke(cli_app, ["migrate"], env=_env(database_url))
    assert result.exit_code == 0, _output(result)
    assert "Migrations applied." in _output(result)


def test_healthcheck_exits_zero_against_a_live_server(live_server: str) -> None:
    result = runner.invoke(cli_app, ["healthcheck", "--url", f"{live_server}/healthz"])
    assert result.exit_code == 0, _output(result)


def test_healthcheck_exits_one_when_the_server_is_down() -> None:
    result = runner.invoke(cli_app, ["healthcheck", "--url", "http://127.0.0.1:59991/healthz"])
    assert result.exit_code == 1


@pytest.mark.parametrize("seconds", [0, 1])
def test_wait_for_database_gives_up_and_never_prints_the_password(seconds: int, caplog) -> None:
    from app.config import Settings
    from app.db import create_database_engine, wait_for_database

    url = f"postgresql+psycopg://wadjet:{SECRET}@127.0.0.1:59990/wadjet"
    settings = Settings(database_url=url, secret_key="k" * 40, base_url="http://localhost")
    engine = create_database_engine(settings)
    with caplog.at_level("DEBUG"):
        assert wait_for_database(engine, seconds, settings.redact) is False
    engine.dispose()
    assert SECRET not in caplog.text


def test_seed_demo_seeds_once_then_skips(database_url: str) -> None:
    first = runner.invoke(cli_app, ["seed-demo"], env=_env(database_url))
    assert first.exit_code == 0, _output(first)
    out = _output(first)
    assert "Demo data seeded:" in out
    assert "demo-admin" in out and "demo-password" in out

    second = runner.invoke(cli_app, ["seed-demo"], env=_env(database_url))
    assert second.exit_code == 0, _output(second)
    assert "already present - skipped" in _output(second)
