"""Command line interface of the Wadjet server (section 15.3.8)."""

from __future__ import annotations

import sys

import httpx
import typer
import uvicorn
from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.config import ConfigError, Settings, load_settings
from app.db import advisory_lock, create_database_engine, wait_for_database
from app.logging_setup import configure_logging
from app.migrate import upgrade_to_head

app = typer.Typer(
    help="Wadjet quality gate server.",
    no_args_is_help=True,
    add_completion=False,
)

EXIT_CONFIG = 2
EXIT_DATABASE = 1


def _settings_or_exit() -> Settings:
    """Validate configuration; a problem prints one line and exits with code 2."""
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_CONFIG) from None
    configure_logging(settings)
    return settings


def _wait_or_exit(settings: Settings, engine: Engine) -> None:
    """Section 15.3.3: retry until the wait window closes, then exit 1."""
    if wait_for_database(engine, settings.db_wait_seconds, settings.redact):
        return
    print(
        settings.redact(
            f"Database unreachable after {settings.db_wait_seconds} seconds: "
            f"{settings.redacted_database_url()}"
        ),
        file=sys.stderr,
    )
    raise SystemExit(EXIT_DATABASE)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Address to bind."),
    port: int = typer.Option(8080, help="Port to bind."),
    reload: bool = typer.Option(False, "--reload", help="Reload on code changes (development)."),
) -> None:
    """Wait for the database, migrate under a lock, then serve."""
    settings = _settings_or_exit()
    engine = create_database_engine(settings)
    _wait_or_exit(settings, engine)
    if settings.auto_migrate:
        with advisory_lock(engine):
            upgrade_to_head(settings)
    engine.dispose()
    if reload:
        uvicorn.run(
            "app.main:create_app",
            factory=True,
            host=host,
            port=port,
            reload=True,
            log_level=settings.log_level,
        )
    else:
        from app.main import create_app

        uvicorn.run(create_app(settings), host=host, port=port, log_level=settings.log_level)


@app.command()
def migrate() -> None:
    """Run migrations and exit."""
    settings = _settings_or_exit()
    engine = create_database_engine(settings)
    _wait_or_exit(settings, engine)
    with advisory_lock(engine):
        upgrade_to_head(settings)
    engine.dispose()
    print("Migrations applied.")


@app.command()
def check_db() -> None:
    """Connectivity test: exit 0 when the database answers, 1 otherwise."""
    settings = _settings_or_exit()
    engine = create_database_engine(settings)
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SET statement_timeout TO 5000")
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - report any failure, never the credentials
        print(settings.redact(f"Database check failed: {exc}"), file=sys.stderr)
        engine.dispose()
        raise SystemExit(EXIT_DATABASE) from None
    engine.dispose()
    print(f"Database OK: {settings.redacted_database_url()}")


@app.command()
def healthcheck(
    url: str = typer.Option("http://127.0.0.1:8080/healthz", help="Health endpoint to call."),
) -> None:
    """Call the local /healthz endpoint (used as the container healthcheck)."""
    try:
        response = httpx.get(url, timeout=4.0)
    except Exception as exc:  # noqa: BLE001 - any transport error is unhealthy
        print(f"Health check failed: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_DATABASE) from None
    if response.status_code != 200:
        print(f"Health check failed: HTTP {response.status_code}", file=sys.stderr)
        raise SystemExit(EXIT_DATABASE) from None
    print(response.text)


@app.command()
def create_admin(
    username: str = typer.Option(..., help="Admin username."),
    email: str = typer.Option(..., help="Admin email."),
    password: str = typer.Option(..., help="Admin password (will be hashed with argon2id)."),
) -> None:
    """Create the first admin user (run once after database setup)."""
    from app.security import hash_password

    settings = _settings_or_exit()
    engine = create_database_engine(settings)
    _wait_or_exit(settings, engine)

    # Check if any admin already exists
    with engine.begin() as conn:
        result = conn.execute(text("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")).scalar()
    if result and result > 0:
        print("Admin user already exists.", file=sys.stderr)
        engine.dispose()
        raise SystemExit(1)

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
    engine.dispose()
    print(f"Admin user {username} created.")


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()
