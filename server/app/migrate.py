"""Alembic helpers. Migrations are forward-only (section 15.3.7)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from app.config import Settings

SERVER_DIR = Path(__file__).resolve().parent.parent


def alembic_config(database_url: str) -> Config:
    """Build an Alembic config for ``database_url`` (which may carry query options)."""
    cfg = Config(str(SERVER_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(SERVER_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return cfg


def upgrade_url(database_url: str) -> None:
    """Apply every migration to ``database_url``. Callers hold the advisory lock."""
    command.upgrade(alembic_config(database_url), "head")


def upgrade_to_head(settings: Settings) -> None:
    """Apply every migration. Callers hold the advisory lock."""
    upgrade_url(settings.database_url)
