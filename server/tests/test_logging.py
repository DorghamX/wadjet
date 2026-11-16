"""No log line may contain a secret (section 15.3.6)."""

from __future__ import annotations

import logging

from app.config import Settings
from app.logging_setup import configure_logging


def test_configured_logging_redacts_secrets(caplog) -> None:
    settings = Settings(
        database_url="postgresql+psycopg://wadjet:db-secret@localhost:5432/wadjet",
        secret_key="session-secret",
        base_url="http://localhost",
    )
    configure_logging(settings)
    with caplog.at_level(logging.INFO):
        logging.getLogger("wadjet.test").info(
            "connecting to postgresql+psycopg://wadjet:db-secret@localhost:5432/wadjet "
            "with session-secret"
        )
    assert "db-secret" not in caplog.text
    assert "session-secret" not in caplog.text
    assert "***" in caplog.text
