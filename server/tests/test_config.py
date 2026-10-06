"""Configuration validation and secret redaction (section 15.3.1 and 15.3.6)."""

from __future__ import annotations

import pytest

from app.config import (
    ConfigError,
    Settings,
    load_settings,
    normalize_database_url,
    redact_text,
    redact_url,
)

GOOD_ENV = {
    "DATABASE_URL": "postgresql+psycopg://wadjet:super-secret@localhost:5432/wadjet",
    "WADJET_SECRET_KEY": "k" * 40,
    "WADJET_BASE_URL": "https://wadjet.example.com",
}


def test_valid_environment_loads() -> None:
    settings = load_settings(GOOD_ENV)
    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.base_url == "https://wadjet.example.com"
    assert settings.db_pool_size == 5
    assert settings.auto_migrate is True
    assert settings.cookie_secure is True


def test_missing_database_url_is_one_clear_line() -> None:
    env = dict(GOOD_ENV)
    del env["DATABASE_URL"]
    with pytest.raises(ConfigError) as excinfo:
        load_settings(env)
    message = str(excinfo.value)
    assert message.startswith("DATABASE_URL is not set")
    assert "\n" not in message


def test_malformed_database_url_rejected() -> None:
    env = dict(GOOD_ENV)
    env["DATABASE_URL"] = "mysql://user:pass@host/db"
    with pytest.raises(ConfigError, match="DATABASE_URL must start with"):
        load_settings(env)


def test_postgres_and_postgresql_schemes_are_normalized() -> None:
    assert normalize_database_url("postgres://u:p@h/db").startswith("postgresql+psycopg://")
    assert normalize_database_url("postgresql://u:p@h/db").startswith("postgresql+psycopg://")


def test_database_url_file_is_read_when_set(tmp_path) -> None:
    path = tmp_path / "db.url"
    path.write_text("postgresql+psycopg://wadjet:from-file@localhost:5432/wadjet\n")
    env = dict(GOOD_ENV)
    del env["DATABASE_URL"]
    env["DATABASE_URL_FILE"] = str(path)
    settings = load_settings(env)
    assert "from-file" in settings.database_url


def test_secret_key_length_is_enforced() -> None:
    env = dict(GOOD_ENV)
    env["WADJET_SECRET_KEY"] = "short"
    with pytest.raises(ConfigError, match="at least 32"):
        load_settings(env)


def test_admin_credentials_must_come_in_pairs() -> None:
    env = dict(GOOD_ENV)
    env["WADJET_ADMIN_USER"] = "admin"
    with pytest.raises(ConfigError, match="must be set together"):
        load_settings(env)


def test_unknown_log_level_rejected() -> None:
    env = dict(GOOD_ENV)
    env["WADJET_LOG_LEVEL"] = "chatty"
    with pytest.raises(ConfigError, match="WADJET_LOG_LEVEL"):
        load_settings(env)


def test_redact_text_removes_passwords_and_known_secrets() -> None:
    text = "failed: postgresql+psycopg://wadjet:super-secret@localhost:5432/wadjet using key kkkk"
    cleaned = redact_text(text, ["kkkk", "super-secret"])
    assert "super-secret" not in cleaned
    assert "kkkk" not in cleaned
    assert "wadjet:***@localhost" in cleaned


def test_settings_redact_covers_database_password_secret_key_and_admin_password() -> None:
    settings = Settings(
        database_url="postgresql+psycopg://wadjet:db-pass@localhost:5432/wadjet",
        secret_key="secret-key-value",
        base_url="http://localhost",
        admin_password="admin-pass",
    )
    noisy = "db-pass secret-key-value admin-pass in one line"
    cleaned = settings.redact(noisy)
    assert "db-pass" not in cleaned
    assert "secret-key-value" not in cleaned
    assert "admin-pass" not in cleaned


def test_redact_url_hides_password() -> None:
    assert "super-secret" not in redact_url(GOOD_ENV["DATABASE_URL"])
    assert "***" in redact_url(GOOD_ENV["DATABASE_URL"])
