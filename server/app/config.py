"""Environment-driven configuration.

Section 15.2 of the build guide: configuration comes only from environment variables, the
database URL is validated at startup, and no secret is ever written to a log line, an error
message or a traceback.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.engine import make_url

_URL_PASSWORD_RE = re.compile(r"://([^:/@\s]+):([^@\s]+)@")


class ConfigError(Exception):
    """Invalid configuration. The message is a single line and never contains a secret."""


def _read_secret_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from None


def normalize_database_url(raw: str) -> str:
    """Validate a database URL and accept the three schemes from section 15.2."""
    value = raw.strip()
    if not value:
        raise ConfigError("DATABASE_URL is empty")
    if value.startswith("postgres://"):
        value = "postgresql+psycopg://" + value[len("postgres://") :]
    elif value.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value[len("postgresql://") :]
    if not value.startswith("postgresql+psycopg://"):
        raise ConfigError(
            "DATABASE_URL must start with postgresql+psycopg://, postgresql:// or postgres://"
        )
    try:
        url = make_url(value)
    except Exception:
        raise ConfigError("DATABASE_URL is not a valid URL") from None
    if not url.database:
        raise ConfigError("DATABASE_URL is missing a database name")
    return url.render_as_string(hide_password=False)


def redact_url(raw: str) -> str:
    """Render a URL with its password replaced by ``***``."""
    try:
        return make_url(raw).render_as_string(hide_password=True)
    except Exception:
        return "<invalid database url>"


def redact_text(text: str, secrets: Iterable[str]) -> str:
    """Remove known secrets and any ``user:password@`` pair from arbitrary text."""
    out = text
    for secret in secrets:
        if secret:
            out = out.replace(secret, "***")
    return _URL_PASSWORD_RE.sub(lambda m: f"://{m.group(1)}:***@", out)


def _parse_bool(name: str, raw: str, default: bool) -> bool:
    if not raw:
        return default
    lowered = raw.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false")


def _parse_int(name: str, raw: str, default: int, minimum: int = 0) -> int:
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated server configuration (section 15.2)."""

    database_url: str
    secret_key: str
    base_url: str
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30
    db_wait_seconds: int = 60
    auto_migrate: bool = True
    admin_user: str | None = None
    admin_password: str | None = None
    cookie_secure: bool = True
    log_level: str = "info"

    @property
    def database_password(self) -> str:
        """The password inside ``database_url``, or an empty string."""
        try:
            return make_url(self.database_url).password or ""
        except Exception:
            return ""

    @property
    def secrets(self) -> tuple[str, ...]:
        """Values that must never appear in a log line or an error message."""
        found = [self.database_password, self.secret_key, self.admin_password or ""]
        return tuple(secret for secret in found if secret)

    def redact(self, text: str) -> str:
        """Strip every known secret from ``text`` before it is printed or logged."""
        return redact_text(text, self.secrets)

    def redacted_database_url(self) -> str:
        """The database URL as it may be shown to a human."""
        return redact_url(self.database_url)


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Read and validate configuration. Raises :class:`ConfigError` with one clear line."""
    source = os.environ if env is None else env

    def get(name: str) -> str:
        return source.get(name, "").strip()

    def get_secret(name: str) -> str:
        direct = get(name)
        if direct:
            return direct
        path = get(f"{name}_FILE")
        return _read_secret_file(path) if path else ""

    raw_url = get_secret("DATABASE_URL")
    if not raw_url:
        raise ConfigError("DATABASE_URL is not set (or set DATABASE_URL_FILE)")
    database_url = normalize_database_url(raw_url)

    secret_key = get_secret("WADJET_SECRET_KEY")
    if not secret_key:
        raise ConfigError("WADJET_SECRET_KEY is not set (or set WADJET_SECRET_KEY_FILE)")
    if len(secret_key) < 32:
        raise ConfigError("WADJET_SECRET_KEY must be at least 32 characters")

    base_url = get("WADJET_BASE_URL")
    if not base_url:
        raise ConfigError("WADJET_BASE_URL is not set")
    if not base_url.startswith(("http://", "https://")):
        raise ConfigError("WADJET_BASE_URL must start with http:// or https://")

    admin_user = get("WADJET_ADMIN_USER") or None
    admin_password = get("WADJET_ADMIN_PASSWORD") or None
    if bool(admin_user) != bool(admin_password):
        raise ConfigError("WADJET_ADMIN_USER and WADJET_ADMIN_PASSWORD must be set together")

    log_level = get("WADJET_LOG_LEVEL") or "info"
    if log_level.lower() not in {"debug", "info", "warning", "error", "critical"}:
        raise ConfigError("WADJET_LOG_LEVEL must be debug, info, warning, error or critical")

    return Settings(
        database_url=database_url,
        secret_key=secret_key,
        base_url=base_url.rstrip("/"),
        db_pool_size=_parse_int("WADJET_DB_POOL_SIZE", get("WADJET_DB_POOL_SIZE"), 5, 1),
        db_max_overflow=_parse_int("WADJET_DB_MAX_OVERFLOW", get("WADJET_DB_MAX_OVERFLOW"), 10),
        db_pool_timeout=_parse_int("WADJET_DB_POOL_TIMEOUT", get("WADJET_DB_POOL_TIMEOUT"), 30, 1),
        db_wait_seconds=_parse_int("WADJET_DB_WAIT_SECONDS", get("WADJET_DB_WAIT_SECONDS"), 60),
        auto_migrate=_parse_bool("WADJET_AUTO_MIGRATE", get("WADJET_AUTO_MIGRATE"), True),
        admin_user=admin_user,
        admin_password=admin_password,
        cookie_secure=_parse_bool("WADJET_COOKIE_SECURE", get("WADJET_COOKIE_SECURE"), True),
        log_level=log_level.lower(),
    )
