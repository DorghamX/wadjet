"""Test session setup shared by every package.

Tests read ``TEST_DATABASE_URL`` (section 15.8). Each test session gets a unique schema,
``search_path`` is set on every connection through URL options, migrations run into that
schema once, and the schema is dropped at the end, so the suite needs only CREATE rights
and never touches real data.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

REQUIRED_ENV_MESSAGE = (
    "TEST_DATABASE_URL is not set. Tests need a real PostgreSQL database, for example:\n"
    "  export TEST_DATABASE_URL=postgresql+psycopg://wadjet:dev@localhost:5432/wadjet"
)


def pytest_configure() -> None:
    """Fail immediately, with a clear message, when no test database is configured."""
    if not os.environ.get("TEST_DATABASE_URL", "").strip():
        pytest.exit(REQUIRED_ENV_MESSAGE, returncode=4)


@pytest.fixture(scope="session")
def base_database_url() -> str:
    """The raw URL of the throwaway test database."""
    return os.environ["TEST_DATABASE_URL"]


@pytest.fixture(scope="session")
def database_url(base_database_url: str) -> Iterator[str]:
    """A URL pinned to a unique schema, migrated once, dropped at the end of the session."""
    from app.migrate import upgrade_url

    schema = f"t_{uuid.uuid4().hex[:8]}"
    base = make_url(base_database_url)
    admin = create_engine(base)
    try:
        with admin.connect() as conn:
            conn.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            conn.commit()
    finally:
        admin.dispose()

    url = base.set(query={"options": f"-c search_path={schema}"}).render_as_string(
        hide_password=False
    )
    upgrade_url(url)

    yield url

    admin = create_engine(base)
    try:
        with admin.connect() as conn:
            conn.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            conn.commit()
    finally:
        admin.dispose()
