"""Fixtures for the server test suite."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

SECRET_KEY = "test-secret-key-0123456789abcdef0123456789abcdef"


@pytest.fixture()
def settings(database_url: str) -> Settings:
    """Settings bound to the session schema of the test database."""
    return Settings(
        database_url=database_url,
        secret_key=SECRET_KEY,
        base_url="http://testserver",
        cookie_secure=False,
        auto_migrate=False,
        log_level="debug",
    )


@pytest.fixture()
def app(settings: Settings) -> FastAPI:
    """A Wadjet application pointed at the test database."""
    return create_app(settings)


@pytest.fixture()
def client(app: FastAPI) -> Iterator[TestClient]:
    """HTTP client for the application."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def live_server(settings: Settings) -> Iterator[str]:
    """A real uvicorn server on a local port, for CLI health checks."""
    config = uvicorn.Config(
        create_app(settings),
        host="127.0.0.1",
        port=8123,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:  # pragma: no cover - startup failure
        pytest.fail("test server did not start")
    yield "http://127.0.0.1:8123"
    server.should_exit = True
    thread.join(timeout=10)
