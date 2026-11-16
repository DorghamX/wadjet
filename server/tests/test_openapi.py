"""Verify the OpenAPI schema endpoint is reachable (T0.4 skeleton)."""

from __future__ import annotations

import os

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def _make_client() -> TestClient:
    """Build a TestClient bound to the test database."""
    os.environ["TEST_DATABASE_URL"] = "postgresql+psycopg://wadjet@localhost:5432/wadjet"
    settings_obj = Settings(
        database_url="postgresql+psycopg://wadjet@localhost:5432/wadjet",
        secret_key="k" * 40,
        base_url="http://testserver",
        cookie_secure=False,
        auto_migrate=False,
    )
    app = create_app(settings_obj)
    return TestClient(app)


def test_openapi_endpoint_is_reachable() -> None:
    """The /api/openapi.json must be served (section 222: OpenAPI at /api/docs)."""
    client = _make_client()
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    assert "openapi" in response.json()
