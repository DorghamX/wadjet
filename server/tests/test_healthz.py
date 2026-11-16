"""`GET /healthz` behaviour from section 15.3.5."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

SECRET = "never-show-this-password"


def _settings(database_url: str) -> Settings:
    return Settings(
        database_url=database_url,
        secret_key="k" * 40,
        base_url="http://testserver",
        cookie_secure=False,
        auto_migrate=False,
    )


def test_healthz_returns_ok_when_the_database_answers(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "db": "ok"}


def test_healthz_returns_503_when_the_database_is_down() -> None:
    url = f"postgresql+psycopg://wadjet:{SECRET}@127.0.0.1:59992/wadjet"
    app: FastAPI = create_app(_settings(url))
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "db": "down"}
    assert SECRET not in response.text


def test_openapi_is_available(client: TestClient) -> None:
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    assert "paths" in response.json()
