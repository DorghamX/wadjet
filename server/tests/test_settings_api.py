"""Project settings API: read, write, validation, audit (section 10, T3.4)."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.audit import read_audit
from app.exclusions import effective_exclusion_globs
from app.security import hash_password
from app.tokens import create_token
from wadjet_schema import DEFAULT_EXCLUSION_GLOBS


def create_user(engine: Engine, *, admin: bool) -> tuple[str, str]:
    """A user that can actually log in: (username, password)."""
    username = f"settings-{'admin' if admin else 'user'}-{uuid.uuid4().hex[:8]}"
    password = "correct-horse"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:username, :email, :hash, :admin, TRUE)"
            ),
            {
                "username": username,
                "email": f"{username}@test.com",
                "hash": hash_password(password),
                "admin": admin,
            },
        )
    return username, password


def login(client: TestClient, username: str, password: str) -> dict[str, str]:
    """Log in and return the CSRF headers the write endpoints need."""
    response = client.post("/session", data={"username": username, "password": password})
    assert response.status_code == 201
    client.get("/healthz")  # fetch a page so the CSRF cookie exists
    csrf = client.cookies.get("wadjet_csrf")
    assert csrf is not None
    return {"X-CSRF-Token": csrf}


@pytest.fixture()
def fresh_project(engine: Engine, admin_user_id: int) -> int:
    """A project of this test's own, so settings writes never leak (session
    fixtures are shared)."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES (:key, 'Settings tests', :uid) RETURNING id"
            ),
            {"key": f"settings-{uuid.uuid4().hex[:8]}", "uid": admin_user_id},
        )
        return int(result.scalar_one())


def settings_url(project_id: int) -> str:
    return f"/api/v1/projects/{project_id}/settings"


def test_settings_require_a_session(client: TestClient, fresh_project: int) -> None:
    assert client.get(settings_url(fresh_project)).status_code == 401


def test_get_returns_section_10_defaults(
    client: TestClient, engine: Engine, fresh_project: int
) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    response = client.get(settings_url(fresh_project), headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["fail_on_scanner_error"] is True
    assert body["timeout_seconds"] == 300.0
    assert body["scope"] == {"include": ["."], "exclude": list(DEFAULT_EXCLUSION_GLOBS)}
    assert body["scanners"]["ruff"] == {
        "enabled": True,
        "timeout": None,
        "skipped_test_ids": [],
        "minimum_confidence": None,
        "dependency_files": [],
        "dependency_default_severity": None,
        "families": [],
        "report_path": None,
    }


def test_get_on_a_missing_project_is_404(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    assert client.get(settings_url(99_999_999), headers=headers).status_code == 404


def test_get_needs_project_browse(client: TestClient, engine: Engine, fresh_project: int) -> None:
    username, password = create_user(engine, admin=False)
    headers = login(client, username, password)
    assert client.get(settings_url(fresh_project), headers=headers).status_code == 403


def test_put_needs_project_admin(client: TestClient, engine: Engine, fresh_project: int) -> None:
    username, password = create_user(engine, admin=False)
    headers = login(client, username, password)
    response = client.put(settings_url(fresh_project), json={}, headers=headers)
    assert response.status_code == 403


def test_put_stores_validated_settings_and_audits(
    client: TestClient, engine: Engine, fresh_project: int
) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    payload = {
        "scanners": {
            "bandit": {"skipped_test_ids": ["B101"], "minimum_confidence": "low"},
            "ruff": {"families": ["F", "B"], "enabled": True},
        },
        "scope": {"include": ["src"], "exclude": ["tests/fixtures/"]},
        "timeout_seconds": 120,
    }
    response = client.put(settings_url(fresh_project), json=payload, headers=headers)
    assert response.status_code == 200
    stored = response.json()
    assert stored["timeout_seconds"] == 120
    assert stored["scanners"]["bandit"]["skipped_test_ids"] == ["B101"]

    # What GET serves and what ingest reads is the same stored JSON.
    assert client.get(settings_url(fresh_project), headers=headers).json() == stored
    with engine.begin() as conn:
        raw = conn.execute(
            text("SELECT settings FROM projects WHERE id = :pid"), {"pid": fresh_project}
        ).scalar_one()
    assert json.loads(raw)["scanners"]["ruff"]["families"] == ["F", "B"]
    # The exclusion pass consumes scope.exclude directly (section 10).
    assert effective_exclusion_globs(json.loads(raw)) == ["tests/fixtures/"]

    entries = read_audit(engine, action="project.settings_update")
    assert entries and entries[0]["target_id"] == str(fresh_project)
    changed = json.loads(entries[0]["details"])["changed"]
    assert "scanners.ruff.families" in changed
    assert "scanners.bandit.skipped_test_ids" in changed
    assert "scope.exclude" in changed


def test_put_rejects_unsupported_settings_without_writing(
    client: TestClient, engine: Engine, fresh_project: int
) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    # Free-form CLI args and unknown scanners must never land (section 10).
    assert (
        client.put(
            settings_url(fresh_project),
            json={"scanners": {"bandit": {"args": "--fix"}}},
            headers=headers,
        ).status_code
        == 422
    )
    assert (
        client.put(
            settings_url(fresh_project),
            json={"scanners": {"semgrep": {"enabled": True}}},
            headers=headers,
        ).status_code
        == 422
    )
    with engine.begin() as conn:
        raw = conn.execute(
            text("SELECT settings FROM projects WHERE id = :pid"), {"pid": fresh_project}
        ).scalar_one()
    assert raw is None  # nothing was written
    mine = [
        entry
        for entry in read_audit(engine, action="project.settings_update")
        if entry["target_id"] == str(fresh_project)
    ]
    assert mine == []


def test_agent_config_serves_the_updated_settings(
    client: TestClient, engine: Engine, fresh_project: int, admin_user_id: int
) -> None:
    """The stored options reach the agent through the config endpoint."""
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    payload: dict[str, Any] = {"scanners": {"coverage": {"report_path": "cov.xml"}}}
    assert client.put(settings_url(fresh_project), json=payload, headers=headers).status_code == 200
    full_token, _ = create_token(engine, fresh_project, "settings-test", created_by=admin_user_id)
    response = client.get("/api/v1/agent/config", headers={"Authorization": f"Bearer {full_token}"})
    assert response.status_code == 200
    assert response.json()["settings"]["scanners"]["coverage"]["report_path"] == "cov.xml"
