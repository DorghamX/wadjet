"""``GET /api/v1/agent/config`` tests (section 11, step 2; T2.6)."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.tokens import create_token


def make_project(engine: Engine, admin_user_id: int) -> tuple[int, str]:
    """A fresh project: returns (project_id, key)."""
    key = f"agentcfg-{uuid.uuid4().hex[:8]}"
    with engine.begin() as conn:
        project_id = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES (:key, 'Agent config tests', :uid) RETURNING id"
            ),
            {"key": key, "uid": admin_user_id},
        ).scalar_one()
    return int(project_id), key


def token_for(engine: Engine, project_id: int, admin_user_id: int) -> str:
    full_token, _ = create_token(engine, project_id, "agentcfg", created_by=admin_user_id)
    return full_token


def fetch_config(client: TestClient, token: str) -> Any:
    return client.get("/api/v1/agent/config", headers={"Authorization": f"Bearer {token}"})


def test_config_requires_a_project_token(
    client: TestClient, engine: Engine, admin_user_id: int
) -> None:
    make_project(engine, admin_user_id)
    assert fetch_config(client, "00" * 32).status_code == 401
    assert client.get("/api/v1/agent/config").status_code == 401


def test_config_defaults_for_a_bare_project(
    client: TestClient, engine: Engine, admin_user_id: int
) -> None:
    project_id, key = make_project(engine, admin_user_id)
    response = fetch_config(client, token_for(engine, project_id, admin_user_id))
    assert response.status_code == 200
    body = response.json()
    assert body["project_key"] == key
    assert body["settings"] == {}
    assert body["exclusion_globs"] == [
        ".venv/",
        "venv/",
        "node_modules/",
        ".git/",
        "build/",
        "dist/",
        "__pycache__/",
        "site-packages/",
    ]
    # The default gate fallback (migration 0008) travels with the config.
    conditions = body["gate_conditions"]["conditions"]
    assert [c["metric"] for c in conditions] == [
        "issues_blocker",
        "issues_critical",
        "issues_high",
        "secrets",
        "dependency_vulns_with_fix",
        "coverage_line_percent",
    ]


def test_config_honours_stored_scope_settings(
    client: TestClient, engine: Engine, admin_user_id: int
) -> None:
    project_id, _ = make_project(engine, admin_user_id)
    settings = {"scope": {"include": ["src"], "exclude": ["private/"]}}
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE projects SET settings = :settings WHERE id = :pid"),
            {"settings": json.dumps(settings), "pid": project_id},
        )
    body = fetch_config(client, token_for(engine, project_id, admin_user_id)).json()
    assert body["exclusion_globs"] == ["private/"]
    assert body["settings"] == settings


def test_config_token_is_bound_to_its_project(
    client: TestClient, engine: Engine, admin_user_id: int
) -> None:
    project_a, key_a = make_project(engine, admin_user_id)
    make_project(engine, admin_user_id)
    body = fetch_config(client, token_for(engine, project_a, admin_user_id)).json()
    assert body["project_key"] == key_a
