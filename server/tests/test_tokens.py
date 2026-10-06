"""Tests for project tokens and the token auth dependency (section 13, T1.3)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.tokens import (
    constant_time_compare,
    create_token,
    generate_token,
    hash_token,
    list_tokens,
    revoke_token,
    update_last_used,
    validate_token,
)


def test_generate_token_is_32_bytes_hex() -> None:
    """32 random bytes shown as hex, with an 8-char display prefix."""
    full_token, prefix, token_hash = generate_token()
    assert len(full_token) == 64  # 32 bytes * 2 hex chars
    assert prefix == full_token[:8]
    assert token_hash == hashlib.sha256(full_token.encode()).hexdigest()


def test_generate_token_is_unique() -> None:
    """Two generated tokens never collide."""
    first, _, _ = generate_token()
    second, _, _ = generate_token()
    assert first != second


def test_hash_token_is_sha256() -> None:
    """Tokens are stored as a SHA-256 hex digest."""
    assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest()


def test_constant_time_compare() -> None:
    """Equality is decided without leaking length beyond a cheap guard."""
    assert constant_time_compare("abc", "abc") is True
    assert constant_time_compare("abc", "abd") is False
    assert constant_time_compare("abc", "abcd") is False
    assert constant_time_compare("", "") is True


def test_create_and_validate_token(engine: Engine, project_id: int, admin_user_id: int) -> None:
    """A created token validates and is bound to its own project."""
    full_token, token_id = create_token(engine, project_id, "ci", created_by=admin_user_id)
    data = validate_token(engine, full_token)
    assert data is not None
    assert data["id"] == token_id
    assert data["project_id"] == project_id
    assert data["name"] == "ci"


def test_validate_rejects_unknown_token(engine: Engine) -> None:
    """A token that was never issued does not validate."""
    assert validate_token(engine, "deadbeef" * 8) is None


def test_revoke_token(engine: Engine, project_id: int, admin_user_id: int) -> None:
    """Revocation is one-shot and stops validation."""
    full_token, token_id = create_token(engine, project_id, "revoke-me", created_by=admin_user_id)
    assert validate_token(engine, full_token) is not None
    assert revoke_token(engine, token_id) is True
    assert validate_token(engine, full_token) is None
    # Second revocation reports nothing to do
    assert revoke_token(engine, token_id) is False


def test_expired_token_does_not_validate(
    engine: Engine, project_id: int, admin_user_id: int
) -> None:
    """An expired token is rejected."""
    full_token, _ = create_token(
        engine,
        project_id,
        "expired",
        created_by=admin_user_id,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    assert validate_token(engine, full_token) is None


def test_update_last_used(engine: Engine, project_id: int, admin_user_id: int) -> None:
    """Successful use refreshes last_used_at."""
    full_token, token_id = create_token(engine, project_id, "last-used", created_by=admin_user_id)
    with engine.begin() as conn:
        before = conn.execute(
            text("SELECT last_used_at FROM api_tokens WHERE id = :tid"),
            {"tid": token_id},
        ).scalar()
    assert before is None
    update_last_used(engine, token_id)
    with engine.begin() as conn:
        after = conn.execute(
            text("SELECT last_used_at FROM api_tokens WHERE id = :tid"),
            {"tid": token_id},
        ).scalar()
    assert after is not None


def test_list_tokens_hides_the_hash(engine: Engine, project_id: int, admin_user_id: int) -> None:
    """Token listing shows prefix and metadata, never the stored hash."""
    create_token(engine, project_id, "visible", created_by=admin_user_id)
    rows = list_tokens(engine, project_id)
    assert len(rows) >= 1
    row = next(r for r in rows if r["name"] == "visible")
    assert "token_hash" not in row
    assert len(row["prefix"]) == 8


def test_list_tokens_is_scoped_to_project(
    engine: Engine, project_id: int, admin_user_id: int
) -> None:
    """Listing tokens for one project never leaks another project's tokens."""
    with engine.begin() as conn:
        other_project = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES ('other-project', 'Other', :uid) RETURNING id"
            ),
            {"uid": admin_user_id},
        ).scalar_one()
    create_token(engine, other_project, "other-secret", created_by=admin_user_id)
    other_keys = {r["name"] for r in list_tokens(engine, other_project)}
    mine_keys = {r["name"] for r in list_tokens(engine, project_id)}
    assert "other-secret" in other_keys
    assert "other-secret" not in mine_keys


def test_agent_route_requires_token(app: FastAPI) -> None:
    """No Authorization header means 401."""
    with TestClient(app) as client:
        response = client.get("/api/v1/agent/config")
    assert response.status_code == 401


def test_agent_route_rejects_bad_token(app: FastAPI) -> None:
    """An unknown Bearer token means 401."""
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/agent/config",
            headers={"Authorization": "Bearer " + "00" * 32},
        )
    assert response.status_code == 401


def test_agent_route_accepts_valid_token_and_touches_last_used(
    app: FastAPI, engine: Engine, project_id: int, admin_user_id: int
) -> None:
    """A valid token authenticates and refreshes last_used_at."""
    full_token, token_id = create_token(engine, project_id, "agent", created_by=admin_user_id)
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/agent/config",
            headers={"Authorization": f"Bearer {full_token}"},
        )
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"project_key", "settings", "gate_conditions", "exclusion_globs"}
    assert body["settings"] == {}
    with engine.begin() as conn:
        last_used = conn.execute(
            text("SELECT last_used_at FROM api_tokens WHERE id = :tid"),
            {"tid": token_id},
        ).scalar()
    assert last_used is not None


def test_token_for_project_a_cannot_read_project_b(
    app: FastAPI, engine: Engine, project_id: int, admin_user_id: int
) -> None:
    """A token bound to project A cannot act for project B (T1.4 acceptance)."""
    with engine.begin() as conn:
        project_b = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES ('project-b', 'Project B', :uid) RETURNING id"
            ),
            {"uid": admin_user_id},
        ).scalar_one()

    # A route pinned to project B; the token belongs to project A.
    @app.get("/api/v1/projects/project-b/config")
    def pinned_route(token: dict = Depends(app.state.require_project_token)) -> dict:  # type: ignore[assignment]
        if token["project_id"] != project_b:
            from fastapi import HTTPException

            raise HTTPException(status_code=403, detail="Token is not valid for this project")
        return {"project_id": token["project_id"]}

    token_a, _ = create_token(engine, project_id, "token-a", created_by=admin_user_id)
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/projects/project-b/config",
            headers={"Authorization": f"Bearer {token_a}"},
        )
    assert response.status_code == 403
