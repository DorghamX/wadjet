"""Audit log writer tests (section 13, T1.4)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.audit import read_audit, write_audit
from app.tokens import create_token, revoke_token


def test_write_and_read_roundtrip(engine: Engine, admin_user_id: int) -> None:
    """An entry lands with actor, action, target, details and ip intact."""
    write_audit(
        engine,
        action="settings.change",
        actor_id=admin_user_id,
        target_type="project",
        target_id=42,
        details={"field": "name", "from": "old", "to": "new"},
        ip="203.0.113.9",
    )
    entries = read_audit(engine, action="settings.change")
    assert entries, "expected one settings.change entry"
    entry = entries[0]
    assert entry["actor_id"] == admin_user_id
    assert entry["target_type"] == "project"
    assert entry["target_id"] == "42"
    assert entry["ip"] == "203.0.113.9"
    assert '"from": "old"' in entry["details"]
    assert entry["created_at"] is not None


def test_write_audit_allows_anonymous_actor(engine: Engine) -> None:
    """actor_id is nullable for events with no known user."""
    write_audit(engine, action="login.failed", details={"username": "ghost"})
    entries = read_audit(engine, action="login.failed")
    assert entries
    assert entries[0]["actor_id"] is None


def test_read_audit_can_filter_by_actor(engine: Engine, admin_user_id: int) -> None:
    """Filtering by actor narrows the trail."""
    write_audit(engine, action="flag.confirm", actor_id=admin_user_id)
    write_audit(engine, action="flag.confirm")
    entries = read_audit(engine, action="flag.confirm", actor_id=admin_user_id)
    assert entries
    assert all(e["actor_id"] == admin_user_id for e in entries)


def test_write_audit_never_raises(engine: Engine) -> None:
    """A failing audit write must not break the action it describes."""
    # An action longer than varchar(64) violates the column constraint.
    write_audit(engine, action="x" * 200)
    entries = read_audit(engine, action="x" * 64)
    assert entries == []


def test_token_create_and_revoke_are_audited(
    engine: Engine, project_id: int, admin_user_id: int
) -> None:
    """Token creation and revocation both land in the audit log (section 13)."""
    full_token, token_id = create_token(engine, project_id, "audited", created_by=admin_user_id)
    created = read_audit(engine, action="token.create")
    assert created, "expected token.create entry"
    assert created[0]["actor_id"] == admin_user_id
    assert created[0]["target_id"] == str(project_id)

    assert revoke_token(engine, token_id, actor_id=admin_user_id) is True
    revoked = read_audit(engine, action="token.revoke")
    assert revoked, "expected token.revoke entry"
    assert revoked[0]["actor_id"] == admin_user_id


def test_logout_is_audited(app: FastAPI, engine: Engine) -> None:
    """Logging out records who left and from where."""
    from app.security import hash_password

    with engine.begin() as conn:
        uid = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('auditee', 'auditee@example.test', :h, FALSE, TRUE) RETURNING id"
            ),
            {"h": hash_password("correct-horse")},
        ).scalar_one()

    with TestClient(app) as client:
        client.post("/session", data={"username": "auditee", "password": "correct-horse"})
        client.get("/healthz")
        csrf = client.cookies.get("wadjet_csrf")
        client.post("/session/logout", headers={"X-CSRF-Token": csrf})

    entries = read_audit(engine, action="logout", actor_id=uid)
    assert entries, "expected a logout audit entry"
