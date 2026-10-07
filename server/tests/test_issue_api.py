"""The issue JSON API (section 12): detail, triage, assignment, comments.

One rule matters more than any single status code here: the three ways an
issue cannot be answered - unknown id, somebody else's project, no grant -
are the same "No such issue", so the endpoint never confirms that an id
belongs to a project this session may not see.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.security import hash_password
from app.seed import DEMO_PASSWORD, seed_demo

API = "/api/v1/issues"

HTML = {"Accept": "text/html"}


# --- fixtures and helpers --------------------------------------------------


@pytest.fixture()
def restored(engine: Engine) -> Iterator[None]:
    """Seed, snapshot, and put the demo data back on the way out.

    The list tests count the seed and ``seed_demo`` will not re-seed what is
    already there, so anything these tests flag or assign must not stick.
    """
    seed_demo(engine)
    with engine.connect() as conn:
        issues = conn.execute(
            text(
                "SELECT id, triage_status, triage_reason, triaged_by, triaged_at, "
                "assignee_id FROM issues"
            )
        ).all()
        marks = {
            table: int(conn.execute(text(f"SELECT COALESCE(MAX(id), 0) FROM {table}")).scalar_one())
            for table in ("issue_events", "issue_comments", "issue_requests", "audit_log")
        }
    yield
    with engine.begin() as conn:
        for table, mark in marks.items():
            conn.execute(text(f"DELETE FROM {table} WHERE id > :mark"), {"mark": mark})
        for issue_id, status, reason, by, at, assignee in issues:
            conn.execute(
                text(
                    "UPDATE issues SET triage_status = :status, triage_reason = :reason, "
                    "triaged_by = :by, triaged_at = :at, assignee_id = :assignee "
                    "WHERE id = :id"
                ),
                {
                    "id": issue_id,
                    "status": status,
                    "reason": reason,
                    "by": by,
                    "at": at,
                    "assignee": assignee,
                },
            )


def _signed_in(client: TestClient, engine: Engine, username: str) -> None:
    seed_demo(engine)
    assert _login(client, username, DEMO_PASSWORD).status_code == 303


def _login(client: TestClient, username: str, password: str) -> Any:
    if "wadjet_csrf" not in client.cookies:
        client.get("/login")
    return client.post(
        "/session?next=/",
        data={
            "username": username,
            "password": password,
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )


def _signup(engine: Engine, username: str) -> str:
    password = f"pw-{username}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:u, :e, :h, FALSE, TRUE)"
            ),
            {"u": username, "e": f"{username}@example.test", "h": hash_password(password)},
        )
    return password


def _api_headers(client: TestClient) -> dict[str, str]:
    """Session cookies plus the CSRF header an API client sends."""
    return {"X-CSRF-Token": client.cookies.get("wadjet_csrf", "")}


def _issue_id(
    engine: Engine,
    *,
    key: str = "payments",
    status: str | None = None,
    rule_id: str | None = None,
    severity: str | None = None,
) -> int:
    sql = "SELECT i.id FROM issues i JOIN projects p ON p.id = i.project_id WHERE p.key = :key"
    params: dict[str, Any] = {"key": key}
    for column, value in (("triage_status", status), ("rule_id", rule_id), ("severity", severity)):
        if value is not None:
            sql += f" AND i.{column} = :{column}"
            params[column] = value
    sql += " ORDER BY i.id LIMIT 1"
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def _user_id(engine: Engine, username: str) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT id FROM users WHERE username = :u"), {"u": username}
            ).scalar_one()
        )


def _count(engine: Engine, sql: str, **params: Any) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


# --- reading ---------------------------------------------------------------


def test_get_issue_detail(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, severity="blocker")
    response = client.get(f"{API}/{issue}", headers=_api_headers(client))
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == issue
    assert data["title"] == "Private Key"
    assert data["triage_status"] == "open"
    assert data["triage_reason"] is None
    assert data["triaged_by"] is None
    assert data["assignee"] is None
    assert data["description"].startswith("Private Key detected on line 1")
    assert data["cwe"] == "CWE-798"
    assert data["first_seen_analysis_id"] is not None


def test_unknown_and_ungranted_issues_share_one_answer(
    client: TestClient, engine: Engine, restored: None
) -> None:
    real = _issue_id(engine, severity="blocker")

    _signed_in(client, engine, "demo-bob")
    unknown = client.get(f"{API}/99999999", headers=_api_headers(client))
    assert unknown.status_code == 404
    assert unknown.json() == {"detail": "No such issue"}

    _signup(engine, "t44-api-outsider")
    _login(client, "t44-api-outsider", "pw-t44-api-outsider")
    unseen = client.get(f"{API}/{real}", headers=_api_headers(client))
    assert unseen.status_code == 404
    assert unseen.json() == {"detail": "No such issue"}  # byte for byte the same


# --- triage ----------------------------------------------------------------


def test_patch_sets_the_status_with_a_reason(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    response = client.patch(
        f"{API}/{issue}",
        json={
            "triage_status": "wont_fix",
            "reason": "Superseded by the new billing service",
        },
        headers=_api_headers(client),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["triage_status"] == "wont_fix"
    assert data["triage_reason"] == "Superseded by the new billing service"
    assert data["triaged_by"]["username"] == "demo-alice"
    assert data["triaged_at"] is not None
    assert (
        _count(
            engine,
            "SELECT count(*) FROM issue_events WHERE issue_id = :iid AND type = 'status_changed'",
            iid=issue,
        )
        == 1
    )


def test_patch_requires_the_reason_where_section_8_does(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    response = client.patch(
        f"{API}/{issue}",
        json={"triage_status": "false_positive"},
        headers=_api_headers(client),
    )
    assert response.status_code == 422
    assert "at least 10 characters" in response.json()["detail"]
    with engine.connect() as conn:
        status = conn.execute(
            text("SELECT triage_status FROM issues WHERE id = :id"), {"id": issue}
        ).scalar_one()
    assert status == "open"


def test_patch_rejects_an_unknown_status(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    response = client.patch(
        f"{API}/{issue}",
        json={"triage_status": "banana", "reason": "Perfectly good reason here"},
        headers=_api_headers(client),
    )
    assert response.status_code == 422
    assert "Unknown status" in response.json()["detail"]


def test_patch_without_the_flag_permission_is_403(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    response = client.patch(
        f"{API}/{issue}",
        json={"triage_status": "wont_fix", "reason": "Bob would like this gone"},
        headers=_api_headers(client),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "flag.wont_fix permission required."


# --- assignment ------------------------------------------------------------


def test_assign_and_unassign_through_the_api(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    carol = _user_id(engine, "demo-carol")

    assigned = client.post(
        f"{API}/{issue}/assign",
        json={"assignee_id": carol},
        headers=_api_headers(client),
    )
    assert assigned.status_code == 200
    assert assigned.json()["assignee"]["username"] == "demo-carol"

    # Null is the unassign; the field itself is required, its value is not.
    cleared = client.post(
        f"{API}/{issue}/assign",
        json={"assignee_id": None},
        headers=_api_headers(client),
    )
    assert cleared.status_code == 200
    assert cleared.json()["assignee"] is None


def test_assign_to_somebody_outside_the_project_is_422(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    _signup(engine, "t44-api-nomember")
    issue = _issue_id(engine, status="open")
    response = client.post(
        f"{API}/{issue}/assign",
        json={"assignee_id": _user_id(engine, "t44-api-nomember")},
        headers=_api_headers(client),
    )
    assert response.status_code == 422
    assert "member of this project" in response.json()["detail"]
    with engine.connect() as conn:
        assignee = conn.execute(
            text("SELECT assignee_id FROM issues WHERE id = :id"), {"id": issue}
        ).scalar_one()
    assert assignee is None


def test_assign_without_issue_assign_is_403(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-dave")
    issue = _issue_id(engine, status="open")
    response = client.post(
        f"{API}/{issue}/assign",
        json={"assignee_id": _user_id(engine, "demo-bob")},
        headers=_api_headers(client),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "issue.assign permission required."


# --- comments --------------------------------------------------------------


def test_comments_round_trip_through_the_api(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, rule_id="B006")  # no seeded comments

    empty = client.get(f"{API}/{issue}/comments", headers=_api_headers(client))
    assert empty.status_code == 200
    assert empty.json() == []

    created = client.post(
        f"{API}/{issue}/comments",
        json={"body": "Posted through the API."},
        headers=_api_headers(client),
    )
    assert created.status_code == 201
    comment = created.json()
    assert comment["body_md"] == "Posted through the API."
    assert comment["author"]["username"] == "demo-alice"
    assert comment["edited_at"] is None

    listed = client.get(f"{API}/{issue}/comments", headers=_api_headers(client))
    assert [row["id"] for row in listed.json()] == [comment["id"]]


def test_comment_without_issue_comment_is_403_and_empty_is_422(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-dave")
    issue = _issue_id(engine, rule_id="B006")
    refused = client.post(
        f"{API}/{issue}/comments",
        json={"body": "May I?"},
        headers=_api_headers(client),
    )
    assert refused.status_code == 403
    assert refused.json()["detail"] == "issue.comment permission required."

    _login(client, "demo-alice", DEMO_PASSWORD)
    blank = client.post(
        f"{API}/{issue}/comments",
        json={"body": "   "},
        headers=_api_headers(client),
    )
    assert blank.status_code == 422
    assert "Write something first." in blank.json()["detail"]


# --- auth and CSRF ---------------------------------------------------------


def test_api_answers_401_without_a_session(
    client: TestClient, engine: Engine, restored: None
) -> None:
    issue = _issue_id(engine, severity="blocker")
    posted = client.post(f"{API}/{issue}/comments", json={"body": "Anonymous."})
    assert posted.status_code == 401
    read = client.get(f"{API}/{issue}")
    assert read.status_code == 401
    assert read.json() == {"detail": "Authentication required"}


def test_api_state_changes_require_the_csrf_header(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """A session cookie alone cannot carry a state change (section 13)."""
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    response = client.patch(
        f"{API}/{issue}",
        json={"triage_status": "confirmed", "reason": "Sent without the header"},
    )
    assert response.status_code == 403
