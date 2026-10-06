"""Quality gate tests: built-in default, fallback, engine matrix, CRUD (section 9, T2.5)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.audit import read_audit
from app.gate import (
    ALL_METRICS,
    compute_issue_metrics,
    evaluate_conditions,
    load_gate_conditions,
)
from app.security import hash_password

#: The built-in default gate of section 9, frozen here so the test fails if
#: migration 0008 ever seeds anything else.
DEFAULT_CONDITIONS = [
    ("issues_blocker", ">", 0.0),
    ("issues_critical", ">", 0.0),
    ("issues_high", ">", 0.0),
    ("secrets", ">", 0.0),
    ("dependency_vulns_with_fix", ">", 0.0),
    ("coverage_line_percent", "<", 70.0),
]

#: Section 9's metric list, frozen the same way.
SECTION_9_METRICS = {
    "issues_total",
    "issues_blocker",
    "issues_critical",
    "issues_high",
    "issues_medium",
    "issues_low",
    "vulnerabilities",
    "secrets",
    "dependency_vulns",
    "dependency_vulns_with_fix",
    "bugs",
    "code_smells",
    "coverage_line_percent",
}


@pytest.fixture()
def fresh_project(engine: Engine, admin_user_id: int) -> int:
    """A project with no gate of its own, so the default fallback shows."""
    with engine.begin() as conn:
        project_id = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES (:key, 'Gate tests', :uid) RETURNING id"
            ),
            {"key": f"gate-test-{uuid.uuid4().hex[:8]}", "uid": admin_user_id},
        ).scalar_one()
    return int(project_id)


def create_user(engine: Engine, *, admin: bool) -> tuple[str, str]:
    """A user that can actually log in: (username, password)."""
    username = f"gate-{'admin' if admin else 'user'}-{uuid.uuid4().hex[:8]}"
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


def create_gate_api(client: TestClient, headers: dict[str, str], **body: Any) -> Any:
    return client.post(
        "/api/v1/gates", json={"name": "tmp", "conditions": [], **body}, headers=headers
    )


def default_conditions_from_db(engine: Engine) -> list[tuple[str, str, float]]:
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT gc.metric, gc.operator, gc.threshold "
                "FROM gate_conditions gc JOIN quality_gates g ON g.id = gc.gate_id "
                "WHERE g.is_default ORDER BY gc.id"
            )
        ).fetchall()
    return [(row[0], row[1], float(row[2])) for row in rows]


# --- the built-in default gate ---------------------------------------------


def test_default_gate_is_seeded(engine: Engine) -> None:
    with engine.begin() as conn:
        gate = conn.execute(
            text("SELECT name, is_default, is_builtin FROM quality_gates WHERE is_default = TRUE")
        ).first()
    assert gate is not None
    assert gate.name == "Wadjet default"
    assert gate.is_default is True
    assert gate.is_builtin is True
    assert default_conditions_from_db(engine) == DEFAULT_CONDITIONS


def test_metric_vocabulary_matches_section_9() -> None:
    assert set(ALL_METRICS) == SECTION_9_METRICS


def test_project_without_a_gate_falls_back_to_the_default(
    engine: Engine, fresh_project: int
) -> None:
    with engine.connect() as conn:
        conditions = load_gate_conditions(conn, fresh_project)
    assert [(c["metric"], c["operator"], c["threshold"]) for c in conditions] == (
        DEFAULT_CONDITIONS
    )


def test_project_with_a_gate_uses_only_that_gate(engine: Engine, fresh_project: int) -> None:
    with engine.begin() as conn:
        gate_id = conn.execute(
            text(
                "INSERT INTO quality_gates (name, is_default, is_builtin) "
                "VALUES ('Custom', FALSE, FALSE) RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO gate_conditions (gate_id, metric, operator, threshold) "
                "VALUES (:gid, 'issues_total', '>', 10)"
            ),
            {"gid": gate_id},
        )
        conn.execute(
            text("UPDATE projects SET gate_id = :gid WHERE id = :pid"),
            {"gid": gate_id, "pid": fresh_project},
        )
    with engine.connect() as conn:
        conditions = load_gate_conditions(conn, fresh_project)
    assert [(c["metric"], c["operator"], c["threshold"]) for c in conditions] == [
        ("issues_total", ">", 10.0)
    ]


# --- the engine -------------------------------------------------------------


@pytest.mark.parametrize(
    ("operator", "threshold", "actual", "expected"),
    [
        (">", 0.0, 1.0, True),
        (">", 0.0, 0.0, False),
        (">=", 1.0, 1.0, True),
        (">=", 1.0, 0.0, False),
        ("<", 1.0, 0.0, True),
        ("<", 1.0, 1.0, False),
        ("<=", 1.0, 1.0, True),
        ("<=", 1.0, 2.0, False),
        ("==", 1.0, 1.0, True),
        ("==", 1.0, 2.0, False),
    ],
)
def test_operator_matrix(operator: str, threshold: float, actual: float, expected: bool) -> None:
    details = evaluate_conditions(
        [{"metric": "issues_total", "operator": operator, "threshold": threshold}],
        {"issues_total": actual},
    )
    assert details[0]["triggered"] is expected
    assert details[0]["actual"] == actual
    assert details[0]["threshold"] == threshold


def test_unknown_operator_fails_closed() -> None:
    details = evaluate_conditions(
        [{"metric": "issues_total", "operator": "??", "threshold": 0.0}],
        {"issues_total": 0.0},
    )
    assert details[0]["triggered"] is True


def test_metrics_count_open_and_confirmed_only(engine: Engine, fresh_project: int) -> None:
    """Section 9: false positive, accepted risk and won't fix are excluded."""
    rows = [
        ("open", "present"),
        ("confirmed", "present"),
        ("false_positive", "present"),
        ("accepted_risk", "present"),
        ("wont_fix", "present"),
        ("open", "resolved"),
    ]
    with engine.begin() as conn:
        for index, (triage, presence) in enumerate(rows):
            conn.execute(
                text(
                    "INSERT INTO issues (project_id, fingerprint, tool, rule_id, severity, "
                    "category, title, triage_status, presence) "
                    "VALUES (:pid, :fp, 'bandit', 'B101', 'medium', 'bug', 'title', "
                    ":triage, :presence)"
                ),
                {
                    "pid": fresh_project,
                    "fp": f"{uuid.uuid4().hex}{index:02d}",
                    "triage": triage,
                    "presence": presence,
                },
            )
    with engine.connect() as conn:
        metrics = compute_issue_metrics(conn, fresh_project)
    assert metrics["issues_total"] == 2.0  # open + confirmed


# --- CRUD -------------------------------------------------------------------


def test_gate_list_requires_a_session(client: TestClient) -> None:
    assert client.get("/api/v1/gates").status_code == 401


def test_gate_list_shows_the_default_gate(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=False)
    headers = login(client, username, password)
    response = client.get("/api/v1/gates", headers=headers)
    assert response.status_code == 200
    gates = {gate["name"]: gate for gate in response.json()}
    default = gates["Wadjet default"]
    assert default["is_builtin"] is True
    assert [
        (c["metric"], c["operator"], c["threshold"]) for c in default["conditions"]
    ] == DEFAULT_CONDITIONS


def test_regular_user_cannot_create_gates(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=False)
    headers = login(client, username, password)
    response = create_gate_api(client, headers, name="Nope")
    assert response.status_code == 403


def test_admin_creates_a_gate_and_it_is_audited(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    response = create_gate_api(
        client,
        headers,
        name="Strict",
        conditions=[{"metric": "issues_total", "operator": ">", "threshold": 0.0}],
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Strict"
    assert body["is_default"] is False and body["is_builtin"] is False
    assert body["conditions"] == [{"metric": "issues_total", "operator": ">", "threshold": 0.0}]

    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, name FROM quality_gates WHERE id = :gid"),
            {"gid": body["id"]},
        ).first()
    assert row.name == "Strict"
    entries = read_audit(engine, action="gate.create")
    assert entries and entries[0]["target_id"] == str(body["id"])


def test_create_rejects_an_unknown_metric(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    response = create_gate_api(
        client,
        headers,
        name="Bad metric",
        conditions=[{"metric": "nonsense", "operator": ">", "threshold": 0.0}],
    )
    assert response.status_code == 422


def test_create_rejects_an_unknown_operator(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    response = create_gate_api(
        client,
        headers,
        name="Bad operator",
        conditions=[{"metric": "issues_total", "operator": "!=", "threshold": 0.0}],
    )
    assert response.status_code == 422


def test_create_rejects_a_duplicate_name(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    response = create_gate_api(client, headers, name="Wadjet default")
    assert response.status_code == 409


def test_patch_replaces_name_and_conditions(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    created = create_gate_api(client, headers, name="Before").json()

    response = client.patch(
        f"/api/v1/gates/{created['id']}",
        json={
            "name": "After",
            "conditions": [{"metric": "secrets", "operator": "==", "threshold": 0.0}],
        },
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "After"
    assert body["conditions"] == [{"metric": "secrets", "operator": "==", "threshold": 0.0}]

    entries = read_audit(engine, action="gate.update")
    assert entries and entries[0]["target_id"] == str(created["id"])


def test_patch_with_nothing_to_update_is_rejected(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    created = create_gate_api(client, headers, name="Empty").json()
    response = client.patch(f"/api/v1/gates/{created['id']}", json={}, headers=headers)
    assert response.status_code == 422


def test_patch_unknown_gate_is_404(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    response = client.patch("/api/v1/gates/999999", json={"name": "Ghost"}, headers=headers)
    assert response.status_code == 404


def test_builtin_gate_cannot_be_deleted(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    default = next(
        gate for gate in client.get("/api/v1/gates", headers=headers).json() if gate["is_builtin"]
    )
    response = client.delete(f"/api/v1/gates/{default['id']}", headers=headers)
    assert response.status_code == 403
    assert "built-in" in response.json()["detail"]


def test_gate_in_use_cannot_be_deleted(
    client: TestClient, engine: Engine, fresh_project: int
) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    created = create_gate_api(client, headers, name="In use").json()
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE projects SET gate_id = :gid WHERE id = :pid"),
            {"gid": created["id"], "pid": fresh_project},
        )
    response = client.delete(f"/api/v1/gates/{created['id']}", headers=headers)
    assert response.status_code == 409
    assert "project" in response.json()["detail"]


def test_unused_gate_deletes_cleanly(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    created = create_gate_api(
        client,
        headers,
        name="Disposable",
        conditions=[{"metric": "bugs", "operator": ">", "threshold": 0.0}],
    ).json()

    response = client.delete(f"/api/v1/gates/{created['id']}", headers=headers)
    assert response.status_code == 204

    with engine.begin() as conn:
        gate = conn.execute(
            text("SELECT 1 FROM quality_gates WHERE id = :gid"), {"gid": created["id"]}
        ).scalar()
        conditions = conn.execute(
            text("SELECT COUNT(*) FROM gate_conditions WHERE gate_id = :gid"),
            {"gid": created["id"]},
        ).scalar_one()
    assert gate is None
    assert conditions == 0

    entries = read_audit(engine, action="gate.delete")
    assert entries and entries[0]["target_id"] == str(created["id"])
