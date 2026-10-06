"""End-to-end tests for ``POST /api/v1/analyses`` (sections 11, 10, 9, T2.4)."""

from __future__ import annotations

import gzip
import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.api.analyses import MAX_UPLOAD_BYTES, derive_analysis_status
from app.tokens import create_token
from wadjet_schema import AnalysisResult

SNIPPET = "\n".join(
    [
        "import os",  # context
        "import sys",  # context
        "value = 1",  # context
        "assert value",  # flagged (line 10)
        "print(value)",  # context
        "print('a')",  # context
        "print('b')",  # context
    ]
)


def make_finding(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "tool": "bandit",
        "rule_id": "B101",
        "severity": "medium",
        "category": "bug",
        "title": "Assert used",
        "message": "assert statement found",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 10,
        "snippet": SNIPPET,
    }
    values.update(overrides)
    return values


def make_upload(
    project_key: str, findings: list[dict[str, object]], **extra: object
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "project_key": project_key,
        "commit_sha": "abc123",
        "ci_url": None,
        "findings": findings,
        "metrics": {},
        "scanner_runs": {"bandit": {"version": "1.7.10", "status": "ok", "duration": 1.2}},
    }
    payload.update(extra)
    return payload


@pytest.fixture()
def ingest_project(engine: Engine, admin_user_id: int) -> tuple[int, str]:
    """A fresh project per test, so issue counts never leak between tests."""
    key = f"ingest-{uuid.uuid4().hex[:10]}"
    with engine.begin() as conn:
        project_id = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES (:key, 'Ingest tests', :uid) RETURNING id"
            ),
            {"key": key, "uid": admin_user_id},
        ).scalar_one()
    return int(project_id), key


@pytest.fixture()
def project_token(engine: Engine, ingest_project: tuple[int, str]) -> str:
    project_id, _ = ingest_project
    full_token, _ = create_token(engine, project_id, "ingest", created_by=1)
    return full_token


def upload(
    client: TestClient,
    token: str,
    payload: dict[str, Any],
    *,
    raw: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    body = raw if raw is not None else json.dumps(payload).encode()
    request_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    return client.post("/api/v1/analyses", content=body, headers=request_headers)


def attach_gate(engine: Engine, project_id: int, conditions: list[tuple[str, str, float]]) -> None:
    """Give the project a gate with the given (metric, operator, threshold)."""
    with engine.begin() as conn:
        gate_id = conn.execute(
            text(
                "INSERT INTO quality_gates (name, is_default, is_builtin) "
                "VALUES (:name, FALSE, FALSE) RETURNING id"
            ),
            {"name": f"gate-{uuid.uuid4().hex[:8]}"},
        ).scalar_one()
        for metric, operator, threshold in conditions:
            conn.execute(
                text(
                    "INSERT INTO gate_conditions (gate_id, metric, operator, threshold) "
                    "VALUES (:gid, :metric, :operator, :threshold)"
                ),
                {
                    "gid": gate_id,
                    "metric": metric,
                    "operator": operator,
                    "threshold": threshold,
                },
            )
        conn.execute(
            text("UPDATE projects SET gate_id = :gid WHERE id = :pid"),
            {"gid": gate_id, "pid": project_id},
        )


def fetch_analysis(engine: Engine, analysis_id: str) -> dict[str, Any]:
    with engine.begin() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT status, gate_status, gate_details, excluded_count, metrics "
                    "FROM analyses WHERE id = :aid"
                ),
                {"aid": analysis_id},
            )
            .mappings()
            .one()
        )
    return dict(row)


def fetch_issues(engine: Engine, project_id: int) -> list[dict[str, Any]]:
    with engine.begin() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT id, fingerprint, file_path, presence, triage_status, description, "
                    "impact, fix, cwe, title, first_seen_analysis_id, last_seen_analysis_id "
                    "FROM issues WHERE project_id = :pid ORDER BY id"
                ),
                {"pid": project_id},
            )
            .mappings()
            .fetchall()
        )
    return [dict(row) for row in rows]


def fetch_events(engine: Engine, issue_id: int) -> list[str]:
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT type FROM issue_events WHERE issue_id = :iid ORDER BY id"),
            {"iid": issue_id},
        ).fetchall()
    return [row[0] for row in rows]


# --- auth and validation ----------------------------------------------------


def test_upload_requires_a_project_token(client: TestClient, ingest_project) -> None:
    _, key = ingest_project
    response = client.post("/api/v1/analyses", json=make_upload(key, []))
    assert response.status_code == 401

    response = client.post(
        "/api/v1/analyses",
        content=json.dumps(make_upload(key, [])),
        headers={"Authorization": "Bearer " + "00" * 32},
    )
    assert response.status_code == 401


def test_token_of_another_project_is_rejected(
    client: TestClient, ingest_project, project_token: str
) -> None:
    """A token may only upload for its own project (section 13)."""
    response = upload(client, project_token, make_upload("some-other-key", []))
    assert response.status_code == 403
    assert response.json()["detail"] == "Token is not valid for this project"


def test_invalid_payload_is_422(client: TestClient, project_token: str) -> None:
    response = upload(client, project_token, {}, raw=b"{}")
    assert response.status_code == 422

    response = upload(client, project_token, {}, raw=b"this is not json")
    assert response.status_code == 422


def test_unsupported_content_encoding_is_415(client: TestClient, project_token: str) -> None:
    response = upload(
        client,
        project_token,
        {},
        raw=b"{}",
        headers={"Content-Encoding": "br"},
    )
    assert response.status_code == 415


def test_oversized_body_is_413(client: TestClient, project_token: str) -> None:
    body = b"x" * (MAX_UPLOAD_BYTES + 1)
    response = upload(client, project_token, {}, raw=body)
    assert response.status_code == 413


def test_gzip_bomb_is_413(client: TestClient, project_token: str) -> None:
    """A small compressed body that expands past the cap is refused."""
    bomb = gzip.compress(b"\0" * (MAX_UPLOAD_BYTES + 1))
    assert len(bomb) < MAX_UPLOAD_BYTES
    response = upload(
        client,
        project_token,
        {},
        raw=bomb,
        headers={"Content-Encoding": "gzip"},
    )
    assert response.status_code == 413


# --- happy path --------------------------------------------------------------


def test_first_upload_creates_analysis_and_issues(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    # The default gate's coverage condition needs a report; the project's own
    # test step supplies one, and a clean report keeps the gate green.
    payload = make_upload(key, [make_finding()], metrics={"coverage_line_percent": 100.0})
    response = upload(client, project_token, payload)
    assert response.status_code == 201

    result = AnalysisResult.model_validate(response.json())
    assert result.gate_status == "passed"
    assert result.issues_created == 1
    assert result.issues_resolved == 0
    assert int(result.analysis_id) > 0

    analysis = fetch_analysis(engine, result.analysis_id)
    assert analysis["status"] == "complete"
    assert analysis["gate_status"] == "passed"
    assert analysis["excluded_count"] == 0
    assert analysis["metrics"]["issues_total"] == 1.0

    issues = fetch_issues(engine, project_id)
    assert len(issues) == 1
    issue = issues[0]
    assert issue["presence"] == "present"
    assert issue["triage_status"] == "open"
    assert issue["file_path"] == "src/app.py"
    assert issue["first_seen_analysis_id"] == int(result.analysis_id)
    assert issue["last_seen_analysis_id"] == int(result.analysis_id)
    # Enrichment from the Bandit KB (section 6) landed on the issue.
    assert issue["title"] == "Assert used"
    assert issue["description"] and issue["impact"] and issue["fix"]
    assert issue["cwe"] == "CWE-617"
    assert fetch_events(engine, issue["id"]) == ["created"]


def test_gzip_upload_is_accepted(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    _, key = ingest_project
    body = gzip.compress(json.dumps(make_upload(key, [make_finding()])).encode())
    response = upload(
        client,
        project_token,
        {},
        raw=body,
        headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
    )
    assert response.status_code == 201
    assert response.json()["issues_created"] == 1


# --- exclusions --------------------------------------------------------------


def test_excluded_paths_are_dropped_and_counted(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    payload = make_upload(
        key,
        [
            make_finding(file_path="src/app.py"),
            make_finding(file_path=".venv/lib/python3.12/site-packages/evil.py"),
            make_finding(file_path="node_modules/pkg/index.js"),
            make_finding(file_path="build/generated.py"),
        ],
    )
    response = upload(client, project_token, payload)
    assert response.status_code == 201
    result = response.json()
    assert result["issues_created"] == 1

    analysis = fetch_analysis(engine, result["analysis_id"])
    assert analysis["excluded_count"] == 3
    issues = fetch_issues(engine, project_id)
    assert [issue["file_path"] for issue in issues] == ["src/app.py"]


def test_dependency_findings_are_never_excluded(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    dep = make_finding(
        tool="pip-audit",
        rule_id="CVE-2023-12345",
        category="dependency",
        file_path=None,
        package="django",
        vuln_id="CVE-2023-12345",
        installed_version="4.2.0",
        fixed_versions=["4.2.1"],
        severity="high",
        title="django vulnerability",
        message="advisory text",
        snippet="",
    )
    payload = make_upload(
        key,
        [dep, make_finding(file_path=".venv/skipped.py")],
        scanner_runs={"pip-audit": {"version": "2.7", "status": "ok", "duration": 0.5}},
    )
    response = upload(client, project_token, payload)
    assert response.status_code == 201
    assert response.json()["issues_created"] == 1

    issues = fetch_issues(engine, project_id)
    assert len(issues) == 1
    assert issues[0]["file_path"] is None
    # pip-audit enrichment: fix text from fix_versions (section 6).
    assert issues[0]["fix"] == "Upgrade `django` to `4.2.1`"

    analysis = fetch_analysis(engine, response.json()["analysis_id"])
    assert analysis["excluded_count"] == 1


def test_duplicate_dependency_rows_collapse_to_one_issue(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    dep = make_finding(
        tool="pip-audit",
        rule_id="CVE-2023-12345",
        category="dependency",
        file_path=None,
        package="django",
        vuln_id="CVE-2023-12345",
        severity="high",
        title="django vulnerability",
        message="advisory text",
        snippet="",
    )
    payload = make_upload(key, [dep, dict(dep)])
    response = upload(client, project_token, payload)
    assert response.status_code == 201
    assert response.json()["issues_created"] == 1
    assert len(fetch_issues(engine, project_id)) == 1


# --- lifecycle across uploads ------------------------------------------------


def test_unseen_issue_resolves_on_the_next_complete_analysis(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    first = upload(client, project_token, make_upload(key, [make_finding()]))
    assert first.json()["issues_created"] == 1

    second = upload(
        client,
        project_token,
        make_upload(key, [make_finding(file_path="src/other.py", rule_id="B102")]),
    )
    body = second.json()
    assert body["issues_created"] == 1
    assert body["issues_resolved"] == 1

    issues = {issue["file_path"]: issue for issue in fetch_issues(engine, project_id)}
    assert issues["src/app.py"]["presence"] == "resolved"
    assert issues["src/other.py"]["presence"] == "present"
    assert "resolved_by_scan" in fetch_events(engine, issues["src/app.py"]["id"])


def test_incomplete_analysis_resolves_nothing(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    upload(client, project_token, make_upload(key, [make_finding()]))

    payload = make_upload(
        key,
        [make_finding(file_path="src/other.py", rule_id="B102")],
        scanner_runs={"bandit": {"version": "1.7.10", "status": "error", "error": "boom"}},
    )
    response = upload(client, project_token, payload)
    body = response.json()
    assert body["issues_resolved"] == 0
    assert body["issues_created"] == 1

    issues = {issue["file_path"]: issue for issue in fetch_issues(engine, project_id)}
    assert issues["src/app.py"]["presence"] == "present"  # not resolved
    assert issues["src/other.py"]["presence"] == "present"

    # The gate fails, and the synthetic condition explains why (section 6/9).
    analysis = fetch_analysis(engine, body["analysis_id"])
    assert analysis["status"] == "incomplete"
    assert analysis["gate_status"] == "failed"
    conditions = analysis["gate_details"]["conditions"]
    assert conditions[0]["metric"] == "all_scanners_completed"
    assert conditions[0]["triggered"] is True


def test_resolved_issue_reappears_with_triage_preserved(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    upload(client, project_token, make_upload(key, [make_finding()]))

    # Flag it, then let a scan resolve it.
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE issues SET triage_status = 'false_positive', "
                "triage_reason = 'not reachable' WHERE project_id = :pid"
            ),
            {"pid": project_id},
        )
    upload(
        client,
        project_token,
        make_upload(key, [make_finding(file_path="src/other.py", rule_id="B102")]),
    )

    # And bring the original finding back.
    response = upload(client, project_token, make_upload(key, [make_finding()]))
    assert response.json()["issues_created"] == 0
    assert response.json()["issues_resolved"] == 1  # the other one went away

    issues = {issue["file_path"]: issue for issue in fetch_issues(engine, project_id)}
    original = issues["src/app.py"]
    assert original["presence"] == "present"
    assert original["triage_status"] == "false_positive"  # carried over
    events = fetch_events(engine, original["id"])
    assert "reopened_by_scan" in events
    assert "flag_carried_over" in events
    assert "resolved_by_scan" in events


def test_flag_survives_a_line_shift_end_to_end(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    upload(client, project_token, make_upload(key, [make_finding()]))
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE issues SET triage_status = 'confirmed' WHERE project_id = :pid"),
            {"pid": project_id},
        )

    shifted = make_finding(line_start=25, line_end=25)
    response = upload(client, project_token, make_upload(key, [shifted]))
    body = response.json()
    assert body["issues_created"] == 0
    assert body["issues_resolved"] == 0

    issues = fetch_issues(engine, project_id)
    assert len(issues) == 1
    assert issues[0]["triage_status"] == "confirmed"
    assert "flag_carried_over" in fetch_events(engine, issues[0]["id"])


# --- gate -------------------------------------------------------------------


def test_gate_condition_fails_the_analysis(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    attach_gate(engine, project_id, [("issues_total", ">", 0.0)])

    response = upload(client, project_token, make_upload(key, [make_finding()]))
    body = response.json()
    assert body["gate_status"] == "failed"

    conditions = body["gate_details"]["conditions"]
    assert conditions[0] == {
        "metric": "issues_total",
        "operator": ">",
        "threshold": 0.0,
        "actual": 1.0,
        "triggered": True,
    }

    analysis = fetch_analysis(engine, body["analysis_id"])
    assert analysis["gate_status"] == "failed"
    assert analysis["gate_details"]["conditions"][0]["triggered"] is True


def test_gate_passes_when_no_condition_triggers(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    attach_gate(engine, project_id, [("issues_total", ">", 100.0)])

    response = upload(client, project_token, make_upload(key, [make_finding()]))
    body = response.json()
    assert body["gate_status"] == "passed"
    condition = body["gate_details"]["conditions"][0]
    assert condition["triggered"] is False
    assert condition["actual"] == 1.0


def test_coverage_metric_reaches_the_gate(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    attach_gate(engine, project_id, [("coverage_line_percent", "<", 70.0)])

    payload = make_upload(key, [], metrics={"coverage_line_percent": 42.5})
    response = upload(client, project_token, payload)
    body = response.json()
    assert body["gate_status"] == "failed"
    condition = body["gate_details"]["conditions"][0]
    assert condition["actual"] == 42.5
    assert condition["triggered"] is True

    analysis = fetch_analysis(engine, body["analysis_id"])
    assert analysis["metrics"]["coverage_line_percent"] == 42.5


def test_missing_coverage_report_fails_the_coverage_condition(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    """Section 6 coverage row: no report + coverage condition = trigger."""
    project_id, key = ingest_project
    attach_gate(engine, project_id, [("coverage_line_percent", "<", 70.0)])

    response = upload(client, project_token, make_upload(key, [make_finding()]))
    body = response.json()
    assert body["gate_status"] == "failed"
    condition = body["gate_details"]["conditions"][0]
    assert condition["actual"] is None
    assert condition["triggered"] is True
    assert condition["reason"] == "no coverage report"


def test_coverage_above_threshold_passes_the_condition(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    attach_gate(engine, project_id, [("coverage_line_percent", "<", 70.0)])

    payload = make_upload(key, [], metrics={"coverage_line_percent": 95.5})
    body = upload(client, project_token, payload).json()
    assert body["gate_status"] == "passed"
    condition = body["gate_details"]["conditions"][0]
    assert condition["actual"] == 95.5
    assert condition["triggered"] is False
    assert "reason" not in condition


def test_unknown_metric_shows_as_null_and_does_not_trigger(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    project_id, key = ingest_project
    attach_gate(engine, project_id, [("no_such_metric", ">", 1.0)])

    response = upload(client, project_token, make_upload(key, [make_finding()]))
    body = response.json()
    assert body["gate_status"] == "passed"
    condition = body["gate_details"]["conditions"][0]
    assert condition["actual"] is None
    assert condition["triggered"] is False


def test_triaged_issues_leave_the_metrics(
    client: TestClient,
    engine: Engine,
    ingest_project: tuple[int, str],
    project_token: str,
) -> None:
    """False positives, accepted risks and won't-fix never fail a gate."""
    project_id, key = ingest_project
    attach_gate(engine, project_id, [("issues_total", ">", 0.0)])

    upload(client, project_token, make_upload(key, [make_finding()]))
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE issues SET triage_status = 'false_positive' WHERE project_id = :pid"),
            {"pid": project_id},
        )

    response = upload(client, project_token, make_upload(key, [make_finding()]))
    body = response.json()
    assert body["gate_status"] == "passed"
    assert body["gate_details"]["conditions"][0]["actual"] == 0.0


# --- status derivation (pure) ------------------------------------------------


@pytest.mark.parametrize(
    ("runs", "expected"),
    [
        ({}, "complete"),
        ({"bandit": {"status": "ok"}}, "complete"),
        ({"bandit": {"status": "ok"}, "pip-audit": {"status": "ok"}}, "complete"),
        ({"bandit": {"status": "error"}}, "incomplete"),
        ({"bandit": {"status": "ok"}, "pip-audit": {"status": "error"}}, "incomplete"),
        ({"bandit": "broken"}, "incomplete"),
        ({"bandit": None}, "incomplete"),
    ],
)
def test_derive_analysis_status(runs: dict[str, Any], expected: str) -> None:
    assert derive_analysis_status(runs) == expected
