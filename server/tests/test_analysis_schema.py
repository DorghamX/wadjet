"""Schema tests for the analysis pipeline tables (section 4, T2.1)."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text

EXPECTED_TABLES = (
    "analyses",
    "issues",
    "issue_events",
    "issue_comments",
    "issue_requests",
)


@pytest.mark.parametrize("table", EXPECTED_TABLES)
def test_table_exists(engine: Engine, table: str) -> None:
    """Every table from section 4 exists after the migrations run."""
    with engine.begin() as conn:
        found = conn.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = current_schema() AND table_name = :t"
            ),
            {"t": table},
        ).scalar()
    assert found == 1, f"missing table {table}"


def test_issue_lifecycle_columns(engine: Engine) -> None:
    """The issue carries triage, presence and sighting columns."""
    with engine.begin() as conn:
        columns = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = 'issues'"
                )
            ).fetchall()
        }
    required = {
        "fingerprint",
        "tool",
        "rule_id",
        "severity",
        "category",
        "title",
        "file_path",
        "line_start",
        "line_end",
        "snippet",
        "snippet_norm_hash",
        "package",
        "vuln_id",
        "installed_version",
        "fixed_versions",
        "cwe",
        "description",
        "impact",
        "fix",
        "references",
        "triage_status",
        "presence",
        "triage_reason",
        "triaged_by",
        "triaged_at",
        "assignee_id",
        "first_seen_analysis_id",
        "last_seen_analysis_id",
        "resolved_at",
    }
    assert required <= columns, f"missing: {required - columns}"


def test_analysis_jsonb_columns(engine: Engine) -> None:
    """scanner_runs, metrics and gate_details are real JSONB columns."""
    with engine.begin() as conn:
        types = {
            row[0]: row[1]
            for row in conn.execute(
                text(
                    "SELECT column_name, data_type FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = 'analyses'"
                )
            ).fetchall()
        }
    assert types["scanner_runs"] == "jsonb"
    assert types["metrics"] == "jsonb"
    assert types["gate_details"] == "jsonb"


def test_issue_fingerprint_is_unique_per_project(
    engine: Engine, project_id: int, admin_user_id: int
) -> None:
    """One persistent issue per (project, fingerprint) (section 5)."""

    def _insert(fingerprint: str) -> None:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO issues (project_id, fingerprint, tool, rule_id, severity, "
                    "category, title) "
                    "VALUES (:pid, :fp, 'bandit', 'B101', 'medium', 'bug', 't')"
                ),
                {"pid": project_id, "fp": fingerprint},
            )

    _insert("fp-unique-test")
    with pytest.raises(Exception):  # noqa: B017 - driver-specific integrity error
        _insert("fp-unique-test")
    # The same fingerprint in another project is a different issue.
    with engine.begin() as conn:
        other = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES ('fp-other-project', 'Other', :uid) RETURNING id"
            ),
            {"uid": admin_user_id},
        ).scalar_one()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO issues (project_id, fingerprint, tool, rule_id, severity, "
                "category, title) "
                "VALUES (:pid, 'fp-unique-test', 'bandit', 'B101', 'medium', 'bug', 't')"
            ),
            {"pid": other},
        )


def test_event_comment_request_defaults(engine: Engine, project_id: int) -> None:
    """Issue events, comments and requests insert with their defaults."""
    with engine.begin() as conn:
        author_id = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('schema-author', 'schema-author@example.test', 'x', FALSE, TRUE) "
                "RETURNING id"
            )
        ).scalar_one()
        issue_id = conn.execute(
            text(
                "INSERT INTO issues (project_id, fingerprint, tool, rule_id, severity, "
                "category, title) VALUES (:pid, 'fp-defaults', 'bandit', 'B101', 'medium', "
                "'bug', 'assert_used') RETURNING id"
            ),
            {"pid": project_id},
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO issue_events (issue_id, type, payload) "
                "VALUES (:iid, 'created', :payload)"
            ),
            {"iid": issue_id, "payload": '{"analysis": 1}'},
        )
        conn.execute(
            text(
                "INSERT INTO issue_comments (issue_id, author_id, body_md) "
                "VALUES (:iid, :author, 'looks fine')"
            ),
            {"iid": issue_id, "author": author_id},
        )
        conn.execute(
            text(
                "INSERT INTO issue_requests (issue_id, requested_by, requested_action) "
                "VALUES (:iid, :author, 'false_positive')"
            ),
            {"iid": issue_id, "author": author_id},
        )
        state = conn.execute(
            text("SELECT state FROM issue_requests WHERE issue_id = :iid"),
            {"iid": issue_id},
        ).scalar_one()
    assert state == "pending"
