"""seed-demo: one transaction, every page's data (section 17, T4.0)."""

from __future__ import annotations

from sqlalchemy import Engine, text

from app.gate import evaluate_gate
from app.permissions import Permission, can
from app.security import verify_password
from app.seed import DEMO_PASSWORD, DEMO_PROJECT_KEYS, DEMO_USERS, seed_demo
from wadjet_schema import ProjectSettings

DEMO_KEY_LIST = ", ".join(f"'{key}'" for key in DEMO_PROJECT_KEYS)
DEMO_USERNAMES = tuple(username for username, *_rest in DEMO_USERS)


def _count(engine: Engine, sql: str, **params: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def _id(engine: Engine, table: str, column: str, value: str) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text(f'SELECT id FROM "{table}" WHERE {column} = :value'), {"value": value}
            ).scalar_one()
        )


def test_seed_creates_the_full_demo_dataset(engine: Engine) -> None:
    """Every table the UI reads gets rows, and a second run is a no-op."""
    seed_demo(engine)
    assert seed_demo(engine) == {}  # idempotent (test_cli may have seeded first)

    expectations = {
        "users": (
            "SELECT count(*) FROM users WHERE username LIKE 'demo-%'",
            len(DEMO_USERS),
        ),
        "groups": ("SELECT count(*) FROM groups WHERE name = 'Platform team'", 1),
        "group_members": (
            "SELECT count(*) FROM group_members gm JOIN groups g ON g.id = gm.group_id "
            "WHERE g.name = 'Platform team'",
            3,
        ),
        "projects": (
            f"SELECT count(*) FROM projects WHERE key IN ({DEMO_KEY_LIST})",
            3,
        ),
        "grants": (
            f"SELECT count(*) FROM project_grants pg JOIN projects p ON p.id = pg.project_id "
            f"WHERE p.key IN ({DEMO_KEY_LIST})",
            38,
        ),
        "gates": ("SELECT count(*) FROM quality_gates WHERE name = 'Release gate'", 1),
        "gate_conditions": (
            "SELECT count(*) FROM gate_conditions gc JOIN quality_gates q ON q.id = gc.gate_id "
            "WHERE q.name = 'Release gate'",
            4,
        ),
        "analyses": (
            f"SELECT count(*) FROM analyses a JOIN projects p ON p.id = a.project_id "
            f"WHERE p.key IN ({DEMO_KEY_LIST})",
            9,
        ),
        "issues": (
            f"SELECT count(*) FROM issues i JOIN projects p ON p.id = i.project_id "
            f"WHERE p.key IN ({DEMO_KEY_LIST})",
            22,
        ),
        "issue_events": (
            f"SELECT count(*) FROM issue_events e JOIN issues i ON i.id = e.issue_id "
            f"JOIN projects p ON p.id = i.project_id WHERE p.key IN ({DEMO_KEY_LIST})",
            32,  # 22 created + 8 triaged + 2 resolved_by_scan
        ),
        "issue_comments": (
            f"SELECT count(*) FROM issue_comments c JOIN issues i ON i.id = c.issue_id "
            f"JOIN projects p ON p.id = i.project_id WHERE p.key IN ({DEMO_KEY_LIST})",
            4,
        ),
        "issue_requests": (
            f"SELECT count(*) FROM issue_requests r JOIN issues i ON i.id = r.issue_id "
            f"JOIN projects p ON p.id = i.project_id WHERE p.key IN ({DEMO_KEY_LIST})",
            3,
        ),
        "tokens": (
            f"SELECT count(*) FROM api_tokens t JOIN projects p ON p.id = t.project_id "
            f"WHERE p.key IN ({DEMO_KEY_LIST})",
            3,
        ),
        "audit entries": (
            "SELECT count(*) FROM audit_log al JOIN users u ON u.id = al.actor_id "
            "WHERE u.username LIKE 'demo-%'",
            6,
        ),
    }
    for name, (sql, expected) in expectations.items():
        assert _count(engine, sql) == expected, name

    # The demo accounts share one password that actually verifies.
    with engine.connect() as conn:
        hashed = conn.execute(
            text("SELECT password_hash FROM users WHERE username = :name"),
            {"name": DEMO_USERS[0][0]},
        ).scalar_one()
    assert verify_password(DEMO_PASSWORD, str(hashed))


def test_seed_gate_story_matches_the_issue_table(engine: Engine) -> None:
    """The latest analysis of each project recomputes to exactly what is stored."""
    expected = {"payments": "failed", "web-portal": "passed", "data-pipeline": "failed"}
    for key, want in expected.items():
        with engine.connect() as conn:
            project_id = int(
                conn.execute(
                    text("SELECT id FROM projects WHERE key = :key"), {"key": key}
                ).scalar_one()
            )
            latest = (
                conn.execute(
                    text(
                        "SELECT id, status, gate_status, gate_details, metrics FROM analyses "
                        "WHERE project_id = :pid ORDER BY created_at DESC, id DESC LIMIT 1"
                    ),
                    {"pid": project_id},
                )
                .mappings()
                .one()
            )
            stored_metrics = latest["metrics"]
            uploaded = (
                {"coverage_line_percent": stored_metrics["coverage_line_percent"]}
                if "coverage_line_percent" in stored_metrics
                else {}
            )
            # Recompute from TODAY's issues (no issue_metrics override): the seed
            # must keep the latest analysis consistent with the issue table.
            status, details, metrics = evaluate_gate(
                conn,
                project_id,
                analysis_status=str(latest["status"]),
                uploaded_metrics=uploaded,
            )
        assert latest["gate_status"] == want == status
        assert latest["gate_details"]["conditions"] == details
        assert stored_metrics == metrics

    # The incomplete scan really is incomplete, with the synthetic row first.
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT a.status, a.gate_details FROM analyses a "
                "JOIN projects p ON p.id = a.project_id "
                "WHERE p.key = 'data-pipeline' AND a.status = 'incomplete'"
            )
        ).one()
    conditions = row[1]["conditions"]
    assert row[0] == "incomplete"
    assert conditions[0]["metric"] == "all_scanners_completed"
    assert conditions[0]["triggered"] is True
    coverage = next(c for c in conditions if c["metric"] == "coverage_line_percent")
    assert coverage["actual"] is None  # no coverage report, fail closed


def test_seed_settings_validate_against_the_schema(engine: Engine) -> None:
    """The stored settings JSON is one ProjectSettings document, never a legacy blob."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(f"SELECT key, settings FROM projects WHERE key IN ({DEMO_KEY_LIST})")
        ).fetchall()
    assert {row[0] for row in rows} == set(DEMO_PROJECT_KEYS)
    for key, raw in rows:
        settings = ProjectSettings.model_validate_json(raw)
        if key == "payments":
            assert settings.scanners.ruff.families == ["F", "B", "C90", "PLE"]
            assert settings.scanners.coverage.report_path == "coverage.xml"
            assert settings.scope.include == ["src", "tests"]
        elif key == "data-pipeline":
            assert settings.scanners.pip_audit.dependency_files == ["requirements.txt"]
        else:  # web-portal: pure defaults
            assert settings == ProjectSettings()

    # The custom gate is attached to payments only.
    assert (
        _count(
            engine,
            f"SELECT count(*) FROM projects p JOIN quality_gates q ON q.id = p.gate_id "
            f"WHERE p.key IN ({DEMO_KEY_LIST}) AND q.name = 'Release gate'",
        )
        == 1
    )


def test_seed_grants_match_the_permission_templates(engine: Engine) -> None:
    """User grants, group grants and the admin flag all resolve through can()."""
    alice = _id(engine, "users", "username", "demo-alice")
    dave = _id(engine, "users", "username", "demo-dave")
    payments = _id(engine, "projects", "key", "payments")
    portal = _id(engine, "projects", "key", "web-portal")

    # Direct project_admin grant.
    assert can(engine, alice, Permission.PROJECT_ADMIN, payments)
    assert can(engine, alice, Permission.FLAG_CONFIRM, payments)
    # alice is in the Platform team, which holds triager on web-portal.
    assert can(engine, alice, Permission.FLAG_FALSE_POSITIVE, portal)
    # The viewer template is browse only.
    assert can(engine, dave, Permission.PROJECT_BROWSE, payments)
    assert not can(engine, dave, Permission.FLAG_CONFIRM, payments)
    assert not can(engine, dave, Permission.ISSUE_COMMENT, payments)
    # alice has no grants on data-pipeline of her own; the Platform team does.
    pipeline = _id(engine, "projects", "key", "data-pipeline")
    assert not can(engine, alice, Permission.FLAG_CONFIRM, pipeline)
