"""Projects list and overview (phase 4, T4.2).

Both pages are rendered from ``seed-demo`` data, so the assertions below are
also a contract on the design: gate status first, a word with every color,
counts and coverage from the latest analysis, failing conditions at the top
of the overview. Permission-awareness is checked with a real member account.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.permissions import PERMISSION_TEMPLATES
from app.security import hash_password
from app.seed import DEMO_PASSWORD, DEMO_PROJECT_KEYS, seed_demo
from app.web.routes import timeago

HTML = {"Accept": "text/html"}


def _signup(engine: Engine, username: str, *, is_admin: bool = False) -> str:
    """Create a user with a known password and return that password."""
    password = f"pw-{username}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:u, :e, :h, :admin, TRUE)"
            ),
            {
                "u": username,
                "e": f"{username}@example.test",
                "h": hash_password(password),
                "admin": is_admin,
            },
        )
    return password


def _login(client: TestClient, username: str, password: str, next_url: str = "/") -> Any:
    """Log in the way the browser form does (html Accept + hidden csrf)."""
    if "wadjet_csrf" not in client.cookies:
        client.get("/login")
    return client.post(
        f"/session?next={next_url}",
        data={
            "username": username,
            "password": password,
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )


def _row(body: str, key: str) -> str:
    """The table row of one project, from its overview link to ``</tr>``."""
    return body.split(f'href="/projects/{key}"', 1)[1].split("</tr>", 1)[0]


def _count(engine: Engine, sql: str, **params: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def test_anonymous_project_pages_redirect_to_login(client: TestClient) -> None:
    for path in ("/", "/projects", "/projects/payments", "/projects/new"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303, path
        assert response.headers["location"].startswith("/login"), path


def test_projects_list_shows_gate_counts_coverage_and_last_analysis(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    password = _signup(engine, "listadmin", is_admin=True)
    _login(client, "listadmin", password)

    body = client.get("/").text
    assert 'class="topbar"' in body
    expected = _count(engine, "SELECT count(*) FROM projects")
    assert f">{expected} project" in body.replace("\n", "")

    # payments: failed, blocker 1 / critical 0 / high 2, 76.4% coverage.
    payments = _row(body, "payments")
    assert 'class="c bad">Failed</span>' in payments
    assert "<td>1</td>" in payments and "<td>0</td>" in payments
    assert "<td>2</td>" in payments
    assert "<td>76.4%</td>" in payments
    assert "Payments service" in payments

    # web-portal: passed with its coverage.
    portal = _row(body, "web-portal")
    assert 'class="c ok">Passed</span>' in portal
    assert "<td>92.1%</td>" in portal

    # data-pipeline: incomplete, no coverage report.
    pipeline = _row(body, "data-pipeline")
    assert 'class="c wn">Incomplete</span>' in pipeline
    assert "<td>No report</td>" in pipeline

    # Every row links to its overview, and the design's button is there.
    assert 'href="/projects/data-pipeline"' in body
    assert 'href="/projects/new">New project</a>' in body


def test_projects_list_only_shows_granted_projects(client: TestClient, engine: Engine) -> None:
    """demo-dave holds browse on payments and data-pipeline, nothing else."""
    seed_demo(engine)
    _login(client, "demo-dave", DEMO_PASSWORD)

    body = client.get("/projects").text
    assert "2 projects" in body
    assert 'href="/projects/payments"' in body
    assert 'href="/projects/data-pipeline"' in body
    assert 'href="/projects/web-portal"' not in body
    # Not an admin: no create button (section 7 hides what you cannot do).
    assert 'href="/projects/new"' not in body


def test_member_without_any_grants_gets_the_empty_state(client: TestClient, engine: Engine) -> None:
    password = _signup(engine, "nogrants")
    _login(client, "nogrants", password)

    body = client.get("/").text
    assert "0 projects" in body
    assert "No projects yet" in body
    assert 'href="/projects/new"' not in body


def test_overview_banner_lists_the_failing_conditions(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    password = _signup(engine, "ovadmin", is_admin=True)
    _login(client, "ovadmin", password)

    body = client.get("/projects/payments").text
    assert "<h1>Payments service</h1>" in body
    assert '<span class="m mu">payments</span>' in body
    # The failing conditions, each with its actual value (design copy).
    assert '<div class="ban">' in body
    assert "<b>Quality gate failed</b>" in body
    assert "on analysis #" in body
    assert "Blocker issues: 1. Fails when above 0." in body
    assert "Secrets: 1. Fails when above 0." in body
    assert "Issues: 12. Fails when above 10." in body
    assert "Line coverage: 76.4%. Fails when below 85%." in body
    # Metric cards from the same analysis snapshot.
    assert '<div class="v">12</div>Open issues' in body
    assert '<div class="v">76.4%</div>Line coverage' in body
    assert '<div class="v">1</div>Vulnerable dependencies' in body
    flagged = _count(
        engine,
        "SELECT count(*) FROM issues i JOIN projects p ON p.id = i.project_id "
        "WHERE p.key = 'payments' AND i.triage_status = 'false_positive'",
    )
    assert f'<div class="v">{flagged}</div>Flagged false positive' in body


def test_overview_banner_word_matches_the_outcome(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    password = _signup(engine, "bancolor", is_admin=True)
    _login(client, "bancolor", password)

    portal = client.get("/projects/web-portal").text
    assert '<div class="ban ok">' in portal
    assert "<b>Quality gate passed</b>" in portal

    # Incomplete scan of data-pipeline: the gate failed and says why.
    pipeline = client.get("/projects/data-pipeline").text
    assert '<div class="ban">' in pipeline
    assert "<b>Quality gate failed</b>" in pipeline
    assert "Not every scanner completed - see the scanners below." in pipeline
    assert 'class="c bad">Failed</span>' in pipeline  # bandit errored
    assert "bandit is not installed" in pipeline


def test_overview_links_to_its_issue_list(client: TestClient, engine: Engine) -> None:
    """Phase-4 reachability: the overview tabs are the hub of the project pages."""
    seed_demo(engine)
    password = _signup(engine, "hubadmin", is_admin=True)
    _login(client, "hubadmin", password)
    body = client.get("/projects/payments").text
    assert '<a class="on" href="/projects/payments">Overview</a>' in body
    assert '<a href="/projects/payments/issues">Issues</a>' in body


def test_overview_trend_scanners_and_history(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    password = _signup(engine, "trendadmin", is_admin=True)
    _login(client, "trendadmin", password)

    body = client.get("/projects/payments").text
    # Trend: one bar per analysis of the project, oldest first, labelled.
    assert "<h3>Open issues over the last 10 analyses</h3>" in body
    assert 'role="img" aria-label="Open issues per analysis: analysis #' in body
    analyses = _count(
        engine,
        "SELECT count(*) FROM analyses a JOIN projects p ON p.id = a.project_id "
        "WHERE p.key = 'payments'",
    )
    assert body.count("<i style=") == analyses

    # Scanners of the latest analysis, each with a word, plus the report.
    for label in ("Bandit", "pip-audit", "Ruff", "detect-secrets"):
        assert f"{label} " in body
    assert "Coverage report " in body
    assert 'class="c ok">Complete</span>' in body
    assert 'class="c ok">Found</span>' in body

    # Recent analyses: five newest rows with status and gate words.
    assert "<h3>Recent analyses</h3>" in body
    assert 'class="c ok">Complete</span>' in body
    assert '<td class="m">#' in body


def test_overview_of_an_unknown_or_ungranted_project_is_404(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    password = _signup(engine, "missing", is_admin=True)
    _login(client, "missing", password)

    unknown = client.get("/projects/no-such-key")
    assert unknown.status_code == 404
    assert "Project not found" in unknown.text

    # Untrusted key text never reaches the browser as markup.
    hostile = client.get("/projects/<script>alert(1)")
    assert hostile.status_code == 404
    assert "<script>alert" not in hostile.text
    assert "&lt;script&gt;" in hostile.text

    # A member without the grant gets the same 404: no existence leak.
    seed_demo(engine)
    client.cookies.clear()
    _login(client, "demo-dave", DEMO_PASSWORD)
    assert client.get("/projects/web-portal").status_code == 404


def test_overview_without_analyses_has_an_empty_state(client: TestClient, engine: Engine) -> None:
    password = _signup(engine, "freshadmin", is_admin=True)
    _login(client, "freshadmin", password)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO projects (key, name, description, created_by) "
                "VALUES ('fresh', 'Fresh project', NULL, "
                "(SELECT id FROM users WHERE username = 'freshadmin'))"
            )
        )

    body = client.get("/projects/fresh").text
    assert "<h1>Fresh project</h1>" in body
    assert "No analysis yet" in body
    assert 'class="ban' not in body  # nothing ran yet: no gate verdict
    assert 'class="v"' not in body


def test_new_project_form_creates_the_project(client: TestClient, engine: Engine) -> None:
    password = _signup(engine, "creator", is_admin=True)
    _login(client, "creator", password)

    form = client.get("/projects/new")
    assert form.status_code == 200
    assert 'action="/projects"' in form.text
    assert 'name="csrf_token"' in form.text
    assert 'name="key"' in form.text and 'name="name"' in form.text

    csrf = client.cookies.get("wadjet_csrf")
    created = client.post(
        "/projects",
        data={
            "key": "round-trip",
            "name": "Round trip",
            "description": "Made by the form.",
            "csrf_token": csrf,
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert created.status_code == 303
    assert created.headers["location"] == "/projects/round-trip"

    overview = client.get("/projects/round-trip")
    assert overview.status_code == 200
    assert "<h1>Round trip</h1>" in overview.text

    # The creator owns it (project admin template) and it is audited.
    assert _count(
        engine,
        "SELECT count(*) FROM project_grants pg JOIN projects p ON p.id = pg.project_id "
        "WHERE p.key = 'round-trip' AND pg.subject_type = 'user' AND pg.subject_id = "
        "(SELECT id FROM users WHERE username = 'creator')",
    ) == len(PERMISSION_TEMPLATES["project_admin"])
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log al JOIN users u ON u.id = al.actor_id "
            "WHERE al.action = 'project.create' AND u.username = 'creator'",
        )
        == 1
    )


def test_new_project_form_rejects_bad_and_duplicate_keys(
    client: TestClient, engine: Engine
) -> None:
    password = _signup(engine, "rejform", is_admin=True)
    _login(client, "rejform", password)
    csrf = client.cookies.get("wadjet_csrf")

    def post(key: str) -> Any:
        return client.post(
            "/projects",
            data={"key": key, "name": "Whatever", "csrf_token": csrf},
            headers=HTML,
        )

    bad = post("Bad Key!")
    assert bad.status_code == 400
    assert "key must start with" in bad.text
    assert 'value="Bad Key!"' in bad.text  # the form keeps what was typed

    reserved = post("new")
    assert reserved.status_code == 400
    assert "reserved" in reserved.text

    assert post("dup-key").status_code in (200, 303)
    duplicate = post("dup-key")
    assert duplicate.status_code == 400
    assert "already exists" in duplicate.text


def test_new_project_form_is_admin_only(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-dave", DEMO_PASSWORD)

    page = client.get("/projects/new")
    assert page.status_code == 403
    assert "Only admins can create projects" in page.text

    posted = client.post(
        "/projects",
        data={"key": "sneaky", "name": "Sneaky", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert posted.status_code == 403
    assert _count(engine, "SELECT count(*) FROM projects WHERE key = 'sneaky'") == 0


def _api_headers(client: TestClient) -> dict[str, str]:
    """Session cookies plus the CSRF header an HTMX/API client sends."""
    return {"X-CSRF-Token": client.cookies.get("wadjet_csrf", "")}


def test_api_create_project_validation_and_permissions(client: TestClient, engine: Engine) -> None:
    password = _signup(engine, "apimin", is_admin=True)
    _login(client, "apimin", password)
    headers = {**_api_headers(client), "Content-Type": "application/json"}

    created = client.post(
        "/api/v1/projects",
        json={"key": "api-made", "name": "API made", "description": None},
        headers=headers,
    )
    assert created.status_code == 201
    body = created.json()
    assert body["key"] == "api-made"
    assert isinstance(body["id"], int)
    assert _count(engine, "SELECT count(*) FROM projects WHERE key = 'api-made'") == 1

    duplicate = client.post(
        "/api/v1/projects", json={"key": "api-made", "name": "Again"}, headers=headers
    )
    assert duplicate.status_code == 409

    bad_key = client.post(
        "/api/v1/projects", json={"key": "Not A Key", "name": "Nope"}, headers=headers
    )
    assert bad_key.status_code == 422

    unknown_field = client.post(
        "/api/v1/projects",
        json={"key": "extra-field", "name": "Nope", "cli_args": "--select S"},
        headers=headers,
    )
    assert unknown_field.status_code == 422  # extra="forbid": no smuggled options

    # A member may not create projects (section 7 defines no such permission).
    client.cookies.clear()
    _login(client, "demo-dave", DEMO_PASSWORD)
    member = client.post(
        "/api/v1/projects",
        json={"key": "member-made", "name": "Nope"},
        headers={**_api_headers(client), "Content-Type": "application/json"},
    )
    assert member.status_code == 403
    assert _count(engine, "SELECT count(*) FROM projects WHERE key = 'member-made'") == 0


def test_timeago_reads_like_the_design_copy() -> None:
    now = datetime.now(timezone.utc)
    assert timeago(None) == "never"
    assert timeago(now - timedelta(seconds=10)) == "just now"
    assert timeago(now - timedelta(minutes=5)) == "5 minutes ago"
    assert timeago(now - timedelta(minutes=1)) == "1 minute ago"
    assert timeago(now - timedelta(hours=2)) == "2 hours ago"
    assert timeago(now - timedelta(days=1)) == "yesterday"
    assert timeago(now - timedelta(days=3)) == "3 days ago"
    assert timeago(now - timedelta(days=400)) == "1 year ago"
    # A naive timestamp is read as UTC; malformed input is passed through.
    assert timeago((now - timedelta(hours=3)).replace(tzinfo=None)) == "3 hours ago"
    assert timeago("not-a-date") == "not-a-date"
    assert timeago("2026-01-02T03:04:05+00:00").endswith("ago")


def test_api_projects_list_shares_the_page_visibility(client: TestClient, engine: Engine) -> None:
    """Section 12's list answers with exactly what the page shows."""
    seed_demo(engine)
    password = _signup(engine, "apilist", is_admin=True)
    _login(client, "apilist", password)

    listed = client.get("/api/v1/projects", headers=_api_headers(client))
    assert listed.status_code == 200
    entries = {row["key"]: row for row in listed.json()}
    assert set(DEMO_PROJECT_KEYS) <= set(entries)
    # An admin sees every project - the same total the page counts.
    assert len(entries) == _count(engine, "SELECT count(*) FROM projects")

    # The newest analysis travels with the row.
    payments = entries["payments"]["analysis"]
    assert payments["status"] == "complete"
    assert payments["gate_status"] in {"passed", "failed"}

    # A project that has never run reports null, not a fabricated verdict.
    created = client.post(
        "/api/v1/projects",
        json={"key": "not-scanned-yet", "name": "Not scanned yet"},
        headers={**_api_headers(client), "Content-Type": "application/json"},
    )
    assert created.status_code == 201
    fresh = client.get("/api/v1/projects", headers=_api_headers(client)).json()
    by_key = {row["key"]: row for row in fresh}
    assert by_key["not-scanned-yet"]["analysis"] is None

    # A member gets only the granted projects: one query, one rule.
    client.cookies.clear()
    _login(client, "demo-dave", DEMO_PASSWORD)
    member = client.get("/api/v1/projects", headers=_api_headers(client))
    assert {row["key"] for row in member.json()} == {"payments", "data-pipeline"}


def test_api_projects_list_needs_a_session(client: TestClient) -> None:
    assert client.get("/api/v1/projects").status_code == 401
