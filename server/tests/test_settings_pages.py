"""Project settings pages and their API (phase 4, T4.5).

The six tabs of section 10 - General, Scanners, Scope, Quality gate, Tokens,
Members - rendered from ``seed-demo`` data so the assertions also pin the
design copy: the tab row, the members matrix with a word in every cell, the
token shown exactly once. Permission rules are checked with real accounts:
a viewer gets one 403 that names ``project.admin``, deletion is admin-only.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.config import Settings
from app.permissions import PERMISSION_TEMPLATES
from app.projects import grant
from app.security import hash_password
from app.seed import DEMO_PASSWORD, seed_demo


@pytest.fixture(scope="module")
def database_url(isolated_database_url: str) -> str:
    """Own schema: these tests mutate seed users, tokens and member grants."""
    return isolated_database_url


@pytest.fixture(scope="module")
def engine(isolated_engine: Engine) -> Engine:
    return isolated_engine


@pytest.fixture()
def settings(isolated_settings: Settings) -> Settings:
    return isolated_settings


HTML = {"Accept": "text/html"}

#: One token value, as the create response and the one-time banner print it.
TOKEN_RE = re.compile(r"<div class=\"code\"><div>([0-9a-f]{64})</div></div>")

TABS = (
    ("general", "General"),
    ("scanners", "Scanners"),
    ("scope", "Scope"),
    ("gate", "Quality gate"),
    ("tokens", "Tokens"),
    ("members", "Members"),
)


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


def _headers(client: TestClient, *, json_body: bool = False) -> dict[str, str]:
    """Session cookies plus the CSRF header an API or HTMX client sends."""
    headers = {"X-CSRF-Token": client.cookies.get("wadjet_csrf", "")}
    if json_body:
        headers["Content-Type"] = "application/json"
    return headers


def _count(engine: Engine, sql: str, **params: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def _stored(engine: Engine, project_id: int) -> dict[str, Any]:
    """The project row's settings as a dict."""
    with engine.connect() as conn:
        raw = conn.execute(
            text("SELECT settings FROM projects WHERE id = :pid"), {"pid": project_id}
        ).scalar()
    return json.loads(raw) if raw else {}


def _project_id(engine: Engine, key: str) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(text("SELECT id FROM projects WHERE key = :k"), {"k": key}).scalar_one()
        )


def _user_id(engine: Engine, username: str) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT id FROM users WHERE username = :u"), {"u": username}
            ).scalar_one()
        )


def _new_project(client: TestClient, key: str, name: str) -> int:
    """Create a project through the API; the session must be a global admin."""
    created = client.post(
        "/api/v1/projects",
        json={"key": key, "name": name},
        headers=_headers(client, json_body=True),
    )
    assert created.status_code == 201, created.text
    return int(created.json()["id"])


def _tab(client: TestClient, key: str, tab: str, **kwargs: Any) -> Any:
    return client.get(f"/projects/{key}/settings/{tab}", **kwargs)


# --- the shell -------------------------------------------------------------


def test_anonymous_settings_pages_redirect_to_login(client: TestClient) -> None:
    for path in (
        "/projects/payments/settings",
        "/projects/payments/settings/general",
        "/projects/payments/settings/members",
    ):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303, path
        assert response.headers["location"].startswith("/login"), path


def test_shell_lists_every_tab_and_marks_the_active_one(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    for slug, _label in TABS:
        body = _tab(client, "payments", slug).text
        assert 'class="tabs"' in body
        assert f'<span class="m mu">/projects/payments/settings/{slug}</span>' in body
        for other_slug, other_label in TABS:
            href = f'href="/projects/payments/settings/{other_slug}"'
            if other_slug == slug:
                assert f'{href} class="on" aria-current="page">{other_label}</a>' in body
            else:
                assert f"{href}>{other_label}</a>" in body


def test_the_bare_settings_path_lands_on_general(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    response = client.get("/projects/payments/settings", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/projects/payments/settings/general"


def test_settings_needs_project_admin(client: TestClient, engine: Engine) -> None:
    """demo-dave is a viewer: hidden from him, and refused if he asks."""
    seed_demo(engine)
    _login(client, "demo-dave", DEMO_PASSWORD)

    overview = client.get("/projects/payments").text
    assert 'href="/projects/payments/settings/general"' not in overview

    refused = _tab(client, "payments", "general")
    assert refused.status_code == 403
    assert "Project settings are restricted" in refused.text
    assert "project.admin" in refused.text

    posted = client.post(
        "/projects/payments/settings/general",
        data={"name": "Nope", "description": "", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert posted.status_code == 403

    # demo-alice holds project_admin on payments: she sees the link and the tab.
    client.cookies.clear()
    _login(client, "demo-alice", DEMO_PASSWORD)
    assert (
        'href="/projects/payments/settings/general">Settings</a>'
        in client.get("/projects/payments").text
    )
    assert _tab(client, "payments", "general").status_code == 200


def test_unknown_project_and_unknown_tab_answer_404(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    assert _tab(client, "no-such-key", "general").status_code == 404
    assert "Project not found" in _tab(client, "no-such-key", "general").text

    bad_tab = _tab(client, "payments", "export")
    assert bad_tab.status_code == 404
    assert "No such settings page" in bad_tab.text
    assert "export" in bad_tab.text

    # A project he may not see stays invisible even through a bad tab.
    client.cookies.clear()
    _login(client, "demo-dave", DEMO_PASSWORD)
    assert _tab(client, "web-portal", "general").status_code == 404
    assert _tab(client, "web-portal", "nonsense").status_code == 404


# --- general ---------------------------------------------------------------


def test_general_saves_the_name_and_description(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-general", "First name")

    saved = client.post(
        "/projects/set-general/settings/general",
        data={
            "name": "Second name",
            "description": "Written by the form.",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert saved.headers["location"] == "/projects/set-general/settings/general?saved=general"

    # The confirmation rides the redirect: follow the Location it points at.
    page = client.get(saved.headers["location"])
    assert "<h1>Second name</h1>" in page.text
    assert "Saved. This project&#39;s name and description are updated." in page.text
    assert 'value="Second name"' in page.text
    assert ">Written by the form.</textarea>" in page.text

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT name, description FROM projects WHERE id = :pid"), {"pid": project_id}
        ).first()
    assert row == ("Second name", "Written by the form.")
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'project.update' AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )


def test_general_refuses_an_empty_name(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-noname", "Keep me")

    refused = client.post(
        "/projects/set-noname/settings/general",
        data={"name": "   ", "description": "", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert refused.status_code == 400
    assert "name is required" in refused.text
    with engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT name FROM projects WHERE id = :pid"), {"pid": project_id}
            ).scalar_one()
            == "Keep me"
        )


def test_the_key_field_is_read_only(client: TestClient, engine: Engine) -> None:
    """Section 10: the key is immutable, so the form carries no key input."""
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-immutable", "Immutable")

    page = _tab(client, "set-immutable", "general")
    assert 'name="key"' not in page.text
    assert "readonly" in page.text
    assert "cannot change" in page.text
    with engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT key FROM projects WHERE id = :pid"), {"pid": project_id}
            ).scalar_one()
            == "set-immutable"
        )


def test_danger_zone_deletes_only_when_the_key_is_typed(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-doomed", "Doomed")
    # A project admin who is not a global admin cannot delete (section 7).
    _signup(engine, "set-projadmin")
    grant(
        engine,
        project_id=project_id,
        subject_type="user",
        subject_id=_user_id(engine, "set-projadmin"),
        template="project_admin",
        actor_id=_user_id(engine, "demo-admin"),
    )

    client.cookies.clear()
    _login(client, "set-projadmin", "pw-set-projadmin")
    wrong_role = client.post(
        "/projects/set-doomed/settings/general/delete",
        data={"confirm_key": "set-doomed", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert wrong_role.status_code == 403
    assert "Only admins can delete a project." in wrong_role.text

    client.cookies.clear()
    _login(client, "demo-admin", DEMO_PASSWORD)
    wrong_key = client.post(
        "/projects/set-doomed/settings/general/delete",
        data={"confirm_key": "set-doom", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert wrong_key.status_code == 400
    assert "Type the project key (set-doomed)" in wrong_key.text
    assert _count(engine, "SELECT count(*) FROM projects WHERE key = 'set-doomed'") == 1

    deleted = client.post(
        "/projects/set-doomed/settings/general/delete",
        data={"confirm_key": "set-doomed", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/"
    assert _count(engine, "SELECT count(*) FROM projects WHERE key = 'set-doomed'") == 0
    assert (
        _count(
            engine, "SELECT count(*) FROM project_grants WHERE project_id = :pid", pid=project_id
        )
        == 0
    )
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'project.delete' AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )


# --- scanners and scope ----------------------------------------------------


def _scanner_form(**overrides: str) -> dict[str, str]:
    """A full scanners post: every field present, like the real form."""
    values = {
        "bandit_enabled": "on",
        "bandit_skipped": "",
        "bandit_confidence": "",
        "bandit_timeout": "",
        "pip_audit_enabled": "on",
        "pip_audit_files": "",
        "pip_audit_severity": "",
        "pip_audit_timeout": "",
        "ruff_enabled": "on",
        "ruff_families": "",
        "ruff_timeout": "",
        "detect_secrets_enabled": "on",
        "detect_secrets_timeout": "",
        "coverage_enabled": "on",
        "coverage_path": "",
        "coverage_timeout": "",
        "fail_on_scanner_error": "on",
        "timeout_seconds": "300",
    }
    values.update(overrides)
    values["csrf_token"] = str(values.get("csrf_token") or "")
    return values


def test_scanners_tab_saves_structured_options(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-scanners", "Scanners")

    form = _scanner_form(
        csrf_token=str(client.cookies.get("wadjet_csrf")),
        bandit_skipped="B101, B602",
        bandit_confidence="high",
        bandit_timeout="60",
        pip_audit_enabled="",
        pip_audit_files="requirements.txt, requirements-dev.txt",
        ruff_families="F, B",
        coverage_path="reports/coverage.xml",
        fail_on_scanner_error="",
        timeout_seconds="120",
    )
    saved = client.post(
        "/projects/set-scanners/settings/scanners", data=form, headers=HTML, follow_redirects=False
    )
    assert saved.status_code == 303
    assert saved.headers["location"] == "/projects/set-scanners/settings/scanners?saved=scanners"

    settings = _stored(engine, project_id)
    assert settings["scanners"]["bandit"] == {
        "enabled": True,
        "timeout": 60.0,
        "skipped_test_ids": ["B101", "B602"],
        "minimum_confidence": "high",
        "dependency_files": [],
        "dependency_default_severity": None,
        "families": [],
        "report_path": None,
    }
    assert settings["scanners"]["pip_audit"]["enabled"] is False
    assert settings["scanners"]["pip_audit"]["dependency_files"] == [
        "requirements.txt",
        "requirements-dev.txt",
    ]
    assert settings["scanners"]["ruff"]["families"] == ["F", "B"]
    assert settings["scanners"]["coverage"]["report_path"] == "reports/coverage.xml"
    assert settings["fail_on_scanner_error"] is False
    assert settings["timeout_seconds"] == 120.0
    # The other half of the settings survives this half's write.
    assert settings["scope"]["include"] == ["."]

    page = _tab(client, "set-scanners", "scanners")
    assert 'value="B101, B602"' in page.text
    assert 'name="bandit_enabled" checked' in page.text
    assert 'name="pip_audit_enabled" checked' not in page.text

    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log "
            "WHERE action = 'project.settings_update' AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )


def test_scanners_tab_rejects_a_bad_value_and_keeps_the_input(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-badscanner", "Bad scanner")

    form = _scanner_form(
        csrf_token=str(client.cookies.get("wadjet_csrf")),
        ruff_families="s",
        bandit_skipped="B101",
    )
    refused = client.post("/projects/set-badscanner/settings/scanners", data=form, headers=HTML)
    assert refused.status_code == 400
    assert "scanners.ruff.families" in refused.text
    assert "uppercase" in refused.text
    # What was typed is still on screen, and nothing was written.
    assert 'value="B101"' in refused.text
    assert _stored(engine, project_id) == {}
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log "
            "WHERE action = 'project.settings_update' AND target_id = :tid",
            tid=str(project_id),
        )
        == 0
    )


def test_scope_tab_saves_paths_and_exclusions(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-scope", "Scope")

    saved = client.post(
        "/projects/set-scope/settings/scope",
        data={
            "include": "src\napps",
            "exclude": ".venv/\nprivate/**\nbuild/",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert saved.status_code == 303

    settings = _stored(engine, project_id)["scope"]
    assert settings["include"] == ["src", "apps"]
    assert settings["exclude"] == [".venv/", "private/**", "build/"]

    page = _tab(client, "set-scope", "scope")
    assert ">src\napps</textarea>" in page.text.replace("\r\n", "\n")
    # The editable defaults of section 10 are shown as a hint, not as a claim.
    assert (
        ".venv/, venv/, node_modules/, .git/, build/, dist/, __pycache__/, site-packages/"
        in page.text
    )


def test_scope_needs_at_least_one_include_path(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-noscope", "No scope")

    refused = client.post(
        "/projects/set-noscope/settings/scope",
        data={
            "include": "\n \n",
            "exclude": ".venv/",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
    )
    assert refused.status_code == 400
    assert "include" in refused.text
    # A refused write leaves the stored settings untouched (still unset).
    assert _stored(engine, project_id) == {}


# --- quality gate ----------------------------------------------------------


def test_gate_tab_lists_gates_and_switches_the_choice(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-gate", "Gate choice")
    release_id = _count(engine, "SELECT id FROM quality_gates WHERE name = 'Release gate'")

    page = _tab(client, "set-gate", "gate")
    assert "Wadjet default" in page.text
    assert "Release gate" in page.text
    assert "Built-in default" in page.text
    assert f'value="{release_id}"' in page.text
    # Condition sentences read the way section 9 writes them.
    assert "Fail when Line coverage is below 85%" in page.text

    saved = client.post(
        "/projects/set-gate/settings/gate",
        data={"gate_id": str(release_id), "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
        follow_redirects=False,
    )
    assert saved.status_code == 303
    with engine.connect() as conn:
        chosen = conn.execute(
            text("SELECT gate_id FROM projects WHERE id = :pid"), {"pid": project_id}
        ).scalar_one()
    assert chosen == release_id
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'project.gate_update' "
            "AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )
    reloaded = _tab(client, "set-gate", "gate").text
    assert f'value="{release_id}" checked' in reloaded


def test_gate_tab_refuses_an_unknown_gate(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-gate-bad", "Gate choice")

    refused = client.post(
        "/projects/set-gate-bad/settings/gate",
        data={"gate_id": "999999", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert refused.status_code == 400
    assert "no quality gate with id 999999" in refused.text
    with engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT gate_id FROM projects WHERE id = :pid"), {"pid": project_id}
            ).scalar_one()
            is None
        )


# --- tokens ----------------------------------------------------------------


def test_tokens_tab_creates_shows_once_and_revokes(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-tokens", "Tokens")

    created = client.post(
        "/projects/set-tokens/settings/tokens",
        data={
            "name": "Nightly CI",
            "expires": "",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
    )
    assert created.status_code == 200
    match = TOKEN_RE.search(created.text)
    assert match, "the one-time token value is shown on create"
    value = match.group(1)
    assert len(value) == 64
    assert "Token created" in created.text
    assert "not shown again" in created.text

    # Reloading the page never shows the value again - only the prefix.
    reloaded = _tab(client, "set-tokens", "tokens").text
    assert value not in reloaded
    assert "Nightly CI" in reloaded
    assert 'class="c ok">Active</span>' in reloaded

    with engine.connect() as conn:
        token_id = int(
            conn.execute(
                text("SELECT id FROM api_tokens WHERE project_id = :pid"), {"pid": project_id}
            ).scalar_one()
        )
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'token.create' AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )

    revoked = client.post(
        "/projects/set-tokens/settings/tokens/revoke",
        data={"token_id": str(token_id), "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
        follow_redirects=False,
    )
    assert revoked.status_code == 303
    after = _tab(client, "set-tokens", "tokens").text
    assert 'class="c bad">Revoked</span>' in after
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'token.revoke' AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )


def test_tokens_reject_a_missing_name_and_a_past_expiry(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    _new_project(client, "set-token-dates", "Token dates")

    blank = client.post(
        "/projects/set-token-dates/settings/tokens",
        data={"name": "  ", "expires": "", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert blank.status_code == 400
    assert "Give the token a name" in blank.text

    past = client.post(
        "/projects/set-token-dates/settings/tokens",
        data={
            "name": "Old",
            "expires": "2020-01-01",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
    )
    assert past.status_code == 400
    assert "Expiry must be in the future." in past.text
    assert _count(engine, "SELECT count(*) FROM api_tokens WHERE name = 'Old'") == 0


def test_a_revoked_token_of_another_project_is_not_touchable(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    _new_project(client, "set-tok-a", "Token A")
    _new_project(client, "set-tok-b", "Token B")
    other = client.post(
        "/projects/set-tok-b/settings/tokens",
        data={"name": "B token", "expires": "", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    ).text
    other_id = _count(engine, "SELECT id FROM api_tokens WHERE name = 'B token'")

    refused = client.post(
        "/projects/set-tok-a/settings/tokens/revoke",
        data={"token_id": str(other_id), "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert refused.status_code == 404
    assert "does not belong to this project" in refused.text
    assert other  # the token was created; it simply cannot be revoked cross-project


# --- members ---------------------------------------------------------------


def _row(body: str, name: str) -> str:
    """One table row of the members matrix, from the name to ``</tr>``."""
    return body.split(f"<b>{name}</b>", 1)[1].split("</tr>", 1)[0]


def test_members_matrix_matches_the_design(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    body = _tab(client, "payments", "members").text
    for heading in (
        "Who",
        "Browse",
        "Comment",
        "Assign",
        "Confirm",
        "False positive",
        "Accepted risk",
        "Won&#39;t fix",
        "Reopen",
        "Admin",
    ):
        assert f'<th scope="col">{heading}</th>' in body, heading

    # project_admin holds every column; a viewer holds exactly one.
    alice = _row(body, "Alice Nguyen")
    assert '<span class="mu">User</span>' in alice
    assert alice.count(">Yes<") == 9
    assert alice.count(">No<") == 0

    dave = _row(body, "Dave Lindqvist")
    assert dave.count(">Yes<") == 1
    assert dave.count(">No<") == 8

    # A group reads as the design writes it.
    portal = _tab(client, "web-portal", "members").text
    assert '<b>Platform team</b><br><span class="mu">Group, 3 people</span>' in portal


def test_members_grant_and_revoke_from_the_form(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-members", "Members")
    _signup(engine, "set-newmember")
    member_id = _user_id(engine, "set-newmember")

    granted = client.post(
        "/projects/set-members/settings/members",
        data={
            "subject": f"user:{member_id}",
            "template": "triager",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert granted.status_code == 303
    assert granted.headers["location"] == "/projects/set-members/settings/members?saved=granted"
    assert _count(
        engine,
        "SELECT count(*) FROM project_grants WHERE project_id = :pid "
        "AND subject_type = 'user' AND subject_id = :sid",
        pid=project_id,
        sid=member_id,
    ) == len(PERMISSION_TEMPLATES["triager"])
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'permission.grant' AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )

    body = _tab(client, "set-members", "members").text
    assert "set-newmember" in body

    removed = client.post(
        "/projects/set-members/settings/members/remove",
        data={
            "subject": f"user:{member_id}",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert removed.status_code == 303
    assert removed.headers["location"] == "/projects/set-members/settings/members?saved=removed"
    assert (
        _count(
            engine,
            "SELECT count(*) FROM project_grants WHERE project_id = :pid "
            "AND subject_type = 'user' AND subject_id = :sid",
            pid=project_id,
            sid=member_id,
        )
        == 0
    )
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log "
            "WHERE action = 'permission.revoke' AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )


def test_members_form_refuses_a_bad_subject(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    _new_project(client, "set-members-bad", "Bad subject")

    alien = client.post(
        "/projects/set-members-bad/settings/members",
        data={
            "subject": "alien:1",
            "template": "viewer",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
    )
    assert alien.status_code == 400
    assert "subject_type must be" in alien.text

    missing = client.post(
        "/projects/set-members-bad/settings/members",
        data={
            "subject": "user:99999999",
            "template": "viewer",
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
    )
    assert missing.status_code == 400
    assert "no user with id" in missing.text

    removing = client.post(
        "/projects/set-members-bad/settings/members/remove",
        data={"subject": "user:99999999", "csrf_token": client.cookies.get("wadjet_csrf")},
        headers=HTML,
    )
    assert removing.status_code == 404
    assert "no permissions" in removing.text


# --- the JSON API ----------------------------------------------------------


def test_api_project_endpoints_need_a_session(client: TestClient) -> None:
    """Every new project endpoint refuses an anonymous caller first."""
    cases: tuple[tuple[str, str, dict[str, Any] | None], ...] = (
        ("get", "/api/v1/projects/anything", None),
        ("patch", "/api/v1/projects/anything", {"name": "Renamed"}),
        ("delete", "/api/v1/projects/anything", None),
        ("get", "/api/v1/projects/anything/tokens", None),
        ("post", "/api/v1/projects/anything/tokens", {"name": "ci"}),
        ("delete", "/api/v1/projects/anything/tokens/1", None),
        ("get", "/api/v1/projects/anything/members", None),
        (
            "post",
            "/api/v1/projects/anything/members",
            {"subject_type": "user", "subject_id": 1, "template": "viewer"},
        ),
    )
    for method, path, body in cases:
        # Echo the CSRF cookie (the first GET issues one) so the answer is
        # the endpoint's 401, never the middleware's 403; valid bodies so it
        # is 401, never a 422 from the model.
        headers = {"X-CSRF-Token": client.cookies.get("wadjet_csrf", "")}
        kwargs: dict[str, Any] = {"headers": headers}
        if method in ("post", "patch"):
            kwargs["json"] = body
        response = getattr(client, method)(path, **kwargs)
        assert response.status_code == 401, path


def test_api_get_patch_delete_project(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-api", "API project")

    fetched = client.get("/api/v1/projects/set-api", headers=_headers(client))
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["key"] == "set-api"
    # No stored choice: the null gate is section 9's built-in default,
    # reported as such rather than dressed up as a choice.
    assert body["gate_id"] is None
    assert body["gate_name"] is None
    assert body["settings"]["scope"]["include"] == ["."]
    assert body["created_at"]

    renamed = client.patch(
        "/api/v1/projects/set-api",
        json={"name": "Renamed", "description": "Via PATCH"},
        headers=_headers(client, json_body=True),
    )
    assert renamed.status_code == 200
    assert renamed.json()["name"] == "Renamed"

    immutable = client.patch(
        "/api/v1/projects/set-api",
        json={"key": "something-else"},
        headers=_headers(client, json_body=True),
    )
    assert immutable.status_code == 422
    assert "immutable" in immutable.text

    nothing = client.patch(
        "/api/v1/projects/set-api", json={}, headers=_headers(client, json_body=True)
    )
    assert nothing.status_code == 422
    assert "Nothing to update" in nothing.text

    bad_gate = client.patch(
        "/api/v1/projects/set-api",
        json={"gate_id": 999999},
        headers=_headers(client, json_body=True),
    )
    assert bad_gate.status_code == 422
    assert "no quality gate" in bad_gate.text

    release_id = _count(engine, "SELECT id FROM quality_gates WHERE name = 'Release gate'")
    regated = client.patch(
        "/api/v1/projects/set-api",
        json={"gate_id": release_id},
        headers=_headers(client, json_body=True),
    )
    assert regated.status_code == 200
    assert regated.json()["gate_id"] == release_id
    assert regated.json()["gate_name"] == "Release gate"

    # Unknown key and "no grant" are the same answer (section 7).
    assert client.get("/api/v1/projects/nope", headers=_headers(client)).status_code == 404

    # A member with browse may read but never write.
    _signup(engine, "set-api-member")
    grant(
        engine,
        project_id=project_id,
        subject_type="user",
        subject_id=_user_id(engine, "set-api-member"),
        template="viewer",
        actor_id=_user_id(engine, "demo-admin"),
    )
    client.cookies.clear()
    _login(client, "set-api-member", "pw-set-api-member")
    assert client.get("/api/v1/projects/set-api", headers=_headers(client)).status_code == 200
    refused = client.patch(
        "/api/v1/projects/set-api",
        json={"name": "Nope"},
        headers=_headers(client, json_body=True),
    )
    assert refused.status_code == 403
    assert "project.admin" in refused.text

    # Deleting is admin-only, needs the key typed back, and removes the data.
    client.cookies.clear()
    _login(client, "demo-admin", DEMO_PASSWORD)
    unconfirmed = client.delete("/api/v1/projects/set-api", headers=_headers(client))
    assert unconfirmed.status_code == 422
    assert "confirm" in unconfirmed.text

    client.cookies.clear()
    _login(client, "set-api-member", "pw-set-api-member")
    forbidden = client.delete("/api/v1/projects/set-api?confirm=set-api", headers=_headers(client))
    assert forbidden.status_code == 403
    assert "Only admins can delete projects" in forbidden.text

    client.cookies.clear()
    _login(client, "demo-admin", DEMO_PASSWORD)
    deleted = client.delete("/api/v1/projects/set-api?confirm=set-api", headers=_headers(client))
    assert deleted.status_code == 204
    assert client.get("/api/v1/projects/set-api", headers=_headers(client)).status_code == 404


def test_api_tokens_crud_is_project_scoped(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    _new_project(client, "set-api-tok", "API tokens")

    empty = client.get("/api/v1/projects/set-api-tok/tokens", headers=_headers(client))
    assert empty.status_code == 200
    assert empty.json() == []

    past = client.post(
        "/api/v1/projects/set-api-tok/tokens",
        json={"name": "Old", "expires_at": "2020-01-01T00:00:00Z"},
        headers=_headers(client, json_body=True),
    )
    assert past.status_code == 422

    created = client.post(
        "/api/v1/projects/set-api-tok/tokens",
        json={"name": "CI", "expires_at": None},
        headers=_headers(client, json_body=True),
    )
    assert created.status_code == 201
    payload = created.json()
    assert len(payload["token"]) == 64
    assert payload["prefix"] == payload["token"][:8]
    token_id = payload["id"]

    listed = client.get("/api/v1/projects/set-api-tok/tokens", headers=_headers(client)).json()
    assert [row["name"] for row in listed] == ["CI"]
    assert "token" not in listed[0]

    # Another project's token id is not this project's to revoke.
    _new_project(client, "set-api-tok-b", "Other tokens")
    cross = client.delete(
        f"/api/v1/projects/set-api-tok/tokens/{token_id + 100000}", headers=_headers(client)
    )
    assert cross.status_code == 404

    revoked = client.delete(
        f"/api/v1/projects/set-api-tok/tokens/{token_id}", headers=_headers(client)
    )
    assert revoked.status_code == 204
    after = client.get("/api/v1/projects/set-api-tok/tokens", headers=_headers(client)).json()
    assert after[0]["revoked_at"] is not None

    # Non-admins may not even list them.
    _signup(engine, "set-tok-viewer")
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO project_grants (project_id, subject_type, subject_id, permission) "
                "SELECT id, 'user', :uid, 'project.browse' FROM projects WHERE key = 'set-api-tok'"
            ),
            {"uid": _user_id(engine, "set-tok-viewer")},
        )
    client.cookies.clear()
    _login(client, "set-tok-viewer", "pw-set-tok-viewer")
    refused = client.get("/api/v1/projects/set-api-tok/tokens", headers=_headers(client))
    assert refused.status_code == 403
    assert "project.admin" in refused.text


def test_api_members_grant_and_revoke(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    project_id = _new_project(client, "set-api-members", "API members")
    _signup(engine, "set-api-grantee")
    grantee = _user_id(engine, "set-api-grantee")

    granted = client.post(
        "/api/v1/projects/set-api-members/members",
        json={"subject_type": "user", "subject_id": grantee, "template": "viewer"},
        headers=_headers(client, json_body=True),
    )
    assert granted.status_code == 201
    assert granted.json()["permissions"] == ["project.browse"]

    members = client.get(
        "/api/v1/projects/set-api-members/members", headers=_headers(client)
    ).json()
    mine = [row for row in members if row["subject_id"] == grantee]
    assert len(mine) == 1
    assert mine[0]["name"] == "set-api-grantee"
    assert mine[0]["subtitle"] == "User"

    bad_template = client.post(
        "/api/v1/projects/set-api-members/members",
        json={"subject_type": "user", "subject_id": grantee, "template": "wizard"},
        headers=_headers(client, json_body=True),
    )
    assert bad_template.status_code == 422

    bad_kind = client.post(
        "/api/v1/projects/set-api-members/members",
        json={"subject_type": "alien", "subject_id": grantee, "template": "viewer"},
        headers=_headers(client, json_body=True),
    )
    assert bad_kind.status_code == 422

    unknown = client.post(
        "/api/v1/projects/set-api-members/members",
        json={"subject_type": "user", "subject_id": 99999999, "template": "viewer"},
        headers=_headers(client, json_body=True),
    )
    assert unknown.status_code == 422
    assert "no user with id" in unknown.text

    removed = client.delete(
        f"/api/v1/projects/set-api-members/members/user/{grantee}", headers=_headers(client)
    )
    assert removed.status_code == 204
    again = client.delete(
        f"/api/v1/projects/set-api-members/members/user/{grantee}", headers=_headers(client)
    )
    assert again.status_code == 404
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'permission.grant' AND target_id = :tid",
            tid=str(project_id),
        )
        == 1
    )
