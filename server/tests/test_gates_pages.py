"""Gates pages ``/gates`` and ``/gates/{id}`` (phase 4, T4.6).

The list pins the design's copy and both seeded gates (migration 0008's
built-in default, seed-demo's Release gate); the detail page pins the
design's window - title bar path, "Used by ... Applies to all code in
scope", the "Fail when" rows - in both of its modes: edit rows for a
``gates.admin``, plain words for everyone else. Writes are refused
without that permission and otherwise run through the same service
functions the JSON API tests already pin.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.seed import DEMO_PASSWORD, seed_demo

HTML = {"Accept": "text/html"}


def _login(client: TestClient, username: str, password: str) -> None:
    """Log in the way the browser form does (html Accept + hidden csrf)."""
    if "wadjet_csrf" not in client.cookies:
        client.get("/login")
    client.post(
        "/session?next=/",
        data={
            "username": username,
            "password": password,
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )


def _csrf(client: TestClient) -> str:
    return str(client.cookies.get("wadjet_csrf"))


def _count(engine: Engine, sql: str, **params: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def _gate_id(engine: Engine, name: str) -> int:
    return _count(engine, "SELECT id FROM quality_gates WHERE name = :n", n=name)


def _conditions(engine: Engine, gate_id: int) -> list[tuple[str, str, float]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT metric, operator, threshold FROM gate_conditions "
                "WHERE gate_id = :gid ORDER BY id"
            ),
            {"gid": gate_id},
        ).all()
    return [(str(row[0]), str(row[1]), float(row[2])) for row in rows]


def _row(body: str, needle: str) -> str:
    """The table row that mentions ``needle``, from its ``<tr>`` onward."""
    return next(segment for segment in body.split("<tr>") if needle in segment)


def _new_gate(client: TestClient, name: str) -> int:
    """Create a gate through the page and return its id."""
    created = client.post(
        "/gates",
        data={"name": name, "csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text
    location = str(created.headers["location"])
    return int(location.split("?")[0].rsplit("/", 1)[-1])


# --- the shell -------------------------------------------------------------


def test_anonymous_gates_pages_redirect_to_login(client: TestClient) -> None:
    for path in ("/gates", "/gates/1", "/gates/nonsense"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303, path
        assert response.headers["location"].startswith("/login"), path


def test_unknown_gate_is_404(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    for path in ("/gates/999999", "/gates/nonsense"):
        missing = client.get(path)
        assert missing.status_code == 404, path
        assert "Gate not found" in missing.text

    # A forged write to the same ids answers 404, not a stack of errors.
    forged = client.post("/gates/999999", data={"csrf_token": _csrf(client)}, headers=HTML)
    assert forged.status_code == 404
    assert "Gate not found" in forged.text


# --- the list --------------------------------------------------------------


def test_list_page_shows_every_gate_and_the_design_copy(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    default_id = _gate_id(engine, "Wadjet default")
    release_id = _gate_id(engine, "Release gate")

    page = client.get("/gates")
    assert page.status_code == 200
    assert 'class="on" aria-current="page">Gates</a>' in page.text
    # Design copy above the table, word for word.
    assert "Conditions read &#34;fail when&#34;." in page.text
    assert "There is no new code setting: the gate always looks at the whole project." in page.text

    default_row = _row(page.text, f'href="/gates/{default_id}"')
    assert "<b>Wadjet default</b>" in default_row
    assert "<td>6</td>" in default_row  # migration 0008's six conditions
    assert "<td>0 projects</td>" in default_row
    assert '<span class="c nt">Built-in default</span>' in default_row

    release_row = _row(page.text, f'href="/gates/{release_id}"')
    assert "<b>Release gate</b>" in release_row
    assert "<td>4</td>" in release_row
    assert "<td>1 project</td>" in release_row  # payments chose it

    # A gates.admin may start one from here.
    assert 'action="/gates"' in page.text
    assert 'name="name"' in page.text
    assert ">Create gate<" in page.text


def test_create_form_is_hidden_from_a_non_admin(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-alice", DEMO_PASSWORD)  # project_admin, not gates.admin

    page = client.get("/gates")
    assert page.status_code == 200  # reading is session-scoped (section 15.2)
    assert "Wadjet default" in page.text
    assert "New gate" not in page.text
    assert 'action="/gates"' not in page.text


# --- the detail window -----------------------------------------------------


def test_detail_window_matches_the_design(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    default_id = _gate_id(engine, "Wadjet default")

    page = client.get(f"/gates/{default_id}")
    assert page.status_code == 200
    assert "<h1>Wadjet default</h1>" in page.text
    # The design's title bar, path included.
    assert '<div class="tb">' in page.text
    assert "<b>Wadjet default</b>" in page.text
    assert f'<span class="m">/gates/{default_id}</span>' in page.text
    assert "Not used by any project yet." in page.text
    assert "Applies to all code in scope on every analysis." in page.text
    assert '<span class="c nt">Built-in default</span>' in page.text

    # Edit mode: metric/operator/threshold controls and both buttons.
    assert 'name="metric"' in page.text
    assert '<option value="issues_blocker" selected>' in page.text
    assert '<option value="coverage_line_percent" selected>' in page.text
    assert 'id="c0-threshold" name="threshold"' in page.text
    assert 'value="70"' in page.text  # the coverage condition, raw for editing
    assert ">Add condition<" in page.text
    assert ">Save gate<" in page.text
    assert 'id="condition-row"' in page.text  # the row the button appends
    # The built-in gate itself is never deletable (section 9).
    assert "Delete gate" not in page.text


def test_detail_is_read_only_without_gates_admin(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    release_id = _gate_id(engine, "Release gate")
    _login(client, "demo-alice", DEMO_PASSWORD)

    page = client.get(f"/gates/{release_id}")
    assert page.status_code == 200
    assert "Used by 1 project." in page.text
    # The design's own row: words, not controls.
    assert '<div class="gr">' in page.text
    assert "<b>Fail when</b>" in page.text
    assert '<span class="f">Blocker issues</span>' in page.text
    assert '<span class="f">is above</span>' in page.text
    assert '<span class="f">0</span>' in page.text
    assert '<span class="f">85%</span>' in page.text  # coverage reads as percent
    assert 'name="metric"' not in page.text
    assert ">Save gate<" not in page.text
    assert "Add condition" not in page.text
    assert 'id="condition-row"' not in page.text
    assert "Delete gate" not in page.text

    # Every write is one 403 that names the permission (section 7).
    save = client.post(f"/gates/{release_id}", data={"csrf_token": _csrf(client)}, headers=HTML)
    assert save.status_code == 403
    assert "Gate editing is restricted" in save.text
    assert "gates.admin" in save.text

    create = client.post("/gates", data={"name": "Nope", "csrf_token": _csrf(client)}, headers=HTML)
    assert create.status_code == 403
    assert "gates.admin" in create.text

    removed = client.post(
        f"/gates/{release_id}/delete", data={"csrf_token": _csrf(client)}, headers=HTML
    )
    assert removed.status_code == 403
    # Nothing moved: still four conditions, still named as it was.
    assert len(_conditions(engine, release_id)) == 4
    assert _count(engine, "SELECT count(*) FROM quality_gates WHERE name = 'Release gate'") == 1


# --- create ----------------------------------------------------------------


def test_admin_creates_a_gate_validates_and_audits(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    blank = client.post("/gates", data={"name": "   ", "csrf_token": _csrf(client)}, headers=HTML)
    assert blank.status_code == 400
    assert "Give the gate a name." in blank.text

    gate_id = _new_gate(client, "Create target T4.6")
    assert _conditions(engine, gate_id) == []  # starts empty; rows come next

    duplicate = client.post(
        "/gates", data={"name": "Create target T4.6", "csrf_token": _csrf(client)}, headers=HTML
    )
    assert duplicate.status_code == 400
    assert "A gate with that name already exists" in duplicate.text
    assert (
        _count(engine, "SELECT count(*) FROM quality_gates WHERE name = 'Create target T4.6'") == 1
    )

    page = client.get(str(duplicate.headers.get("location", "/gates")))
    assert page.status_code == 200
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'gate.create' AND target_id = :tid",
            tid=str(gate_id),
        )
        == 1
    )


def test_the_created_gate_lands_on_its_own_page(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    created = client.post(
        "/gates",
        data={"name": "Landing target T4.6", "csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert created.status_code == 303
    location = str(created.headers["location"])
    assert location.startswith("/gates/") and location.endswith("?saved=created")

    page = client.get(location)
    assert page.status_code == 200
    assert "Gate created. Add its conditions and save." in page.text
    assert "No conditions yet - add one and save." in page.text
    assert "<h1>Landing target T4.6</h1>" in page.text


# --- save ------------------------------------------------------------------


def test_save_replaces_conditions_and_audits(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    gate_id = _new_gate(client, "Save target T4.6")

    saved = client.post(
        f"/gates/{gate_id}",
        data={
            "metric": ["coverage_line_percent", "secrets"],
            "operator": ["<", ">"],
            "threshold": ["90", "0"],
            "csrf_token": _csrf(client),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert saved.headers["location"] == f"/gates/{gate_id}?saved=gate"
    assert _conditions(engine, gate_id) == [
        ("coverage_line_percent", "<", 90.0),
        ("secrets", ">", 0.0),
    ]
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'gate.update' AND target_id = :tid",
            tid=str(gate_id),
        )
        == 1
    )

    reloaded = client.get(f"/gates/{gate_id}?saved=gate")
    assert "Gate saved. The next analysis is judged by it." in reloaded.text
    assert 'value="90"' in reloaded.text
    assert '<option value="coverage_line_percent" selected>' in reloaded.text

    # Remove a row by posting one fewer: the list is replaced, not appended.
    fewer = client.post(
        f"/gates/{gate_id}",
        data={
            "metric": ["secrets"],
            "operator": [">"],
            "threshold": ["1"],
            "csrf_token": _csrf(client),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert fewer.status_code == 303
    assert _conditions(engine, gate_id) == [("secrets", ">", 1.0)]

    # No rows at all is the API's own reading of an empty gate: allowed.
    empty = client.post(
        f"/gates/{gate_id}",
        data={"csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert empty.status_code == 303
    assert _conditions(engine, gate_id) == []
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'gate.update' AND target_id = :tid",
            tid=str(gate_id),
        )
        == 3
    )


def test_save_refuses_bad_rows_and_keeps_them_on_screen(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    gate_id = _new_gate(client, "Bad target T4.6")

    bad_number = client.post(
        f"/gates/{gate_id}",
        data={
            "metric": ["issues_total"],
            "operator": [">"],
            "threshold": ["ten"],
            "csrf_token": _csrf(client),
        },
        headers=HTML,
    )
    assert bad_number.status_code == 400
    assert "A threshold must be a number, for example 0 or 85." in bad_number.text
    assert 'value="ten"' in bad_number.text  # what was typed stays on screen
    assert _conditions(engine, gate_id) == []

    bad_metric = client.post(
        f"/gates/{gate_id}",
        data={
            "metric": ["nonsense"],
            "operator": [">"],
            "threshold": ["0"],
            "csrf_token": _csrf(client),
        },
        headers=HTML,
    )
    assert bad_metric.status_code == 400
    assert "unknown metric" in bad_metric.text
    assert _conditions(engine, gate_id) == []

    mismatched = client.post(
        f"/gates/{gate_id}",
        data={
            "metric": ["issues_total", "secrets"],
            "operator": [">"],
            "threshold": ["0"],
            "csrf_token": _csrf(client),
        },
        headers=HTML,
    )
    assert mismatched.status_code == 400
    assert "Every condition needs a metric, an operator and a threshold." in mismatched.text
    assert _conditions(engine, gate_id) == []
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'gate.update' AND target_id = :tid",
            tid=str(gate_id),
        )
        == 0
    )


# --- delete ----------------------------------------------------------------


def test_delete_follows_the_api_rules(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    default_id = _gate_id(engine, "Wadjet default")
    release_id = _gate_id(engine, "Release gate")

    # The built-in default: no button on the page, no way past the server.
    forged = client.post(
        f"/gates/{default_id}/delete", data={"csrf_token": _csrf(client)}, headers=HTML
    )
    assert forged.status_code == 400
    assert "The built-in default gate cannot be deleted" in forged.text
    assert _count(engine, "SELECT count(*) FROM quality_gates WHERE name = 'Wadjet default'") == 1

    # In use by payments: refused until a project picks another gate.
    in_use = client.post(
        f"/gates/{release_id}/delete", data={"csrf_token": _csrf(client)}, headers=HTML
    )
    assert in_use.status_code == 400
    assert "Gate is used by 1 project(s); select another gate first" in in_use.text
    assert _count(engine, "SELECT count(*) FROM quality_gates WHERE name = 'Release gate'") == 1

    # An unused, non-built-in gate goes cleanly (section 15.2).
    gate_id = _new_gate(client, "Doomed gate T4.6")
    page = client.get(f"/gates/{gate_id}")
    assert ">Delete gate<" in page.text

    deleted = client.post(
        f"/gates/{gate_id}/delete",
        data={"csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/gates?saved=deleted"
    assert _count(engine, "SELECT count(*) FROM quality_gates WHERE id = :gid", gid=gate_id) == 0
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'gate.delete' AND target_id = :tid",
            tid=str(gate_id),
        )
        == 1
    )

    after = client.get("/gates?saved=deleted")
    assert "Gate deleted." in after.text
