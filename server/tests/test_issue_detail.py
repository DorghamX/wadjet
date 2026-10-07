"""Issue detail: triage, assignment, comments, timeline and bulk (T4.4).

The page half is asserted against the design's detail window: severity word
with its color edge, the code block with the flagged line lit, the rail of
controls that changes shape with the viewer's permissions - and the view the
design actually draws, a developer who cannot change the status, getting the
request panel instead of the buttons and the sentence that says why.

The mutating half leans on one fixture: ``seed_demo`` is idempotent and the
list tests count the seed (11 open, 1 blocker ...), so everything these tests
flag, assign or comment is put back on the way out.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.security import hash_password
from app.seed import DEMO_PASSWORD, seed_demo
from app.web.issue_detail import _event_line

HTML = {"Accept": "text/html"}

LIST = "/projects/payments/issues"


# --- fixtures and helpers --------------------------------------------------


@pytest.fixture()
def restored(engine: Engine) -> Iterator[None]:
    """Put the demo data back the way it was found.

    The list tests count the seed and ``seed_demo`` will not re-seed what is
    already there, so a triage that sticks would show up as "10 open" two
    files later. Seed, snapshot the mutable issue columns and the id of every
    append-only table, and on the way out truncate what was added and put the
    columns back. Test-created users and sessions stay, as they always have.
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
            for table in (
                "issue_events",
                "issue_comments",
                "issue_requests",
                "audit_log",
                "notifications",
            )
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
    response = _login(client, username, DEMO_PASSWORD)
    assert response.status_code == 303


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


def _signup(engine: Engine, username: str) -> str:
    """A user with a known password and no grants anywhere."""
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


def _csrf(client: TestClient) -> str:
    if "wadjet_csrf" not in client.cookies:
        client.get("/login")
    return client.cookies.get("wadjet_csrf") or ""


def _issue_id(
    engine: Engine,
    *,
    key: str = "payments",
    status: str | None = None,
    rule_id: str | None = None,
    severity: str | None = None,
) -> int:
    """One seeded issue, picked by what you can name about it."""
    sql = "SELECT i.id FROM issues i JOIN projects p ON p.id = i.project_id WHERE p.key = :key"
    params: dict[str, Any] = {"key": key}
    for column, value in (("triage_status", status), ("rule_id", rule_id), ("severity", severity)):
        if value is not None:
            sql += f" AND i.{column} = :{column}"
            params[column] = value
    sql += " ORDER BY i.id LIMIT 1"
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def _open_ids(engine: Engine, how_many: int) -> list[int]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT i.id FROM issues i JOIN projects p ON p.id = i.project_id "
                "WHERE p.key = 'payments' AND i.triage_status = 'open' "
                "ORDER BY i.id LIMIT :n"
            ),
            {"n": how_many},
        ).all()
    return [int(row[0]) for row in rows]


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


def _issue_row(engine: Engine, issue_id: int) -> Any:
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT triage_status, triage_reason, triaged_by, triaged_at, assignee_id "
                "FROM issues WHERE id = :id"
            ),
            {"id": issue_id},
        ).one()


# --- the page: the design's window ----------------------------------------


def test_detail_page_is_the_design_window_for_a_developer(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Bob (developer) gets the exact view the design draws for this story."""
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, rule_id="B006")
    response = client.get(f"{LIST}/{issue}")
    assert response.status_code == 200
    body = response.text

    # Left column, in the design's order: severity + rule, title, place, code.
    assert '<span class="sv s4">Medium</span>' in body
    assert '<span class="mu">Ruff B006</span>' in body
    assert '<h3 style="font-size:20px">B006: mutable default argument</h3>' in body
    assert "src/payments/routes.py, line 19. First seen in analysis #" in body
    assert '<div class="code">' in body
    assert '<div class="h"> 19  def quote(items=[], rate_table=RATES):</div>' in body
    for heading in ("<h3>What it is</h3>", "<h3>Impact on the app</h3>", "<h3>How to fix</h3>"):
        assert heading in body

    # The design's story: no flag permission, so the buttons are there but
    # dead, and the sentence under them says why.
    assert "<h3>Status: Open</h3>" in body
    assert "disabled>Mark confirmed</button>" in body
    assert "disabled>Mark false positive</button>" in body
    # Literal template text is not escaped; button labels (expressions) are.
    assert "You can't change the status. Ask someone who can." in body
    assert 'id="triage-reason"' not in body

    # The request panel replaces the buttons; the targets name the capability
    # the design shows ("Lina (can flag false positives)").
    assert "<h3>Request an action</h3>" in body
    assert "flag false positives" in body
    assert 'id="request-message"' in body
    assert ">Send request</button>" in body
    assert "Bob Okafor (can" not in body  # he cannot do it, he cannot be asked

    # What a developer may still use: assign, comment, read the activity.
    assert 'id="assignee-select"' in body
    assert '<label for="comment-body">Comment</label>' in body
    assert "<h3>Activity</h3>" in body
    assert "Found in analysis #" in body


def test_detail_page_hides_what_the_viewer_cannot_use(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Dave (viewer): no comment box, no request panel, no assign control."""
    _signed_in(client, engine, "demo-dave")
    issue = _issue_id(engine, severity="blocker")
    assert client.get(f"{LIST}/{issue}").status_code == 200
    body = client.get(f"{LIST}/{issue}").text

    assert "You can't comment on this issue." in body
    assert 'for="comment-body"' not in body
    assert "<h3>Request an action</h3>" not in body  # no issue.request either
    assert 'id="assignee-select"' not in body
    assert "disabled>Mark confirmed</button>" in body


def test_detail_page_shows_live_controls_to_a_project_admin(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Alice holds every flag permission: buttons enabled, reason box there."""
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, severity="blocker")
    body = client.get(f"{LIST}/{issue}").text

    assert ">Mark confirmed</button>" in body
    assert ">Mark false positive</button>" in body
    assert "disabled>Mark confirmed</button>" not in body
    assert 'id="triage-reason"' in body
    assert "You can't change the status" not in body
    # She needs nobody's help, so the request panel stays away.
    assert "<h3>Request an action</h3>" not in body


def test_issue_titles_in_the_list_link_to_the_detail_page(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    assert f'href="{LIST}/' in client.get(LIST).text


def test_anonymous_detail_page_redirects_to_login(
    client: TestClient, engine: Engine, restored: None
) -> None:
    seed_demo(engine)
    issue = _issue_id(engine, status="open")
    response = client.get(f"{LIST}/{issue}", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_unknown_issue_is_404_in_a_project_you_can_see(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    response = client.get(f"{LIST}/99999999")
    assert response.status_code == 404
    assert "No issue #99999999" in response.text


def test_ungranted_project_answers_like_an_unknown_project(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Section 7: somebody else's project must be indistinguishable."""
    password = _signup(engine, "t44-outsider")
    seed_demo(engine)
    _login(client, "t44-outsider", password)
    issue = _issue_id(engine, status="open")

    unseen = client.get(f"{LIST}/{issue}")
    unknown = client.get(f"/projects/no-such-key/issues/{issue}")
    assert unseen.status_code == unknown.status_code == 404
    assert "No project with the key" in unseen.text
    assert "No project with the key" in unknown.text


# --- triage ----------------------------------------------------------------


def test_flagging_records_reason_actor_event_and_audit(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    response = client.post(
        f"{LIST}/{issue}/triage",
        data={
            "csrf_token": _csrf(client),
            "status": "false_positive",
            "reason": "Leaked fixture in the repo",
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"{LIST}/{issue}"

    row = _issue_row(engine, issue)
    assert row.triage_status == "false_positive"
    assert row.triage_reason == "Leaked fixture in the repo"
    assert row.triaged_by == _user_id(engine, "demo-alice")
    assert row.triaged_at is not None

    with engine.connect() as conn:
        event = conn.execute(
            text(
                "SELECT type, payload FROM issue_events "
                "WHERE issue_id = :iid AND type = 'status_changed' ORDER BY id DESC LIMIT 1"
            ),
            {"iid": issue},
        ).one()
    assert event.type == "status_changed"
    assert event.payload == {"status": "false_positive", "reason": "Leaked fixture in the repo"}
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'flag.false_positive' "
            "AND target_type = 'issue' AND target_id = :tid",
            tid=str(issue),
        )
        == 1
    )

    # The page tells it in words: status panel and timeline both.
    body = client.get(f"{LIST}/{issue}").text
    assert "Status: False positive" in body
    assert "marked this as a false positive" in body
    assert "Alice Nguyen" in body
    assert "Leaked fixture in the repo" in body


def test_short_reason_changes_nothing(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    events_before = _count(
        engine,
        "SELECT count(*) FROM issue_events WHERE issue_id = :iid AND type = 'status_changed'",
        iid=issue,
    )
    response = client.post(
        f"{LIST}/{issue}/triage",
        data={"csrf_token": _csrf(client), "status": "false_positive", "reason": "nope"},
        headers=HTML,
    )
    assert response.status_code == 400
    assert "at least 10 characters" in response.text
    assert "<h1>Issue #" in response.text  # the whole page, error and all
    assert _issue_row(engine, issue).triage_status == "open"
    assert (
        _count(
            engine,
            "SELECT count(*) FROM issue_events WHERE issue_id = :iid AND type = 'status_changed'",
            iid=issue,
        )
        == events_before
    )


def test_flagging_without_the_permission_changes_nothing(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    response = client.post(
        f"{LIST}/{issue}/triage",
        data={
            "csrf_token": _csrf(client),
            "status": "confirmed",
            "reason": "I would like this to be confirmed",
        },
        headers=HTML,
    )
    assert response.status_code == 400
    assert "flag.confirm permission required" in response.text
    assert _issue_row(engine, issue).triage_status == "open"


def test_reopen_is_recorded_as_flag_reopen(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="false_positive")
    response = client.post(
        f"{LIST}/{issue}/triage",
        data={"csrf_token": _csrf(client), "status": "open", "reason": ""},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    row = _issue_row(engine, issue)
    assert row.triage_status == "open"
    assert row.triage_reason is None
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'flag.reopen' "
            "AND target_type = 'issue' AND target_id = :tid",
            tid=str(issue),
        )
        == 1
    )
    assert "reopened this" in client.get(f"{LIST}/{issue}").text


def test_same_status_flag_writes_nothing(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Re-flagging an open issue as open is a no-op, not a second entry."""
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    events_before = _count(
        engine,
        "SELECT count(*) FROM issue_events WHERE issue_id = :iid AND type = 'status_changed'",
        iid=issue,
    )
    audits_before = _count(
        engine,
        "SELECT count(*) FROM audit_log WHERE target_type = 'issue' AND target_id = :tid",
        tid=str(issue),
    )
    response = client.post(
        f"{LIST}/{issue}/triage",
        data={"csrf_token": _csrf(client), "status": "open", "reason": ""},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert (
        _count(
            engine,
            "SELECT count(*) FROM issue_events WHERE issue_id = :iid AND type = 'status_changed'",
            iid=issue,
        )
        == events_before
    )
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE target_type = 'issue' AND target_id = :tid",
            tid=str(issue),
        )
        == audits_before
    )


def test_htmx_triage_answers_with_the_partial_not_a_redirect(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    response = client.post(
        f"{LIST}/{issue}/triage",
        data={
            "csrf_token": _csrf(client),
            "status": "accepted_risk",
            "reason": "Behind the VPN and monitored by the SOC",
        },
        headers={**HTML, "HX-Request": "true"},
    )
    assert response.status_code == 200
    assert not response.history  # a partial is an answer, not a detour
    assert '<div class="g g3">' in response.text
    assert "<h1>Issue #" not in response.text  # the shell stays behind
    assert "Status: Accepted risk" in response.text


# --- assignment ------------------------------------------------------------


def test_assigning_a_member_records_the_name_in_the_timeline(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    carol = _user_id(engine, "demo-carol")

    response = client.post(
        f"{LIST}/{issue}/assign",
        data={"csrf_token": _csrf(client), "assignee_id": str(carol)},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _issue_row(engine, issue).assignee_id == carol

    with engine.connect() as conn:
        event = conn.execute(
            text(
                "SELECT payload FROM issue_events WHERE issue_id = :iid "
                "AND type = 'assigned' ORDER BY id DESC LIMIT 1"
            ),
            {"iid": issue},
        ).one()
    assert event.payload == {"assignee_id": carol, "assignee": "Carol Reyes"}

    body = client.get(f"{LIST}/{issue}").text
    assert "Bob Okafor assigned this to Carol Reyes" in body

    # Unassigning is the same control with the empty value.
    response = client.post(
        f"{LIST}/{issue}/assign",
        data={"csrf_token": _csrf(client), "assignee_id": ""},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _issue_row(engine, issue).assignee_id is None
    assert "Bob Okafor unassigned this" in client.get(f"{LIST}/{issue}").text


def test_assigning_a_non_member_changes_nothing(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    _signup(engine, "t44-not-a-member")
    outsider = _user_id(engine, "t44-not-a-member")
    issue = _issue_id(engine, status="open")

    response = client.post(
        f"{LIST}/{issue}/assign",
        data={"csrf_token": _csrf(client), "assignee_id": str(outsider)},
        headers=HTML,
    )
    assert response.status_code == 400
    assert "member of this project" in response.text
    assert _issue_row(engine, issue).assignee_id is None


def test_viewer_cannot_assign(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-dave")
    issue = _issue_id(engine, status="open")
    response = client.post(
        f"{LIST}/{issue}/assign",
        data={"csrf_token": _csrf(client), "assignee_id": str(_user_id(engine, "demo-bob"))},
        headers=HTML,
    )
    assert response.status_code == 400
    assert "issue.assign permission required" in response.text
    assert _issue_row(engine, issue).assignee_id is None


# --- comments --------------------------------------------------------------


def test_comment_renders_a_sanitized_markdown_subset(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    raw = "**strong** and <script>alert(1)</script>"
    response = client.post(
        f"{LIST}/{issue}/comments",
        data={"csrf_token": _csrf(client), "body": raw},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303

    body = client.get(f"{LIST}/{issue}").text
    assert "<strong>strong</strong>" in body  # the subset renders
    assert "<script>alert" not in body  # the raw tag never reaches the page
    assert "&lt;script&gt;" in body  # it arrives escaped, not gone
    assert "<b>Bob Okafor</b>" in body  # the comment row names its author

    # The stored body stays exactly as typed, so an edit starts from yours.
    with engine.connect() as conn:
        stored = conn.execute(
            text(
                "SELECT body_md FROM issue_comments WHERE issue_id = :iid ORDER BY id DESC LIMIT 1"
            ),
            {"iid": issue},
        ).scalar_one()
    assert stored == raw


def test_comment_needs_issue_comment_permission(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-dave")
    issue = _issue_id(engine, status="open")
    before = _count(engine, "SELECT count(*) FROM issue_comments WHERE issue_id = :iid", iid=issue)
    response = client.post(
        f"{LIST}/{issue}/comments",
        data={"csrf_token": _csrf(client), "body": "Can I say something here?"},
        headers=HTML,
    )
    assert response.status_code == 400
    assert "issue.comment permission required" in response.text
    assert (
        _count(engine, "SELECT count(*) FROM issue_comments WHERE issue_id = :iid", iid=issue)
        == before
    )


def test_empty_comment_is_refused(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    response = client.post(
        f"{LIST}/{issue}/comments",
        data={"csrf_token": _csrf(client), "body": "   "},
        headers=HTML,
    )
    assert response.status_code == 400
    assert "Write something first." in response.text


def test_comment_edit_and_delete_roundtrip(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    client.post(
        f"{LIST}/{issue}/comments",
        data={"csrf_token": _csrf(client), "body": "First draft."},
        headers=HTML,
        follow_redirects=False,
    )
    with engine.connect() as conn:
        comment_id = int(
            conn.execute(
                text(
                    "SELECT id FROM issue_comments WHERE issue_id = :iid ORDER BY id DESC LIMIT 1"
                ),
                {"iid": issue},
            ).scalar_one()
        )

    edit = client.post(
        f"{LIST}/{issue}/comments/{comment_id}/edit",
        data={"csrf_token": _csrf(client), "body": "Second draft."},
        headers=HTML,
        follow_redirects=False,
    )
    assert edit.status_code == 303
    body = client.get(f"{LIST}/{issue}").text
    assert "Second draft." in body
    assert "(edited)" in body
    assert "First draft." not in body

    delete = client.post(
        f"{LIST}/{issue}/comments/{comment_id}/delete",
        data={"csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert delete.status_code == 303
    assert "Second draft." not in client.get(f"{LIST}/{issue}").text
    with engine.connect() as conn:
        deleted = conn.execute(
            text("SELECT deleted_at FROM issue_comments WHERE id = :cid"), {"cid": comment_id}
        ).scalar_one()
    assert deleted is not None  # kept with the fact of it, not destroyed


def test_only_the_author_or_an_admin_can_touch_a_comment(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-carol")
    issue = _issue_id(engine, status="open")
    client.post(
        f"{LIST}/{issue}/comments",
        data={"csrf_token": _csrf(client), "body": "Carol was here."},
        headers=HTML,
        follow_redirects=False,
    )
    with engine.connect() as conn:
        comment_id = int(
            conn.execute(
                text(
                    "SELECT id FROM issue_comments WHERE issue_id = :iid ORDER BY id DESC LIMIT 1"
                ),
                {"iid": issue},
            ).scalar_one()
        )

    # Bob may neither edit nor delete somebody else's words.
    _login(client, "demo-bob", DEMO_PASSWORD)
    denied = client.post(
        f"{LIST}/{issue}/comments/{comment_id}/edit",
        data={"csrf_token": _csrf(client), "body": "Bob was here too."},
        headers=HTML,
    )
    assert denied.status_code == 400
    assert "your own comments" in denied.text
    denied = client.post(
        f"{LIST}/{issue}/comments/{comment_id}/delete",
        data={"csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert denied.status_code == 400
    assert "author or an admin" in denied.text

    # The global admin can delete any of them (section 8).
    _login(client, "demo-admin", DEMO_PASSWORD)
    removed = client.post(
        f"{LIST}/{issue}/comments/{comment_id}/delete",
        data={"csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert removed.status_code == 303
    with engine.connect() as conn:
        deleted = conn.execute(
            text("SELECT deleted_at FROM issue_comments WHERE id = :cid"), {"cid": comment_id}
        ).scalar_one()
    assert deleted is not None


# --- the timeline ----------------------------------------------------------


def test_timeline_merges_events_comments_and_requests_newest_first(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """One feed: the scan's entry, the pending ask, and the new comment."""
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="false_positive")  # has an event + a request
    client.post(
        f"{LIST}/{issue}/comments",
        data={"csrf_token": _csrf(client), "body": "On it - checking the fixture now."},
        headers=HTML,
        follow_redirects=False,
    )
    body = client.get(f"{LIST}/{issue}").text

    assert '<ul class="tl">' in body
    # The seeded request, with its live state as a word and a color.
    request_line = "asked Carol Reyes to mark this as a false positive"
    assert request_line in body
    assert '<span class="c wn">Pending</span>' in body
    assert body.count(request_line) == 1  # once - not echoed by any event
    # The comment, with its author, rendered from its own row.
    assert "On it - checking the fixture now." in body
    assert body.count("<b>Bob Okafor</b>") == 1
    # The scan's created entry is still part of the story.
    assert "Found in analysis #" in body
    # Newest first: the fresh comment precedes the two-day-old request.
    assert body.index("On it - checking the fixture now.") < body.index(request_line)


def test_event_lines_read_as_design_sentences() -> None:
    """Every event type the timeline can meet, in one deterministic unit."""

    def ev(
        kind: str, payload: dict[str, Any], actor: str | None = "Alice Nguyen"
    ) -> dict[str, Any]:
        return {
            "type": kind,
            "payload": payload,
            "actor_name": actor,
            "actor_username": "demo-alice",
        }

    assert _event_line(ev("created", {"analysis": 119})) == "Found in analysis #119"
    assert _event_line(ev("resolved_by_scan", {"analysis": 120})) == (
        "No longer present after analysis #120"
    )
    assert _event_line(ev("reopened_by_scan", {"analysis": 121})) == "Found again in analysis #121"
    assert _event_line(ev("flag_carried_over", {"analysis": 122, "status": "false_positive"})) == (
        "Carried over as a false positive in analysis #122"
    )
    assert _event_line(ev("assigned", {"assignee": "Carol Reyes"})) == (
        "Alice Nguyen assigned this to Carol Reyes"
    )
    assert _event_line(ev("assigned", {"assignee": None})) == "Alice Nguyen unassigned this"
    assert _event_line(ev("status_changed", {"status": "open"})) == ("Alice Nguyen reopened this")
    assert (
        _event_line(ev("status_changed", {"status": "accepted_risk", "reason": "Scanned twice"}))
        == 'Alice Nguyen marked this as an accepted risk: "Scanned twice"'
    )
    # The seed still writes its older word for the same event.
    assert _event_line(ev("triaged", {"status": "wont_fix"})) == (
        "Alice Nguyen marked this as won't fix"
    )
    # Unknown types still read as a sentence rather than a traceback.
    assert _event_line(ev("something_else", {})) == "Alice Nguyen something else"


# --- bulk triage -----------------------------------------------------------


def test_bulk_bar_offers_itself_only_to_those_who_can_flag(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    allowed = client.get(LIST).text
    assert 'id="bulk-status"' in allowed
    assert 'name="ids"' in allowed

    _login(client, "demo-bob", DEMO_PASSWORD)
    refused = client.get(LIST).text
    assert 'id="bulk-status"' not in refused
    assert 'name="ids"' not in refused  # no checkboxes without the permission


def test_bulk_triage_flags_every_selected_issue(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue_ids = _open_ids(engine, 2)
    response = client.post(
        f"{LIST}/bulk",
        data={
            "csrf_token": _csrf(client),
            "bulk_status": "confirmed",
            "reason": "Reviewed both in one pass",
            "ids": [str(value) for value in issue_ids],
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith(LIST)

    for issue_id in issue_ids:
        row = _issue_row(engine, issue_id)
        assert row.triage_status == "confirmed"
        assert row.triage_reason == "Reviewed both in one pass"
        assert row.triaged_by == _user_id(engine, "demo-alice")
        assert (
            _count(
                engine,
                "SELECT count(*) FROM issue_events WHERE issue_id = :iid "
                "AND type = 'status_changed'",
                iid=issue_id,
            )
            == 1
        )
    assert "Status: Confirmed" in client.get(f"{LIST}/{issue_ids[0]}").text


def test_bulk_failure_changes_not_one_of_the_selected(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Validation runs before the first write, so "Nothing changed" is true."""
    _signed_in(client, engine, "demo-alice")
    issue_ids = _open_ids(engine, 2)
    response = client.post(
        f"{LIST}/bulk",
        data={
            "csrf_token": _csrf(client),
            "bulk_status": "false_positive",
            "reason": "no",
            "ids": [str(value) for value in issue_ids],
        },
        headers=HTML,
    )
    assert response.status_code == 400
    assert "Nothing changed." in response.text
    assert "at least 10 characters" in response.text
    assert "<h1>Issues</h1>" in response.text  # the list, explaining itself
    for issue_id in issue_ids:
        assert _issue_row(engine, issue_id).triage_status == "open"


def test_bulk_without_permission_changes_nothing(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue_ids = _open_ids(engine, 2)
    response = client.post(
        f"{LIST}/bulk",
        data={
            "csrf_token": _csrf(client),
            "bulk_status": "confirmed",
            "reason": "Please and thank you",
            "ids": [str(value) for value in issue_ids],
        },
        headers=HTML,
    )
    assert response.status_code == 400
    assert "flag.confirm permission required" in response.text
    for issue_id in issue_ids:
        assert _issue_row(engine, issue_id).triage_status == "open"


def _open_count(engine: Engine, key: str) -> int:
    return _count(
        engine,
        "SELECT count(*) FROM issues i JOIN projects p ON p.id = i.project_id "
        "WHERE p.key = :key AND i.triage_status = 'open'",
        key=key,
    )


def test_bulk_select_all_follows_the_filters(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    portal_open = _open_count(engine, "web-portal")
    response = client.post(
        f"{LIST}/bulk",
        data={
            "csrf_token": _csrf(client),
            "bulk_status": "confirmed",
            "reason": "Swept every open issue in one go",
            "all": "1",
            "status": "open",  # the mirror the page posts with the form
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _open_count(engine, "payments") == 0  # every one of them
    assert _open_count(engine, "web-portal") == portal_open  # project-scoped


def test_bulk_never_touches_another_projects_issue(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")  # alice holds nothing on web-portal
    foreign = _issue_id(engine, key="web-portal")
    with engine.connect() as conn:
        before = conn.execute(
            text("SELECT triage_status FROM issues WHERE id = :id"), {"id": foreign}
        ).scalar_one()
    response = client.post(
        f"{LIST}/bulk",
        data={
            "csrf_token": _csrf(client),
            "bulk_status": "wont_fix",
            "reason": "This was never our issue anyway",
            "ids": [str(foreign)],
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303  # selected nothing it may touch
    with engine.connect() as conn:
        after = conn.execute(
            text("SELECT triage_status FROM issues WHERE id = :id"), {"id": foreign}
        ).scalar_one()
    assert after == before
