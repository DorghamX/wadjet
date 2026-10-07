"""The request-action workflow (section 8): create, approve, decline, cancel.

Two halves that must agree because they call one service: the detail
page's panel and timeline (the design's "Request an action" card, the
inbox's Approve/Decline copy on the row itself) and the JSON API from the
section 12 table. The rules under test are the section 8 ones - targets
filtered by the permission the action needs, only the target decides, only
the requester cancels, approval applies the flag as the target quoting the
message - plus section 4's vocabulary, which the seed now speaks too.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.security import hash_password
from app.seed import DEMO_PASSWORD, seed_demo

API = "/api/v1"
LIST = "/projects/payments/issues"
HTML = {"Accept": "text/html"}

#: Section 4's vocabulary for issue_requests.requested_action.
VOCABULARY = {"confirm", "false_positive", "accepted_risk", "wont_fix", "fix_help", "other"}


# --- fixtures and helpers --------------------------------------------------


@pytest.fixture()
def restored(engine: Engine) -> Iterator[None]:
    """Seed, snapshot, and put the demo data back on the way out.

    The list tests count the seed and ``seed_demo`` will not re-seed what
    is already there, so every request these tests open must not stick.
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


def _csrf(client: TestClient) -> str:
    if "wadjet_csrf" not in client.cookies:
        client.get("/login")
    return client.cookies.get("wadjet_csrf") or ""


def _api_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("wadjet_csrf", "")}


def _issue_id(
    engine: Engine,
    *,
    key: str = "payments",
    status: str | None = None,
    rule_id: str | None = None,
) -> int:
    sql = "SELECT i.id FROM issues i JOIN projects p ON p.id = i.project_id WHERE p.key = :key"
    params: dict[str, Any] = {"key": key}
    for column, value in (("triage_status", status), ("rule_id", rule_id)):
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


def _open_request(engine: Engine, issue_id: int) -> Any:
    """The newest request on one issue, with the people's names."""
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT r.*, u.username AS requester, t.username AS target "
                "FROM issue_requests r "
                "JOIN users u ON u.id = r.requested_by "
                "LEFT JOIN users t ON t.id = r.target_user_id "
                "WHERE r.issue_id = :iid ORDER BY r.id DESC LIMIT 1"
            ),
            {"iid": issue_id},
        ).one()


def _create(
    client: TestClient,
    engine: Engine,
    *,
    issue_id: int,
    action: str = "false_positive",
    target: str = "demo-carol",
    message: str = "This looks like a test fixture leaking through.",
    follow: bool = False,
) -> Any:
    """Post the panel's form as whoever is logged in on this client."""
    return client.post(
        f"{LIST}/{issue_id}/requests",
        data={
            "csrf_token": _csrf(client),
            "action": action,
            "target": str(_user_id(engine, target)),
            "message": message,
        },
        headers=HTML,
        follow_redirects=follow,
    )


# --- the panel and creating ------------------------------------------------


def test_panel_offers_section_4_actions_and_only_real_targets(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """The design's card, speaking section 4: values are actions, never
    statuses, and the target list is everybody who can decide - minus you."""
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    body = client.get(f"{LIST}/{issue}").text
    panel = body.split("<h3>Request an action</h3>", 1)[1]

    for value in ("confirm", "false_positive", "accepted_risk", "wont_fix", "fix_help"):
        assert f'value="{value}"' in panel
    assert 'value="confirmed"' not in panel  # the triage status word never travels
    assert "Ask for fix help" in panel  # asking for a hand beside the flags

    # Targets: holders of the permission, each saying what they can do.
    assert "Carol Reyes (can confirm issues" in panel
    assert "assign issues" in panel  # fix_help's target says it too
    assert "Dave Lindqvist (can" not in panel  # a viewer can decide nothing
    assert "Bob Okafor (can" not in panel  # and you never ask yourself


def test_create_request_from_the_panel_lands_in_the_timeline(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    response = _create(client, engine, issue_id=issue, follow=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"{LIST}/{issue}"

    row = _open_request(engine, issue)
    assert row.requested_action == "false_positive"
    assert row.state == "pending"
    assert row.requester == "demo-bob"
    assert row.target == "demo-carol"
    assert row.message == "This looks like a test fixture leaking through."

    body = client.get(f"{LIST}/{issue}").text
    assert "Bob Okafor asked Carol Reyes to mark this as a false positive" in body
    assert "This looks like a test fixture leaking through." in body
    assert '<span class="c wn">Pending</span>' in body


def test_create_request_needs_issue_request_permission(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-dave")  # viewer: browse only
    issue = _issue_id(engine, status="open")
    before = _count(engine, "SELECT count(*) FROM issue_requests")
    response = _create(client, engine, issue_id=issue)
    assert response.status_code == 400
    assert "issue.request permission required." in response.text
    assert "Nothing changed." in response.text
    assert _count(engine, "SELECT count(*) FROM issue_requests") == before


def test_create_request_message_rules(client: TestClient, engine: Engine, restored: None) -> None:
    """The message is required (section 8): at least ten real characters."""
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    response = _create(client, engine, issue_id=issue, message="too short")
    assert response.status_code == 400
    assert "at least 10 characters" in response.text
    assert (
        _count(engine, "SELECT count(*) FROM issue_requests WHERE issue_id = :iid", iid=issue) == 0
    )


def test_cannot_request_an_action_you_can_take(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Section 8's audience is people *without* the permission: alice is
    told to use her buttons instead of asking for what she already has."""
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    response = _create(client, engine, issue_id=issue)
    assert response.status_code == 400
    assert "set the status yourself" in response.text
    assert (
        _count(engine, "SELECT count(*) FROM issue_requests WHERE issue_id = :iid", iid=issue) == 0
    )


def test_target_must_hold_the_permission_the_action_needs(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """The panel never offers dave, and the server refuses him anyway."""
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    response = _create(client, engine, issue_id=issue, target="demo-dave")
    assert response.status_code == 400
    assert "does not hold the permission" in response.text
    assert (
        _count(engine, "SELECT count(*) FROM issue_requests WHERE issue_id = :iid", iid=issue) == 0
    )


def test_cannot_ask_yourself(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    response = _create(client, engine, issue_id=issue, target="demo-bob")
    assert response.status_code == 400
    assert "cannot ask yourself" in response.text


def test_duplicate_pending_request_is_refused(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    assert _create(client, engine, issue_id=issue).status_code == 303
    response = _create(client, engine, issue_id=issue)
    assert response.status_code == 400
    assert "already waiting for an answer" in response.text
    assert (
        _count(
            engine,
            "SELECT count(*) FROM issue_requests WHERE issue_id = :iid "
            "AND requested_action = 'false_positive' AND state = 'pending'",
            iid=issue,
        )
        == 1
    )


def test_approved_seeded_requests_show_their_note_without_controls(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """b006's seeded fix_help request is decided: the note shows, the
    buttons do not - state from the row, not from a stale event."""
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, rule_id="B006")
    body = client.get(f"{LIST}/{issue}").text
    assert "help fix this" in body  # fix_help's timeline phrase
    assert '<span class="c ok">Approved</span>' in body
    assert "Replaced the default with None in the next release." in body
    assert ">Cancel request</button>" not in body  # nothing left to cancel


# --- deciding: approve, decline, cancel ------------------------------------


def test_approve_applies_the_flag_as_the_target_with_the_message(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """The heart of section 8: the target decides, the flag lands with the
    requester's message as its reason, and both facts show on the page."""
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    message = "Confirmed against the fixture in staging."
    assert _create(client, engine, issue_id=issue, message=message).status_code == 303
    request_id = int(_open_request(engine, issue).id)

    # As the requester: a cancel button and no note box.
    mine = client.get(f"{LIST}/{issue}").text
    assert f'action="/requests/{request_id}/resolve"' in mine
    assert ">Cancel request</button>" in mine
    assert f'id="note-{request_id}"' not in mine

    # As the target: the design's inbox buttons on the row itself.
    _login(client, "demo-carol", DEMO_PASSWORD)
    theirs = client.get(f"{LIST}/{issue}").text
    assert ">Approve and flag</button>" in theirs
    assert ">Decline</button>" in theirs
    assert f'id="note-{request_id}"' in theirs

    response = client.post(
        f"/requests/{request_id}/resolve",
        data={
            "csrf_token": _csrf(client),
            "resolution": "approve",
            "note": "Checked the fixture myself.",
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303

    with engine.connect() as conn:
        issue_row = conn.execute(
            text("SELECT triage_status, triage_reason, triaged_by FROM issues WHERE id = :id"),
            {"id": issue},
        ).one()
    assert issue_row.triage_status == "false_positive"
    assert issue_row.triage_reason == message  # the message *is* the reason
    assert issue_row.triaged_by == _user_id(engine, "demo-carol")  # attributed to the target

    request_row = _open_request(engine, issue)
    assert request_row.state == "approved"
    assert request_row.resolved_by == _user_id(engine, "demo-carol")
    assert request_row.resolved_note == "Checked the fixture myself."
    assert request_row.resolved_at is not None

    body = client.get(f"{LIST}/{issue}").text
    assert "Status: False positive" in body
    assert '<span class="c ok">Approved</span>' in body
    assert "Checked the fixture myself." in body  # the note beside the decision
    assert ">Approve and flag</button>" not in body  # decided: no buttons


def test_decline_leaves_the_issue_alone(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    assert _create(client, engine, issue_id=issue).status_code == 303
    request_id = int(_open_request(engine, issue).id)

    _login(client, "demo-carol", DEMO_PASSWORD)
    response = client.post(
        f"/requests/{request_id}/resolve",
        data={
            "csrf_token": _csrf(client),
            "resolution": "decline",
            "note": "Declined: the scanner sees it every run.",
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303

    with engine.connect() as conn:
        status = conn.execute(
            text("SELECT triage_status FROM issues WHERE id = :id"), {"id": issue}
        ).scalar_one()
    assert status == "open"  # declining decides nothing about the issue
    request_row = _open_request(engine, issue)
    assert request_row.state == "declined"
    assert request_row.resolved_note == "Declined: the scanner sees it every run."

    body = client.get(f"{LIST}/{issue}").text
    assert '<span class="c bad">Declined</span>' in body
    assert "the scanner sees it every run" in body


def test_only_the_requester_cancels_and_only_while_pending(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    assert _create(client, engine, issue_id=issue).status_code == 303
    request_id = int(_open_request(engine, issue).id)

    # The target may not cancel somebody else's ask.
    _login(client, "demo-carol", DEMO_PASSWORD)
    denied = client.post(
        f"/requests/{request_id}/resolve",
        data={"csrf_token": _csrf(client), "resolution": "cancel"},
        headers=HTML,
    )
    assert denied.status_code == 400
    assert "Only the person who asked" in denied.text

    # The requester may - once. The second time there is nothing to cancel.
    _login(client, "demo-bob", DEMO_PASSWORD)
    cancelled = client.post(
        f"/requests/{request_id}/resolve",
        data={"csrf_token": _csrf(client), "resolution": "cancel"},
        headers=HTML,
        follow_redirects=False,
    )
    assert cancelled.status_code == 303
    assert _open_request(engine, issue).state == "cancelled"
    again = client.post(
        f"/requests/{request_id}/resolve",
        data={"csrf_token": _csrf(client), "resolution": "cancel"},
        headers=HTML,
    )
    assert again.status_code == 400
    assert "was already cancelled" in again.text
    assert '<span class="c nt">Cancelled</span>' in client.get(f"{LIST}/{issue}").text


def test_only_the_target_may_decide(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    assert _create(client, engine, issue_id=issue).status_code == 303
    request_id = int(_open_request(engine, issue).id)

    response = client.post(
        f"/requests/{request_id}/resolve",
        data={"csrf_token": _csrf(client), "resolution": "approve"},
        headers=HTML,
    )
    assert response.status_code == 400
    assert "Only the person it was sent to" in response.text
    with engine.connect() as conn:
        status = conn.execute(
            text("SELECT triage_status FROM issues WHERE id = :id"), {"id": issue}
        ).scalar_one()
    assert status == "open"


def test_fix_help_approval_changes_no_status(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """fix_help sets nothing: an approval is a yes to helping, not a flag.
    The button says only "Approve" - there is no flag to apply."""
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    assert (
        _create(
            client,
            engine,
            issue_id=issue,
            action="fix_help",
            message="Could somebody take a look at this one too?",
        ).status_code
        == 303
    )
    request_id = int(_open_request(engine, issue).id)

    _login(client, "demo-carol", DEMO_PASSWORD)
    page = client.get(f"{LIST}/{issue}").text
    assert ">Approve</button>" in page
    assert ">Approve and flag</button>" not in page

    response = client.post(
        f"/requests/{request_id}/resolve",
        data={"csrf_token": _csrf(client), "resolution": "approve"},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _open_request(engine, issue).state == "approved"
    with engine.connect() as conn:
        status = conn.execute(
            text("SELECT triage_status FROM issues WHERE id = :id"), {"id": issue}
        ).scalar_one()
    assert status == "open"  # unchanged: no flag was asked for


def test_request_outside_your_projects_shares_one_404(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Section 7 for requests: unknown id and somebody else's request are
    the same answer, so an id is never confirmed from outside."""
    _signup(engine, "t51-outsider")
    seed_demo(engine)
    _login(client, "t51-outsider", "pw-t51-outsider")
    with engine.connect() as conn:
        real = int(
            conn.execute(text("SELECT id FROM issue_requests ORDER BY id LIMIT 1")).scalar_one()
        )

    unseen = client.post(
        f"/requests/{real}/resolve",
        data={"csrf_token": _csrf(client), "resolution": "approve"},
        headers=HTML,
    )
    unknown = client.post(
        "/requests/99999999/resolve",
        data={"csrf_token": _csrf(client), "resolution": "approve"},
        headers=HTML,
    )
    assert unseen.status_code == unknown.status_code == 404
    assert "in any project you can see" in unseen.text
    assert "in any project you can see" in unknown.text


# --- the JSON API (section 12) ---------------------------------------------


def test_api_creates_a_request(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    response = client.post(
        f"{API}/issues/{issue}/requests",
        json={
            "action": "false_positive",
            "target_user_id": _user_id(engine, "demo-carol"),
            "message": "The fixture is in the repository history.",
        },
        headers=_api_headers(client),
    )
    assert response.status_code == 201
    data = response.json()
    assert data["state"] == "pending"
    assert data["action"] == "false_positive"
    assert data["requested_by"]["username"] == "demo-bob"
    assert data["target"]["username"] == "demo-carol"
    assert data["resolved_by"] is None
    assert data["issue_id"] == issue


def test_api_create_refuses_what_the_panel_never_offers(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    url = f"{API}/issues/{issue}/requests"
    headers = _api_headers(client)

    short = client.post(
        url,
        json={
            "action": "false_positive",
            "target_user_id": _user_id(engine, "demo-carol"),
            "message": "no",
        },
        headers=headers,
    )
    assert short.status_code == 422
    assert "at least 10 characters" in short.json()["detail"]

    wrong_target = client.post(
        url,
        json={
            "action": "false_positive",
            "target_user_id": _user_id(engine, "demo-dave"),
            "message": "A perfectly reasonable message here.",
        },
        headers=headers,
    )
    assert wrong_target.status_code == 422
    assert "does not hold the permission" in wrong_target.json()["detail"]

    unknown_action = client.post(
        url,
        json={
            "action": "banana",
            "target_user_id": _user_id(engine, "demo-carol"),
            "message": "A perfectly reasonable message here.",
        },
        headers=headers,
    )
    assert unknown_action.status_code == 422
    assert "Unknown requested action" in unknown_action.json()["detail"]

    unknown_issue = client.post(
        f"{API}/issues/99999999/requests",
        json={
            "action": "false_positive",
            "target_user_id": _user_id(engine, "demo-carol"),
            "message": "A perfectly reasonable message here.",
        },
        headers=headers,
    )
    assert unknown_issue.status_code == 404
    assert unknown_issue.json() == {"detail": "No such issue"}


def test_api_create_needs_issue_request_and_no_own_flag(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-alice")
    issue = _issue_id(engine, status="open")
    own_flag = client.post(
        f"{API}/issues/{issue}/requests",
        json={
            "action": "confirm",
            "target_user_id": _user_id(engine, "demo-carol"),
            "message": "Could you confirm this one for me please?",
        },
        headers=_api_headers(client),
    )
    assert own_flag.status_code == 403
    assert "set the status yourself" in own_flag.json()["detail"]

    _login(client, "demo-dave", DEMO_PASSWORD)
    no_permission = client.post(
        f"{API}/issues/{issue}/requests",
        json={
            "action": "fix_help",
            "target_user_id": _user_id(engine, "demo-carol"),
            "message": "Could you look at this one for me please?",
        },
        headers=_api_headers(client),
    )
    assert no_permission.status_code == 403
    assert no_permission.json()["detail"] == "issue.request permission required."


def test_api_resolve_by_role_and_state(client: TestClient, engine: Engine, restored: None) -> None:
    _signed_in(client, engine, "demo-bob")
    issue = _issue_id(engine, status="open")
    created = client.post(
        f"{API}/issues/{issue}/requests",
        json={
            "action": "false_positive",
            "target_user_id": _user_id(engine, "demo-carol"),
            "message": "A fixture leaking into the repository history.",
        },
        headers=_api_headers(client),
    )
    request_id = int(created.json()["id"])
    resolve_url = f"{API}/requests/{request_id}/resolve"

    # Unknown and ungranted share one answer.
    missing = client.post(
        f"{API}/requests/99999999/resolve",
        json={"resolution": "approve"},
        headers=_api_headers(client),
    )
    assert missing.status_code == 404
    assert missing.json() == {"detail": "No such request"}

    # An unknown resolution is a 422, not a silent no-op.
    _login(client, "demo-carol", DEMO_PASSWORD)
    bad = client.post(
        resolve_url,
        json={"resolution": "shrug"},
        headers=_api_headers(client),
    )
    assert bad.status_code == 422
    assert "Unknown resolution" in bad.json()["detail"]

    # The requester may not decide their own ask.
    _login(client, "demo-bob", DEMO_PASSWORD)
    wrong_role = client.post(
        resolve_url, json={"resolution": "approve"}, headers=_api_headers(client)
    )
    assert wrong_role.status_code == 403
    assert "Only the person it was sent to" in wrong_role.json()["detail"]

    # The target decides; the flag lands with the message as its reason.
    _login(client, "demo-carol", DEMO_PASSWORD)
    approved = client.post(
        resolve_url,
        json={"resolution": "approve", "note": "Seen and agreed."},
        headers=_api_headers(client),
    )
    assert approved.status_code == 200
    data = approved.json()
    assert data["state"] == "approved"
    assert data["resolved_by"]["username"] == "demo-carol"
    assert data["resolved_note"] == "Seen and agreed."
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT triage_status, triage_reason, triaged_by FROM issues WHERE id = :id"),
            {"id": issue},
        ).one()
    assert row.triage_status == "false_positive"
    assert row.triage_reason == "A fixture leaking into the repository history."
    assert row.triaged_by == _user_id(engine, "demo-carol")

    # Decided is decided: a second answer changes nothing.
    twice = client.post(resolve_url, json={"resolution": "decline"}, headers=_api_headers(client))
    assert twice.status_code == 422
    assert "already approved" in twice.json()["detail"]


def test_api_requests_need_a_session(client: TestClient, engine: Engine, restored: None) -> None:
    with engine.connect() as conn:
        real = int(
            conn.execute(text("SELECT id FROM issue_requests ORDER BY id LIMIT 1")).scalar_one()
        )
    # A post with no cookies at all skips CSRF and still finds no session.
    posted = client.post(f"{API}/requests/{real}/resolve", json={"resolution": "approve"})
    assert posted.status_code == 401
    assert posted.json() == {"detail": "Authentication required"}


def test_seed_speaks_section_4_vocabulary(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """The demo data stores what the service writes: section 4's bare
    spelling, no legacy ``flag_*`` anywhere."""
    seed_demo(engine)
    with engine.connect() as conn:
        actions = {
            str(row[0])
            for row in conn.execute(text("SELECT DISTINCT requested_action FROM issue_requests"))
        }
    assert actions
    assert actions <= VOCABULARY
