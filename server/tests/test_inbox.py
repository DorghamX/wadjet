"""The inbox (section 14): waiting decisions, sent requests, notifications.

The panels are the design's copy - "Waiting for you (1)", the sentence
with the message in front of the decision, the chip-per-outcome sent
list - plus the notifications section 14 requires, all of it built from
live rows. What is under test beyond the page itself: section 8's
"creates a pending request and a notification" and "both sides get
notifications" (the target is told of the ask, the other side of the
outcome), and the section 12 inbox endpoints.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.security import hash_password
from app.seed import DEMO_PASSWORD, seed_demo

API = "/api/v1/notifications"
LIST = "/projects/payments/issues"
HTML = {"Accept": "text/html"}


# --- fixtures and helpers --------------------------------------------------


@pytest.fixture()
def restored(engine: Engine) -> Iterator[None]:
    """Seed, snapshot, and put the demo data back on the way out."""
    seed_demo(engine)
    with engine.connect() as conn:
        issues = conn.execute(
            text(
                "SELECT id, triage_status, triage_reason, triaged_by, triaged_at, "
                "assignee_id FROM issues"
            )
        ).all()
        notes = conn.execute(text("SELECT id, read_at FROM notifications")).all()
        requests = conn.execute(
            text(
                "SELECT id, state, resolved_by, resolved_note, resolved_at, updated_at "
                "FROM issue_requests"
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
        # Marking read stamps a seeded row; put the demo's unread state back.
        for note_id, read_at in notes:
            conn.execute(
                text("UPDATE notifications SET read_at = :read WHERE id = :id"),
                {"id": note_id, "read": read_at},
            )
        # Deciding from the inbox stamps the seeded request itself.
        for request_id, state, by, note, at, updated in requests:
            conn.execute(
                text(
                    "UPDATE issue_requests SET state = :state, resolved_by = :by, "
                    "resolved_note = :note, resolved_at = :at, updated_at = :updated "
                    "WHERE id = :id"
                ),
                {
                    "id": request_id,
                    "state": state,
                    "by": by,
                    "note": note,
                    "at": at,
                    "updated": updated,
                },
            )
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


def _seeded_pending(engine: Engine) -> tuple[int, int]:
    """The demo's request waiting on carol: (request id, issue id).

    Scoped to the demo project - the schema tests leave their own
    defaults-only pending request in the shared database.
    """
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT r.id, r.issue_id FROM issue_requests r "
                "JOIN issues i ON i.id = r.issue_id "
                "JOIN projects p ON p.id = i.project_id "
                "WHERE p.key = 'payments' "
                "AND r.requested_action = 'false_positive' AND r.state = 'pending'"
            )
        ).one()
    return int(row[0]), int(row[1])


def _open_issues(engine: Engine, n: int) -> list[int]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT i.id FROM issues i JOIN projects p ON p.id = i.project_id "
                "WHERE p.key = 'payments' AND i.triage_status = 'open' "
                "ORDER BY i.id LIMIT :n"
            ),
            {"n": n},
        ).all()
    return [int(row[0]) for row in rows]


def _notif_row(engine: Engine, *, username: str, request_id: int) -> Any:
    """The notification one user holds about one request, if any."""
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT id, type, ref, read_at FROM notifications "
                "WHERE user_id = (SELECT id FROM users WHERE username = :u) "
                "AND (ref ->> 'request')::bigint = :rid"
            ),
            {"u": username, "rid": request_id},
        ).first()


def _create(
    client: TestClient,
    engine: Engine,
    *,
    issue_id: int,
    target: str = "demo-carol",
    action: str = "false_positive",
) -> int:
    """Post the detail panel's form; returns the new request's id."""
    response = client.post(
        f"{LIST}/{issue_id}/requests",
        data={
            "csrf_token": _csrf(client),
            "action": action,
            "target": str(_user_id(engine, target)),
            "message": "A perfectly reasonable message for the ask.",
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT id FROM issue_requests WHERE issue_id = :iid ORDER BY id DESC"),
                {"iid": issue_id},
            ).scalar_one()
        )


# --- the waiting panel and deciding from it --------------------------------


def test_inbox_is_login_protected_and_only_yours(
    client: TestClient, engine: Engine, restored: None
) -> None:
    anonymous = client.get("/inbox", follow_redirects=False)
    assert anonymous.status_code == 303
    assert anonymous.headers["location"].startswith("/login")

    # An outsider sees the same three panels, all empty - nothing of
    # anybody else's requests or notifications leaks in.
    _signup(engine, "t52-outsider")
    seed_demo(engine)
    _login(client, "t52-outsider", "pw-t52-outsider")
    body = client.get("/inbox").text
    assert "<h1>Inbox</h1>" in body
    assert "Nothing waiting for a decision from you." in body
    assert "You have not asked for anything yet." in body
    assert "Nothing new." in body
    assert "asks you to mark" not in body
    assert "declined your request" not in body


def test_waiting_panel_shows_the_design_sentence_and_buttons(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """The design's inbox, line for line: the ask, the message in front
    of the decision, and the two buttons over the same resolve route."""
    _signed_in(client, engine, "demo-carol")
    request_id, issue_id = _seeded_pending(engine)
    body = client.get("/inbox").text

    assert "<h1>Inbox</h1>" in body
    assert "<h3>Waiting for you (1)</h3>" in body
    assert (
        f'<b>Dave Lindqvist</b> asks you to mark <a href="/projects/payments/issues/{issue_id}">'
        in body
    )
    assert "in payments as a false positive.</p>" in body
    assert '"Looks like a test fixture leaking through - could you flag it?"' in body
    assert f'action="/requests/{request_id}/resolve"' in body
    assert 'name="next" value="/inbox"' in body
    assert f'id="note-{request_id}"' in body
    assert ">Approve and flag</button>" in body
    assert ">Decline</button>" in body

    # Carol is not the requester: nothing sent, but the same ask is in
    # her notifications, unread, so the sentence appears exactly twice.
    assert "You have not asked for anything yet." in body
    assert body.count("asks you to mark") == 2
    assert "<h3>Notifications (1)</h3>" in body
    assert '<span class="c wn">Unread</span>' in body
    assert ">Mark all as read</button>" in body


def test_deciding_from_the_inbox_lands_back_on_the_inbox(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Approve posts to the very route the issue page uses, then PRG's
    home to /inbox; both the request and the two sides' notes follow."""
    _signed_in(client, engine, "demo-carol")
    request_id, issue_id = _seeded_pending(engine)

    response = client.post(
        f"/requests/{request_id}/resolve",
        data={
            "csrf_token": _csrf(client),
            "resolution": "approve",
            "note": "Seen and agreed.",
            "next": "/inbox",
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/inbox"

    with engine.connect() as conn:
        state, resolver = conn.execute(
            text("SELECT state, resolved_by FROM issue_requests WHERE id = :id"),
            {"id": request_id},
        ).one()
        status = conn.execute(
            text("SELECT triage_status FROM issues WHERE id = :id"), {"id": issue_id}
        ).scalar_one()
    assert state == "approved"
    assert resolver == _user_id(engine, "demo-carol")
    # The demo's fp issue was already a false positive, so the flag (and
    # its reason) does not move here - applying one to a fresh issue is
    # T5.1's test; what this page owns is the state and who was told.
    assert status == "false_positive"

    # The outcome went to the requester (dave), unread.
    told = _notif_row(engine, username="demo-dave", request_id=request_id)
    assert told is not None
    assert told.read_at is None

    body = client.get("/inbox").text
    assert "Nothing waiting for a decision from you." in body
    # Carol's own note about the ask now reads from the decided row.
    assert "<b>You</b> approved Dave Lindqvist" in body
    assert body.count("Unread") >= 1  # her copy is still unread, dave's is new


def test_sent_panel_lines_carry_word_and_colour_chips(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Design copy: noun on issue in project, chip for the state."""
    _signed_in(client, engine, "demo-dave")
    body = client.get("/inbox").text

    assert "<h3>Requests you sent</h3>" in body
    assert "False positive on" in body and "in payments" in body
    assert '<span class="c wn">Pending</span>' in body
    assert "Accept risk on" in body
    assert '<span class="c bad">Declined</span>' in body
    # Dave is the requester of both: his notifications are the outcomes.
    assert "<h3>Notifications (1)</h3>" in body
    assert "<b>Carol Reyes</b> declined your request to accept the risk of" in body
    assert 'in payments. <span class="c wn">Unread</span>' in body
    # He is not the target of anything: no waiting card, no note boxes.
    assert "Nothing waiting for a decision from you." in body


def test_mark_all_read_clears_the_unread_state(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-dave")
    assert '<span class="c wn">Unread</span>' in client.get("/inbox").text

    response = client.post(
        "/inbox/read",
        data={"csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/inbox"
    assert (
        _count(
            engine,
            "SELECT count(*) FROM notifications WHERE user_id = :uid AND read_at IS NULL",
            uid=_user_id(engine, "demo-dave"),
        )
        == 0
    )

    body = client.get("/inbox").text
    assert "Unread" not in body
    assert ">Mark all as read</button>" not in body
    assert "<h3>Notifications</h3>" in body  # no count once nothing is new
    assert '<p class="mu"><b>Carol Reyes</b> declined your request' in body


def test_read_notifications_show_no_chip_and_no_button(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Bob's seeded notification arrived already read in the demo."""
    _signed_in(client, engine, "demo-bob")
    body = client.get("/inbox").text
    assert "<h3>Notifications</h3>" in body
    assert "Unread" not in body
    assert ">Mark all as read</button>" not in body
    assert '<p class="mu"><b>Alice Nguyen</b> approved your request to help fix' in body


# --- who gets told ---------------------------------------------------------


def test_creating_a_request_notifies_the_target(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Section 8: creates a pending request *and* a notification - one
    transaction, so one cannot exist without the other."""
    _signed_in(client, engine, "demo-bob")
    issue = _open_issues(engine, 1)[0]
    request_id = _create(client, engine, issue_id=issue)

    told = _notif_row(engine, username="demo-carol", request_id=request_id)
    assert told is not None
    assert told.type == "request"
    ref = json.loads(told.ref) if isinstance(told.ref, str) else told.ref
    assert ref == {"request": request_id, "issue": issue}
    assert told.read_at is None
    # The requester is not told about their own ask.
    assert _notif_row(engine, username="demo-bob", request_id=request_id) is None


def test_resolving_notifies_the_requester_and_cancelling_the_target(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Both sides get told (section 8), each exactly once: the target
    was told of the ask, the requester of the outcome - and cancelling
    adds no second copy for the target, whose pointer already reads the
    live "cancelled" state."""
    _signed_in(client, engine, "demo-bob")
    first, second = _open_issues(engine, 2)
    approved = _create(client, engine, issue_id=first)
    cancelled = _create(client, engine, issue_id=second)
    carol = _user_id(engine, "demo-carol")

    _login(client, "demo-carol", DEMO_PASSWORD)
    assert (
        client.post(
            f"/requests/{approved}/resolve",
            data={"csrf_token": _csrf(client), "resolution": "approve"},
            headers=HTML,
            follow_redirects=False,
        ).status_code
        == 303
    )

    _login(client, "demo-bob", DEMO_PASSWORD)
    assert (
        client.post(
            f"/requests/{cancelled}/resolve",
            data={"csrf_token": _csrf(client), "resolution": "cancel"},
            headers=HTML,
            follow_redirects=False,
        ).status_code
        == 303
    )

    # Approved -> the requester learns the outcome; the target keeps
    # exactly the one pointer from the ask itself.
    outcome = _notif_row(engine, username="demo-bob", request_id=approved)
    assert outcome is not None and outcome.read_at is None
    assert (
        _count(
            engine,
            "SELECT count(*) FROM notifications WHERE user_id = :uid "
            "AND (ref ->> 'request')::bigint = :rid",
            uid=carol,
            rid=approved,
        )
        == 1
    )
    # Cancelled -> the target's pointer flips to the cancelled wording
    # (one row, still theirs); the requester gets nothing for acting.
    assert (
        _count(
            engine,
            "SELECT count(*) FROM notifications WHERE user_id = :uid "
            "AND (ref ->> 'request')::bigint = :rid",
            uid=carol,
            rid=cancelled,
        )
        == 1
    )
    assert _notif_row(engine, username="demo-bob", request_id=cancelled) is None


# --- the JSON API (section 12) ---------------------------------------------


def test_api_lists_and_reads_notifications(
    client: TestClient, engine: Engine, restored: None
) -> None:
    _signed_in(client, engine, "demo-dave")
    headers = _api_headers(client)

    listing = client.get(API, headers=headers)
    assert listing.status_code == 200
    data = listing.json()
    assert data["unread"] == 1
    note = data["items"][0]
    assert note["type"] == "request"
    assert set(note["ref"]) == {"request", "issue"}
    assert note["read_at"] is None

    # Somebody else's id changes nothing.
    carol_note = _notif_row(engine, username="demo-carol", request_id=_seeded_pending(engine)[0])
    assert carol_note is not None
    foreign = client.post(f"{API}/read", json={"ids": [int(carol_note[0])]}, headers=headers)
    assert foreign.status_code == 200
    assert foreign.json() == {"read": 0}

    own = client.post(f"{API}/read", json={"ids": [int(note["id"])]}, headers=headers)
    assert own.status_code == 200
    assert own.json() == {"read": 1}
    assert client.get(API, headers=headers).json()["unread"] == 0

    # No ids at all means every unread one of mine - already none.
    all_of_them = client.post(f"{API}/read", json={}, headers=headers)
    assert all_of_them.status_code == 200
    assert all_of_them.json() == {"read": 0}


def test_api_notifications_require_a_session(
    client: TestClient, engine: Engine, restored: None
) -> None:
    seed_demo(engine)
    # No cookies at all skips CSRF and still finds no session - so the
    # state-changing call goes first, before any GET hands out a cookie.
    posted = client.post(f"{API}/read", json={})
    assert posted.status_code == 401
    assert posted.json() == {"detail": "Authentication required"}
    listed = client.get(API)
    assert listed.status_code == 401


def test_seed_notifications_point_at_live_requests(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """The demo ships three pointers, two unread, every ref resolvable."""
    seed_demo(engine)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT type, ref, read_at FROM notifications ORDER BY id")).all()
    assert len(rows) == 3
    assert {str(row[0]) for row in rows} == {"request"}
    assert sum(1 for row in rows if row[2] is None) == 2
    for _kind, ref, _read in rows:
        payload = json.loads(ref) if isinstance(ref, str) else ref
        assert set(payload) == {"request", "issue"}
        with engine.connect() as conn:
            found = conn.execute(
                text("SELECT issue_id FROM issue_requests WHERE id = :rid"),
                {"rid": int(payload["request"])},
            ).scalar_one()
        assert int(found) == int(payload["issue"])
