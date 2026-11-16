"""@mentions (section 8): a name in a comment tells its owner.

A mention is written in the comment's own transaction, and only for
people the comment is visible to: the author is not told about their
own words, an inactive or unknown name tells nobody, and a user who
cannot browse the project is never pointed at an issue they cannot
open. The inbox renders the mention as one sentence with a live link,
and editing a comment stays silent - deleting it takes its pointers
with it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.security import hash_password
from app.seed import DEMO_PASSWORD, seed_demo

LIST = "/projects/payments/issues"
HTML = {"Accept": "text/html"}


# --- fixtures and helpers --------------------------------------------------


@pytest.fixture()
def restored(engine: Engine) -> Iterator[None]:
    """Seed, then drop whatever the test writes on the way out.

    Comments and their mention notifications are all these tests
    change, so those are the tables snapshotted.
    """
    seed_demo(engine)
    with engine.connect() as conn:
        marks = {
            table: int(conn.execute(text(f"SELECT COALESCE(MAX(id), 0) FROM {table}")).scalar_one())
            for table in ("issue_comments", "notifications")
        }
    yield
    with engine.begin() as conn:
        for table, mark in marks.items():
            conn.execute(text(f"DELETE FROM {table} WHERE id > :mark"), {"mark": mark})


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


def _issue_id(engine: Engine) -> int:
    """One payments issue to comment on."""
    with engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT i.id FROM issues i JOIN projects p ON p.id = i.project_id "
                    "WHERE p.key = 'payments' ORDER BY i.id LIMIT 1"
                )
            ).scalar_one()
        )


def _comment(client: TestClient, engine: Engine, *, issue_id: int, body: str) -> int:
    """Post a comment; returns the new row's id."""
    response = client.post(
        f"{LIST}/{issue_id}/comments",
        data={"csrf_token": _csrf(client), "body": body},
        headers=HTML,
        follow_redirects=False,
    )
    assert response.status_code == 303
    with engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT id FROM issue_comments WHERE issue_id = :iid ORDER BY id DESC LIMIT 1"
                ),
                {"iid": issue_id},
            ).scalar_one()
        )


def _edit(client: TestClient, *, issue_id: int, comment_id: int, body: str) -> Any:
    return client.post(
        f"{LIST}/{issue_id}/comments/{comment_id}/edit",
        data={"csrf_token": _csrf(client), "body": body},
        headers=HTML,
        follow_redirects=False,
    )


def _delete(client: TestClient, *, issue_id: int, comment_id: int) -> Any:
    return client.post(
        f"{LIST}/{issue_id}/comments/{comment_id}/delete",
        data={"csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )


def _mentions(engine: Engine, username: str) -> list[Any]:
    """This user's mention notifications, oldest first."""
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT n.ref, n.read_at FROM notifications n "
                "WHERE n.user_id = (SELECT id FROM users WHERE username = :u) "
                "AND n.type = 'mention' ORDER BY n.id"
            ),
            {"u": username},
        ).all()


def _mention_count(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT count(*) FROM notifications WHERE type = 'mention'")
            ).scalar_one()
        )


# --- who is told -----------------------------------------------------------


def test_a_mention_tells_a_reader_of_the_project(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """One comment, one pointer, in the same transaction: the row names
    the issue *and* the comment, unread, for a user who can browse."""
    _signed_in(client, engine, "demo-carol")
    issue = _issue_id(engine)
    comment = _comment(
        client, engine, issue_id=issue, body="@demo-bob this reproduces on main too."
    )

    rows = _mentions(engine, "demo-bob")
    assert len(rows) == 1
    ref = rows[0][0]
    assert ref == {"issue": issue, "comment": comment}
    assert rows[0][1] is None  # unread
    # The author was not told about her own words, and nobody else was.
    assert _mentions(engine, "demo-carol") == []
    assert _mention_count(engine) == 1


def test_unknown_names_self_and_invisible_users_tell_nobody(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """Typo, author, and a user without a single grant: zero pointers."""
    _signed_in(client, engine, "demo-carol")
    _signup(engine, "t53-outsider")
    issue = _issue_id(engine)
    _comment(
        client,
        engine,
        issue_id=issue,
        body=(
            "@demo-carol you wrote this, @definitely-nobody does not exist, "
            "and @t53-outsider cannot see the project."
        ),
    )
    assert _mention_count(engine) == 0


def test_emails_are_not_mentions_and_repeats_count_once(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """'carol@example.com' stays an address; the same name twice is one
    note, not two."""
    _signed_in(client, engine, "demo-carol")
    issue = _issue_id(engine)
    _comment(
        client,
        engine,
        issue_id=issue,
        body="Mail me at carol@example.com - and hey @demo-bob (again: @demo-bob).",
    )
    assert len(_mentions(engine, "demo-bob")) == 1
    assert _mention_count(engine) == 1


# --- where it shows up -----------------------------------------------------


def test_the_inbox_and_api_render_the_mention(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """The design's sentence shape, over a live link: '<b>Carol</b>
    mentioned you on <a>Issue</a> in payments.' - and the section 12
    feed carries the same pointer."""
    _signed_in(client, engine, "demo-carol")
    issue = _issue_id(engine)
    _comment(client, engine, issue_id=issue, body="Heads up @demo-bob, flaky again.")

    _login(client, "demo-bob", DEMO_PASSWORD)
    body = client.get("/inbox").text
    assert "<h3>Notifications (1)</h3>" in body
    assert f'<b>Carol Reyes</b> mentioned you on <a href="{LIST}/{issue}">' in body
    assert 'in payments. <span class="c wn">Unread</span>' in body

    listing = client.get("/api/v1/notifications", headers=_api_headers(client))
    assert listing.status_code == 200
    newest = listing.json()["items"][0]
    assert newest["type"] == "mention"
    assert set(newest["ref"]) == {"issue", "comment"}
    assert newest["read_at"] is None


def test_editing_stays_silent_and_deleting_takes_the_pointer(
    client: TestClient, engine: Engine, restored: None
) -> None:
    """An edit is not a new telling; a deleted comment leaves nothing
    to tell."""
    _signed_in(client, engine, "demo-carol")
    issue = _issue_id(engine)
    comment = _comment(client, engine, issue_id=issue, body="Look @demo-bob.")

    assert (
        _edit(
            client, issue_id=issue, comment_id=comment, body="Look @demo-bob and @demo-dave."
        ).status_code
        == 303
    )
    assert len(_mentions(engine, "demo-bob")) == 1  # not told twice
    assert _mentions(engine, "demo-dave") == []  # edits tell nobody

    assert _delete(client, issue_id=issue, comment_id=comment).status_code == 303
    assert _mentions(engine, "demo-bob") == []
    assert _mention_count(engine) == 0
