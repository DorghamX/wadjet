"""Admin pages ``/admin``, ``/admin/users``, ``/admin/groups`` and
``/admin/permissions`` (phase 4, T4.7).

``/admin`` itself is a 303 to its Users tab - the index decision logged in
``docs/decisions.md``. A session may open a page; every page and every form
post needs the global ``users.admin`` permission and answers with one 403
that names it. The forms write through the same service functions the JSON
API tests pin, so the two cannot disagree, and the matrix is section 7's
own table, read-only.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.config import Settings
from app.permissions import PERMISSION_TEMPLATES, Permission
from app.security import hash_password, verify_password
from app.seed import DEMO_PASSWORD, seed_demo

HTML = {"Accept": "text/html"}


@pytest.fixture(scope="module")
def database_url(isolated_database_url: str) -> str:
    """Own schema: these tests mutate users, groups and the seed dataset."""
    return isolated_database_url


@pytest.fixture(scope="module")
def engine(isolated_engine: Engine) -> Engine:
    return isolated_engine


@pytest.fixture()
def settings(isolated_settings: Settings) -> Settings:
    return isolated_settings


#: The four templates of section 7, as the matrix labels them.
TEMPLATES = (
    ("Viewer", "viewer"),
    ("Developer", "developer"),
    ("Triager", "triager"),
    ("Project admin", "project_admin"),
)


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


def _row(body: str, needle: str) -> str:
    """The table row that mentions ``needle``, from its ``<tr>`` onward."""
    return next(segment for segment in body.split("<tr>") if needle in segment)


def _user_id(engine: Engine, username: str) -> int:
    return _count(engine, "SELECT id FROM users WHERE username = :n", n=username)


def _group_id(engine: Engine, name: str) -> int:
    return _count(engine, "SELECT id FROM groups WHERE name = :n", n=name)


def _email(engine: Engine, username: str) -> str:
    """Somebody's address, for the uniqueness rule."""
    with engine.connect() as conn:
        return str(
            conn.execute(
                text("SELECT email FROM users WHERE username = :n"), {"n": username}
            ).scalar_one()
        )


def _make_user(engine: Engine, prefix: str) -> tuple[int, str, str]:
    """An account this test owns: ``(id, username, password)``."""
    username = f"{prefix}-{uuid.uuid4().hex[:8]}"
    password = "correct-horse"
    with engine.begin() as conn:
        user_id = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:username, :email, :hash, FALSE, TRUE) RETURNING id"
            ),
            {
                "username": username,
                "email": f"{username}@test.com",
                "hash": hash_password(password),
            },
        ).scalar_one()
    return int(user_id), username, password


# --- the shell --------------------------------------------------------------


def test_anonymous_admin_pages_redirect_to_login(client: TestClient) -> None:
    for path in ("/admin", "/admin/users", "/admin/groups", "/admin/permissions"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303, path
        assert response.headers["location"].startswith("/login"), path


def test_admin_index_lands_on_the_users_tab(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    hop = client.get("/admin", follow_redirects=False)
    assert hop.status_code == 303
    assert hop.headers["location"] == "/admin/users"

    page = client.get("/admin")
    assert page.status_code == 200
    assert 'class="on" aria-current="page">Admin</a>' in page.text
    assert '<div class="pagehead">' in page.text
    assert '<span class="m mu">/admin/users</span>' in page.text
    assert 'class="on" aria-current="page">Users</a>' in page.text
    for slug, label in (("groups", "Groups"), ("permissions", "Permissions")):
        assert f'href="/admin/{slug}"' in page.text
        assert f">{label}</a>" in page.text


def test_member_gets_one_403_that_names_the_permission(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-alice", DEMO_PASSWORD)  # project admin, not users.admin

    for path in ("/admin", "/admin/users", "/admin/groups", "/admin/permissions"):
        refused = client.get(path)
        assert refused.status_code == 403, path
        assert "Admin is restricted" in refused.text
        assert "users.admin" in refused.text
        assert "Only an admin has it" in refused.text

    # A forged write is refused before it reaches a service.
    before = _count(engine, "SELECT count(*) FROM users WHERE username = 't47-forge'")
    forged = client.post(
        "/admin/users",
        data={
            "username": "t47-forge",
            "email": "t47-forge@example.com",
            "password": "correct-horse",
            "csrf_token": _csrf(client),
        },
        headers=HTML,
    )
    assert forged.status_code == 403
    assert _count(engine, "SELECT count(*) FROM users WHERE username = 't47-forge'") == before

    blocked = client.post(
        f"/admin/groups/{_group_id(engine, 'Platform team')}/members",
        data={"user_id": str(_user_id(engine, "demo-dave")), "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert blocked.status_code == 403


# --- the users tab -----------------------------------------------------------


def test_users_page_lists_people_roles_groups_and_forms(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    page = client.get("/admin/users")
    assert page.status_code == 200
    assert 'class="on" aria-current="page">Users</a>' in page.text

    admin_row = _row(page.text, "@demo-admin")
    assert "<b>Wadjet Admin</b>" in admin_row
    assert '<span class="c ok">Admin</span>' in admin_row
    assert '<span class="c ok">Active</span>' in admin_row
    assert "ago" in admin_row  # last seen as a relative time, never a raw stamp
    assert '<span class="mu">None</span>' in admin_row  # in no group

    alice_row = _row(page.text, "@demo-alice")
    assert "<b>Alice Nguyen</b>" in alice_row
    assert '<span class="c nt">Member</span>' in alice_row
    assert "Platform team" in alice_row
    assert f'action="/admin/users/{_user_id(engine, "demo-alice")}"' in alice_row

    # One form to edit a row, one to create an account.
    assert '<form method="post" action="/admin/users">' in page.text
    assert ">Create user<" in page.text
    assert 'id="nu-password" name="password"' in page.text
    assert "<b>Admin</b>" in page.text  # the create form's checkbox


def test_create_user_form_validates_and_keeps_what_was_typed(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    blank = client.post("/admin/users", data={"csrf_token": _csrf(client)}, headers=HTML)
    assert blank.status_code == 400
    assert "Give the user a username." in blank.text

    no_password = client.post(
        "/admin/users",
        data={"username": "t47-nopass", "email": "x@example.com", "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert no_password.status_code == 400
    assert "Set a password of at least 8 characters." in no_password.text
    assert 'value="t47-nopass"' in no_password.text  # what was typed stays on screen

    bad_email = client.post(
        "/admin/users",
        data={
            "username": "t47-noemail",
            "email": "nope",
            "password": "correct-horse",
            "csrf_token": _csrf(client),
        },
        headers=HTML,
    )
    assert bad_email.status_code == 400
    assert "does not look like an email address" in bad_email.text
    assert 'value="t47-noemail"' in bad_email.text
    assert 'value="nope"' in bad_email.text
    assert _count(engine, "SELECT count(*) FROM users WHERE username = 't47-noemail'") == 0


def test_create_user_form_creates_notifies_and_audits(client: TestClient, engine: Engine) -> None:
    _login(client, "demo-admin", DEMO_PASSWORD)
    username = f"t47-create-{uuid.uuid4().hex[:6]}"
    body = {
        "username": username,
        "email": f"{username}@example.com",
        "display_name": "Tess Tures",
        "password": "correct-horse",
        "csrf_token": _csrf(client),
    }

    created = client.post("/admin/users", data=body, headers=HTML, follow_redirects=False)
    assert created.status_code == 303
    assert created.headers["location"] == "/admin/users?saved=created"

    page = client.get(str(created.headers["location"]))
    assert page.status_code == 200
    assert "User created. They can sign in with that username now." in page.text
    assert "<b>Tess Tures</b>" in page.text
    assert f"@{username}" in page.text

    user_id = _user_id(engine, username)
    with engine.connect() as conn:
        stored = conn.execute(
            text("SELECT password_hash, is_admin FROM users WHERE id = :uid"),
            {"uid": user_id},
        ).first()
    assert verify_password("correct-horse", str(stored[0]))
    assert stored[1] is False  # the form did not tick the admin box
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'user.create' AND target_id = :tid",
            tid=str(user_id),
        )
        == 1
    )

    duplicate = client.post("/admin/users", data=body, headers=HTML)
    assert duplicate.status_code == 400
    assert "A user with that username already exists" in duplicate.text
    assert _count(engine, "SELECT count(*) FROM users WHERE username = :n", n=username) == 1


def test_edit_user_form_updates_row_and_password(client: TestClient, engine: Engine) -> None:
    _login(client, "demo-admin", DEMO_PASSWORD)
    user_id, username, _ = _make_user(engine, "t47-edit")
    alice_email = _email(engine, "demo-alice")

    saved = client.post(
        f"/admin/users/{user_id}",
        data={
            "display_name": "Renamed Person",
            "email": f"{username}@elsewhere.example",
            "role": "admin",
            "status": "inactive",
            "password": "a-brand-new-pass",
            "csrf_token": _csrf(client),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert saved.headers["location"] == "/admin/users?saved=updated"

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT display_name, email, is_admin, is_active, password_hash "
                "FROM users WHERE id = :uid"
            ),
            {"uid": user_id},
        ).first()
    assert row[0] == "Renamed Person"
    assert row[1] == f"{username}@elsewhere.example"
    assert row[2] is True and row[3] is False
    assert verify_password("a-brand-new-pass", str(row[4]))
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'user.update' AND target_id = :tid",
            tid=str(user_id),
        )
        == 1
    )

    page = client.get("/admin/users?saved=updated")
    assert "User saved." in page.text
    edited_row = _row(page.text, f"@{username}")
    assert "<b>Renamed Person</b>" in edited_row
    assert '<span class="c ok">Admin</span>' in edited_row
    assert '<span class="c bad">Deactivated</span>' in edited_row

    # Somebody else's address is still off limits, and it stays typed.
    taken = client.post(
        f"/admin/users/{user_id}",
        data={
            "display_name": "Renamed Person",
            "email": alice_email,
            "role": "member",
            "status": "active",
            "csrf_token": _csrf(client),
        },
        headers=HTML,
    )
    assert taken.status_code == 400
    assert "A user with that email already exists" in taken.text
    # Still typed on screen, in the row that asked for it.
    assert f'value="{alice_email}"' in _row(taken.text, f"@{username}")

    missing = client.post(
        "/admin/users/99999999",
        data={"display_name": "Ghost", "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert missing.status_code == 404
    assert "User not found" in missing.text

    forged = client.post(
        "/admin/users/nonsense",
        data={"display_name": "Ghost", "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert forged.status_code == 404
    assert "User not found" in forged.text


def test_edit_form_protects_the_actor(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    admin_id = _user_id(engine, "demo-admin")
    base = {
        "display_name": "Wadjet Admin",
        "email": _email(engine, "demo-admin"),
        "csrf_token": _csrf(client),
    }

    demoted = client.post(f"/admin/users/{admin_id}", data={**base, "role": "member"}, headers=HTML)
    assert demoted.status_code == 400
    assert "You cannot remove your own admin flag" in demoted.text
    # What was chosen stays on screen, and nothing changed underneath.
    assert '<option value="member" selected>Member</option>' in demoted.text
    assert (
        _count(engine, "SELECT count(*) FROM users WHERE id = :uid AND is_admin", uid=admin_id) == 1
    )

    deactivated = client.post(
        f"/admin/users/{admin_id}",
        data={**base, "role": "admin", "status": "inactive"},
        headers=HTML,
    )
    assert deactivated.status_code == 400
    assert "You cannot deactivate your own account" in deactivated.text
    assert (
        _count(engine, "SELECT count(*) FROM users WHERE id = :uid AND is_active", uid=admin_id)
        == 1
    )


# --- the groups tab ----------------------------------------------------------


def test_groups_page_lists_members_and_offers_the_others(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    group_id = _group_id(engine, "Platform team")

    page = client.get("/admin/groups")
    assert page.status_code == 200
    assert 'class="on" aria-current="page">Groups</a>' in page.text
    assert '<span class="m mu">/admin/groups</span>' in page.text

    row = _row(page.text, f'action="/admin/groups/{group_id}"')
    assert "<b>Platform team</b>" in row
    assert "Engineers who ship the demo services." in row
    for member in ("demo-alice", "demo-bob", "demo-carol"):
        assert f"@{member}" in row
    assert ">Remove<" in row
    # Dave (and the admin) are still outside, Alice is not offered twice.
    assert ">Dave Lindqvist (demo-dave)</option>" in row
    assert ">Alice Nguyen (demo-alice)</option>" not in row
    assert f'<form method="post" action="/admin/groups/{group_id}/members">' in row
    assert f'<form method="post" action="/admin/groups/{group_id}">' in row

    assert '<form method="post" action="/admin/groups">' in page.text
    assert ">Create group<" in page.text


def test_groups_page_adds_and_removes_members(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    group_id = _group_id(engine, "Platform team")
    dave_id = _user_id(engine, "demo-dave")

    def membership() -> int:
        return _count(
            engine,
            "SELECT count(*) FROM group_members WHERE group_id = :g AND user_id = :u",
            g=group_id,
            u=dave_id,
        )

    added = client.post(
        f"/admin/groups/{group_id}/members",
        data={"user_id": str(dave_id), "csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert added.status_code == 303
    assert added.headers["location"] == "/admin/groups?saved=member_added"
    assert membership() == 1
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'group.member_add' AND target_id = :tid",
            tid=str(group_id),
        )
        == 1
    )
    page = client.get("/admin/groups?saved=member_added")
    assert "That user is now a member of the group." in page.text
    assert ">Dave Lindqvist (demo-dave)</option>" not in page.text

    again = client.post(
        f"/admin/groups/{group_id}/members",
        data={"user_id": str(dave_id), "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert again.status_code == 400
    assert "That user is already in this group" in again.text
    assert membership() == 1  # not silently duplicated

    removed = client.post(
        f"/admin/groups/{group_id}/members/remove",
        data={"user_id": str(dave_id), "csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert removed.status_code == 303
    assert removed.headers["location"] == "/admin/groups?saved=member_removed"
    assert membership() == 0
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'group.member_remove' "
            "AND target_id = :tid",
            tid=str(group_id),
        )
        == 1
    )
    assert (
        "That user was removed from the group."
        in client.get("/admin/groups?saved=member_removed").text
    )

    dropped_twice = client.post(
        f"/admin/groups/{group_id}/members/remove",
        data={"user_id": str(dave_id), "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert dropped_twice.status_code == 400
    assert "That user is not in this group" in dropped_twice.text

    unknown_group = client.post(
        "/admin/groups/99999999/members",
        data={"user_id": str(dave_id), "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert unknown_group.status_code == 404
    assert "Group not found" in unknown_group.text


def test_groups_page_creates_and_renames(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)
    name = f"T47 team {uuid.uuid4().hex[:6]}"

    blank = client.post("/admin/groups", data={"csrf_token": _csrf(client)}, headers=HTML)
    assert blank.status_code == 400
    assert "Give the group a name." in blank.text

    created = client.post(
        "/admin/groups",
        data={"name": name, "description": "Made by the test.", "csrf_token": _csrf(client)},
        headers=HTML,
        follow_redirects=False,
    )
    assert created.status_code == 303
    assert created.headers["location"] == "/admin/groups?saved=group_created"
    group_id = _group_id(engine, name)
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'group.create' AND target_id = :tid",
            tid=str(group_id),
        )
        == 1
    )
    landing = client.get("/admin/groups?saved=group_created")
    assert "Group created. Add its members." in landing.text
    assert f"<b>{name}</b>" in landing.text
    assert "No members yet." in landing.text

    renamed = client.post(
        f"/admin/groups/{group_id}",
        data={
            "name": f"{name} II",
            "description": "Renamed by the test.",
            "csrf_token": _csrf(client),
        },
        headers=HTML,
        follow_redirects=False,
    )
    assert renamed.status_code == 303
    assert renamed.headers["location"] == "/admin/groups?saved=group"
    assert "Group saved." in client.get("/admin/groups?saved=group").text
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'group.update' AND target_id = :tid",
            tid=str(group_id),
        )
        == 1
    )

    taken = client.post(
        f"/admin/groups/{group_id}",
        data={"name": "Platform team", "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert taken.status_code == 400
    assert "A group with that name already exists" in taken.text
    assert 'value="Platform team"' in taken.text  # still typed on screen

    missing = client.post(
        "/admin/groups/99999999",
        data={"name": "Ghost", "csrf_token": _csrf(client)},
        headers=HTML,
    )
    assert missing.status_code == 404
    assert "Group not found" in missing.text


# --- the permissions tab ------------------------------------------------------


def test_permissions_page_renders_the_templates_read_only(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    _login(client, "demo-admin", DEMO_PASSWORD)

    page = client.get("/admin/permissions")
    assert page.status_code == 200
    assert 'class="on" aria-current="page">Permissions</a>' in page.text
    assert '<span class="m mu">/admin/permissions</span>' in page.text
    assert "Each permission is its own flag, granted to a user or to a group." in page.text

    # Every permission of section 7, code and label, is a column.
    for permission in Permission:
        assert f'<span class="m mu">{permission.value}</span>' in page.text
    assert '<th scope="col">Browse<br>' in page.text

    # Each template row carries exactly the permissions it holds.
    for label, key in TEMPLATES:
        row = _row(page.text, f"<b>{label}</b>")
        held = len(PERMISSION_TEMPLATES[key])
        assert row.count(">Yes<") == held, label
        assert row.count(">No<") == len(Permission) - held, label

    # The globals are explained rather than ticked for every template.
    assert "only the admin role holds them" in page.text
    assert "An admin holds every permission everywhere" in page.text

    # The legend spells out what each one allows, in section 7's words.
    assert "What each permission allows" in page.text
    for permission in Permission:
        assert f'<td class="m">{permission.value}</td>' in page.text
    assert "Settings, exclusions, tokens, gate selection and members." in page.text
    assert "Global: manage users and groups." in page.text

    # Read-only: the only form on the page is the top bar's log out.
    assert page.text.count('name="csrf_token"') == 1
    assert 'action="/admin/permissions"' not in page.text
