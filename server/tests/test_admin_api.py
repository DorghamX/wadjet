"""Admin API: ``/api/v1/users`` and ``/api/v1/groups`` (section 12, T4.7).

All six endpoints need a session *and* the global ``users.admin``
permission; the body is validated by Pydantic, uniqueness is a 409, and
every write lands in the audit log (section 13). There is no DELETE in
section 12's list, so an account that should stop working is deactivated
instead - and nobody may demote or deactivate themselves.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import Engine, text

from app.security import hash_password, verify_password
from app.seed import DEMO_PASSWORD, seed_demo


def create_user(engine: Engine, *, admin: bool) -> tuple[str, str]:
    """A user that can actually log in: (username, password)."""
    username = f"adminapi-{'a' if admin else 'u'}-{uuid.uuid4().hex[:8]}"
    password = "correct-horse"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:username, :email, :hash, :admin, TRUE)"
            ),
            {
                "username": username,
                "email": f"{username}@test.com",
                "hash": hash_password(password),
                "admin": admin,
            },
        )
    return username, password


def login(client: TestClient, username: str, password: str) -> dict[str, str]:
    """Log in and return the CSRF headers the write endpoints need."""
    response = client.post("/session", data={"username": username, "password": password})
    assert response.status_code == 201, response.text
    client.get("/healthz")  # fetch a page so the CSRF cookie exists
    csrf = client.cookies.get("wadjet_csrf")
    assert csrf is not None
    return {"X-CSRF-Token": csrf}


def _count(engine: Engine, sql: str, **params: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def _new_body(prefix: str) -> dict[str, str]:
    """A valid create body whose names are unique within the session."""
    suffix = uuid.uuid4().hex[:8]
    return {
        "username": f"{prefix}-{suffix}",
        "email": f"{prefix}-{suffix}@example.com",
        "password": "correct-horse",
    }


# --- who may call at all ----------------------------------------------------


def test_users_and_groups_need_a_session(client: TestClient, engine: Engine) -> None:
    # The unsafe calls come first: a safe one would hand out the CSRF
    # cookie, and every later write would then be refused by section 13
    # before it ever reached the route.
    body = _new_body("anon")
    assert client.post("/api/v1/users", json=body).status_code == 401
    assert client.post("/api/v1/groups", json={"name": "Anon"}).status_code == 401
    assert client.patch("/api/v1/users/1", json={"email": "dev@example.com"}).status_code == 401
    assert client.patch("/api/v1/groups/1", json={"name": "Nope"}).status_code == 401
    assert client.get("/api/v1/users").status_code == 401
    assert client.get("/api/v1/groups").status_code == 401
    assert _count(engine, "SELECT count(*) FROM users WHERE username = :n", n=body["username"]) == 0
    assert _count(engine, "SELECT count(*) FROM groups WHERE name = 'Anon'") == 0


def test_all_six_endpoints_need_users_admin(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=False)
    headers = login(client, username, password)

    assert client.get("/api/v1/users", headers=headers).status_code == 403
    assert client.get("/api/v1/groups", headers=headers).status_code == 403

    created = client.post("/api/v1/users", json=_new_body("denied"), headers=headers)
    assert created.status_code == 403
    assert created.json()["detail"] == "users.admin permission required"

    patched = client.patch("/api/v1/users/1", json={"email": "dev@example.com"}, headers=headers)
    assert patched.status_code == 403

    grouped = client.post("/api/v1/groups", json={"name": "Denied"}, headers=headers)
    assert grouped.status_code == 403

    renamed = client.patch("/api/v1/groups/1", json={"name": "Denied"}, headers=headers)
    assert renamed.status_code == 403

    # Nothing moved.
    assert _count(engine, "SELECT count(*) FROM groups WHERE name = 'Denied'") == 0
    assert _count(engine, "SELECT count(*) FROM users WHERE username LIKE 'denied-%'") == 0


# --- users ------------------------------------------------------------------


def test_list_users_shows_the_seed_groups_and_no_hashes(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)

    response = client.get("/api/v1/users", headers=headers)
    assert response.status_code == 200
    body = response.json()
    by_name = {entry["username"]: entry for entry in body}

    demo_admin = by_name["demo-admin"]
    assert demo_admin["is_admin"] is True
    assert demo_admin["is_active"] is True
    assert demo_admin["display_name"] == "Wadjet Admin"
    assert "password_hash" not in response.text
    assert "correct-horse" not in response.text

    alice = by_name["demo-alice"]
    assert alice["is_admin"] is False
    assert "Platform team" in alice["groups"]
    assert alice["last_login_at"] is not None


def test_create_user_rejects_malformed_bodies(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)

    def post(payload: dict[str, str]) -> Response:
        return client.post("/api/v1/users", json=payload, headers=headers)

    bad_username = post(
        {"username": "not a name!", "email": "dev@example.com", "password": "correct-horse"}
    )
    assert bad_username.status_code == 422
    assert any(
        "Usernames run from 2 to 128 characters" in error["msg"]
        for error in bad_username.json()["detail"]
    )

    bad_email = post({"username": "goodname42", "email": "nope", "password": "correct-horse"})
    assert bad_email.status_code == 422
    assert any(
        "does not look like an email address" in error["msg"]
        for error in bad_email.json()["detail"]
    )

    short = post({"username": "goodname42", "email": "dev@example.com", "password": "short"})
    assert short.status_code == 422
    assert any(
        "Passwords need at least 8 characters" in error["msg"] for error in short.json()["detail"]
    )

    extra = client.post(
        "/api/v1/users",
        json={**_new_body("extra"), "nickname": "smuggled"},
        headers=headers,
    )
    assert extra.status_code == 422
    assert _count(engine, "SELECT count(*) FROM users WHERE username = 'goodname42'") == 0
    assert _count(engine, "SELECT count(*) FROM users WHERE username LIKE 'extra-%'") == 0


def test_create_user_stores_it_audits_and_can_sign_in(client: TestClient, engine: Engine) -> None:
    username, password = create_user(engine, admin=True)
    headers = login(client, username, password)
    body = _new_body("t47-create")
    body["display_name"] = "Ada Lovelace"

    created = client.post("/api/v1/users", json=body, headers=headers)
    assert created.status_code == 201, created.text
    user_id = created.json()["id"]
    assert created.json()["username"] == body["username"]
    assert created.json()["display_name"] == "Ada Lovelace"
    assert created.json()["is_admin"] is False
    assert created.json()["is_active"] is True
    assert created.json()["groups"] == []
    assert "password_hash" not in created.json()

    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'user.create' AND target_id = :tid",
            tid=str(user_id),
        )
        == 1
    )

    duplicate_name = client.post("/api/v1/users", json=body, headers=headers)
    assert duplicate_name.status_code == 409
    assert duplicate_name.json()["detail"] == "A user with that username already exists"

    duplicate_email = client.post(
        "/api/v1/users",
        json={**_new_body("t47-create"), "email": body["email"]},
        headers=headers,
    )
    assert duplicate_email.status_code == 409
    assert duplicate_email.json()["detail"] == "A user with that email already exists"
    assert (
        _count(
            engine,
            "SELECT count(*) FROM users WHERE username = :name",
            name=body["username"],
        )
        == 1
    )

    # The account really works, and its password is a hash at rest.
    client.cookies.clear()
    assert login(client, body["username"], "correct-horse")
    with engine.connect() as conn:
        stored = conn.execute(
            text("SELECT password_hash FROM users WHERE username = :name"),
            {"name": body["username"]},
        ).scalar_one()
    assert verify_password("correct-horse", str(stored))


def test_patch_user_updates_fields_and_password(client: TestClient, engine: Engine) -> None:
    target = _new_body("t47-patch")["username"]
    with engine.begin() as conn:
        target_id = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:username, :email, :hash, FALSE, TRUE) RETURNING id"
            ),
            {
                "username": target,
                "email": f"{target}@example.com",
                "hash": hash_password("before-now"),
            },
        ).scalar_one()
    admin_name, admin_password = create_user(engine, admin=True)
    headers = login(client, admin_name, admin_password)

    patched = client.patch(
        f"/api/v1/users/{int(target_id)}",
        json={
            "email": f"{target}-changed@example.com",
            "display_name": "Patch Target",
            "is_admin": True,
            "password": "after-and-better",
        },
        headers=headers,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["email"] == f"{target}-changed@example.com"
    assert patched.json()["display_name"] == "Patch Target"
    assert patched.json()["is_admin"] is True
    assert "password_hash" not in patched.json()

    with engine.connect() as conn:
        stored = conn.execute(
            text("SELECT password_hash, updated_at FROM users WHERE id = :uid"),
            {"uid": int(target_id)},
        ).first()
    assert verify_password("after-and-better", str(stored[0]))
    assert stored[1] is not None

    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'user.update' AND target_id = :tid",
            tid=str(int(target_id)),
        )
        == 1
    )
    # The audit row says what changed, never the secret.
    with engine.connect() as conn:
        details = conn.execute(
            text("SELECT details FROM audit_log WHERE action = 'user.update' AND target_id = :tid"),
            {"tid": str(int(target_id))},
        ).scalar_one()
    assert "after-and-better" not in str(details)
    assert "is_admin" in str(details)

    deactivated = client.patch(
        f"/api/v1/users/{int(target_id)}", json={"is_active": False}, headers=headers
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["is_active"] is False


def test_patch_user_rejects_nothing_unknown_and_bad_values(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    admin_name, admin_password = create_user(engine, admin=True)
    headers = login(client, admin_name, admin_password)

    nothing = client.patch("/api/v1/users/1", json={}, headers=headers)
    assert nothing.status_code == 422
    assert nothing.json()["detail"] == "Nothing to update"

    missing = client.patch(
        "/api/v1/users/99999999", json={"display_name": "Ghost"}, headers=headers
    )
    assert missing.status_code == 404
    assert missing.json()["detail"] == "User not found"

    bad_email = client.patch(
        "/api/v1/users/1", json={"email": "still not an email"}, headers=headers
    )
    assert bad_email.status_code == 422

    alice_email = with_alice_email(engine)
    taken = client.patch("/api/v1/users/1", json={"email": alice_email}, headers=headers)
    assert taken.status_code == 409
    assert taken.json()["detail"] == "A user with that email already exists"


def with_alice_email(engine: Engine) -> str:
    """Somebody else's address, for the uniqueness rule."""
    with engine.connect() as conn:
        return str(
            conn.execute(text("SELECT email FROM users WHERE username = 'demo-alice'")).scalar_one()
        )


def test_patch_user_protects_the_actor(client: TestClient, engine: Engine) -> None:
    admin_name, admin_password = create_user(engine, admin=True)
    headers = login(client, admin_name, admin_password)
    with engine.connect() as conn:
        admin_id = int(
            conn.execute(
                text("SELECT id FROM users WHERE username = :name"), {"name": admin_name}
            ).scalar_one()
        )

    demoted = client.patch(f"/api/v1/users/{admin_id}", json={"is_admin": False}, headers=headers)
    assert demoted.status_code == 400
    assert demoted.json()["detail"] == "You cannot remove your own admin flag"

    deactivated = client.patch(
        f"/api/v1/users/{admin_id}", json={"is_active": False}, headers=headers
    )
    assert deactivated.status_code == 400
    assert deactivated.json()["detail"] == "You cannot deactivate your own account"

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT is_admin, is_active FROM users WHERE id = :uid"), {"uid": admin_id}
        ).first()
    assert row[0] is True and row[1] is True


# --- groups -----------------------------------------------------------------


def test_list_groups_shows_the_seed_membership(client: TestClient, engine: Engine) -> None:
    seed_demo(engine)
    admin_name, admin_password = create_user(engine, admin=True)
    headers = login(client, admin_name, admin_password)

    response = client.get("/api/v1/groups", headers=headers)
    assert response.status_code == 200
    by_name = {group["name"]: group for group in response.json()}
    platform = by_name["Platform team"]
    assert platform["description"] == "Engineers who ship the demo services."
    members = {member["username"] for member in platform["members"]}
    assert {"demo-alice", "demo-bob", "demo-carol"} <= members
    assert all(set(member) == {"id", "username", "display_name"} for member in platform["members"])


def test_create_and_patch_group(client: TestClient, engine: Engine) -> None:
    admin_name, admin_password = create_user(engine, admin=True)
    headers = login(client, admin_name, admin_password)
    name = f"Team {uuid.uuid4().hex[:8]}"

    created = client.post(
        "/api/v1/groups", json={"name": name, "description": "Ships the thing."}, headers=headers
    )
    assert created.status_code == 201, created.text
    group_id = created.json()["id"]
    assert created.json()["members"] == []
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'group.create' AND target_id = :tid",
            tid=str(group_id),
        )
        == 1
    )

    duplicate = client.post("/api/v1/groups", json={"name": name}, headers=headers)
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "A group with that name already exists"

    blank = client.post("/api/v1/groups", json={"name": "   "}, headers=headers)
    assert blank.status_code == 422
    assert any("A group needs a name" in error["msg"] for error in blank.json()["detail"])

    renamed = client.patch(
        f"/api/v1/groups/{group_id}",
        json={"name": f"{name} renamed", "description": "Renamed by the test."},
        headers=headers,
    )
    assert renamed.status_code == 200
    assert renamed.json()["name"] == f"{name} renamed"
    assert renamed.json()["description"] == "Renamed by the test."
    assert (
        _count(
            engine,
            "SELECT count(*) FROM audit_log WHERE action = 'group.update' AND target_id = :tid",
            tid=str(group_id),
        )
        == 1
    )

    nothing = client.patch(f"/api/v1/groups/{group_id}", json={}, headers=headers)
    assert nothing.status_code == 422
    assert nothing.json()["detail"] == "Nothing to update"

    missing = client.patch("/api/v1/groups/99999999", json={"name": "Ghost"}, headers=headers)
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Group not found"

    # A name another group already holds is refused, not silently swapped.
    taken_name = client.patch(
        f"/api/v1/groups/{group_id}", json={"name": "Platform team"}, headers=headers
    )
    assert taken_name.status_code == 409
    assert taken_name.json()["detail"] == "A group with that name already exists"


def test_list_users_never_carries_a_password_hash(client: TestClient, engine: Engine) -> None:
    """Section 13: an admin can list people, never read their material."""
    seed_demo(engine)
    admin_name, admin_password = create_user(engine, admin=True)
    headers = login(client, admin_name, admin_password)
    with engine.connect() as conn:
        stored = conn.execute(
            text("SELECT password_hash FROM users WHERE username = :name"),
            {"name": admin_name},
        ).scalar_one()
    response = client.get("/api/v1/users", headers=headers)
    assert response.status_code == 200
    assert str(stored) not in response.text
    assert DEMO_PASSWORD not in response.text
