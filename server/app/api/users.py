"""Platform admin API: users and groups (sections 7, 12, 13).

Who may sign in, and which group they belong to, is the global
``users.admin`` permission (section 7: "Manage users and groups"), so every
endpoint here needs a session *and* that permission, and every write lands
in the audit log (section 13).

The writes are plain service functions (``create_user``, ``update_user``,
``create_group``, ``update_group``, ``add_member``, ``remove_member``) so
``app.web.admin`` can offer the same management as pages without repeating
a rule: a form post and a ``PATCH`` cannot disagree about what
"deactivate" means.

Two shapes are deliberately missing from section 12's
``GET/POST/PATCH /api/v1/users`` and ``/groups``:

- **No DELETE.** Somebody who should stop working here is deactivated
  (``is_active: false``); their issues, comments and audit rows stay
  attributable. A username is never rewritten either - it is the identity
  every other row points at.
- **No membership endpoints.** Group membership is edited on
  ``/admin/groups`` with the same service functions the pages already use.

On ``PATCH``, ``None`` means "leave this field alone"; send an empty string
to clear the display name or the group description.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Connection, Engine, text

from app.audit import write_audit
from app.deps import get_current_user
from app.permissions import Permission, can
from app.security import hash_password
from app.session import expire_sessions_for_user

router = APIRouter()

#: A login name: letters, digits, dot, underscore or hyphen, starting with
#: a letter or a digit, 2 to 128 characters long.
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")

#: There is no email-validator dependency (section 17.1: no new deps), so
#: this is the honest minimum: something, an at-sign, something, a dot,
#: something - and no whitespace anywhere in it.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: Passwords are argon2id-hashed (section 13); only the length matters here.
MIN_PASSWORD_LENGTH = 8


# --- validation, shared by the API payloads and the pages ------------------


def check_username(value: str) -> str:
    """A usable login name, or a sentence a person can act on."""
    cleaned = value.strip()
    if not USERNAME_RE.match(cleaned):
        raise ValueError(
            "Usernames run from 2 to 128 characters - letters, digits, dot, "
            "underscore or hyphen - and start with a letter or a digit."
        )
    return cleaned


def check_email(value: str) -> str:
    """A plausible address, or a sentence with an example in it."""
    cleaned = value.strip()
    if len(cleaned) > 255 or not EMAIL_RE.match(cleaned):
        raise ValueError("That does not look like an email address, for example dev@example.com.")
    return cleaned


def check_password(value: str) -> str:
    """The one rule every password has to pass (section 13)."""
    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Passwords need at least {MIN_PASSWORD_LENGTH} characters.")
    return value


def check_group_name(value: str) -> str:
    """A group name worth showing in a members matrix."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("A group needs a name.")
    if len(cleaned) > 128:
        raise ValueError("Group names are at most 128 characters.")
    return cleaned


def clean_text(value: str | None) -> str | None:
    """Trimmed optional text, where ``None`` and ``""`` both mean "none"."""
    if value is None:
        return None
    return value.strip() or None


# --- payloads ---------------------------------------------------------------


class UserCreate(BaseModel):
    """The body of ``POST /api/v1/users`` (section 12)."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(max_length=128)
    email: str = Field(max_length=255)
    password: str = Field(max_length=128)
    display_name: str | None = Field(default=None, max_length=255)
    is_admin: bool = False

    @field_validator("username")
    @classmethod
    def _usable_username(cls, value: str) -> str:
        return check_username(value)

    @field_validator("email")
    @classmethod
    def _usable_email(cls, value: str) -> str:
        return check_email(value)

    @field_validator("password")
    @classmethod
    def _usable_password(cls, value: str) -> str:
        return check_password(value)

    @field_validator("display_name")
    @classmethod
    def _usable_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class UserPatch(BaseModel):
    """The body of ``PATCH /api/v1/users/{user_id}``.

    ``None`` means "leave this field alone" - including ``display_name``,
    where an empty string is what clears the name.
    """

    model_config = ConfigDict(extra="forbid")

    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    is_admin: bool | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, max_length=128)

    @field_validator("email")
    @classmethod
    def _usable_email(cls, value: str | None) -> str | None:
        return None if value is None else check_email(value)

    @field_validator("password")
    @classmethod
    def _usable_password(cls, value: str | None) -> str | None:
        return None if value is None else check_password(value)


class GroupCreate(BaseModel):
    """The body of ``POST /api/v1/groups`` (section 12)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=128)
    description: str | None = Field(default=None, max_length=1000)

    @field_validator("name")
    @classmethod
    def _usable_name(cls, value: str) -> str:
        return check_group_name(value)

    @field_validator("description")
    @classmethod
    def _usable_description(cls, value: str | None) -> str | None:
        return clean_text(value)


class GroupPatch(BaseModel):
    """The body of ``PATCH /api/v1/groups/{group_id}`` (see ``None`` rule)."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=1000)

    @field_validator("name")
    @classmethod
    def _usable_name(cls, value: str | None) -> str | None:
        return None if value is None else check_group_name(value)

    @field_validator("description")
    @classmethod
    def _usable_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return clean_text(value)


class UserRef(BaseModel):
    """A person as both the API and the pages name them."""

    id: int
    username: str
    display_name: str | None = None


class UserOut(BaseModel):
    """One account - never its password hash (section 13)."""

    id: int
    username: str
    email: str
    display_name: str | None
    is_admin: bool
    is_active: bool
    last_login_at: datetime | None
    groups: list[str] = Field(default_factory=list)


class GroupOut(BaseModel):
    """One group with the people in it."""

    id: int
    name: str
    description: str | None
    members: list[UserRef] = Field(default_factory=list)


# --- guards and loaders -----------------------------------------------------


def require_users_admin(engine: Engine, user: dict[str, Any]) -> None:
    """The global ``users.admin`` permission of section 7."""
    if not can(engine, int(user["user_id"]), Permission.USERS_ADMIN):
        raise HTTPException(status_code=403, detail="users.admin permission required")


def user_out(conn: Connection, user_id: int) -> UserOut:
    """One account with the groups it belongs to, or 404."""
    row = (
        conn.execute(
            text(
                "SELECT id, username, email, display_name, is_admin, is_active, last_login_at "
                "FROM users WHERE id = :uid"
            ),
            {"uid": user_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    groups = [
        str(name)
        for (name,) in conn.execute(
            text(
                "SELECT g.name FROM group_members gm JOIN groups g ON g.id = gm.group_id "
                "WHERE gm.user_id = :uid ORDER BY g.name"
            ),
            {"uid": user_id},
        ).all()
    ]
    return UserOut(
        id=int(row["id"]),
        username=str(row["username"]),
        email=str(row["email"]),
        display_name=row["display_name"],
        is_admin=bool(row["is_admin"]),
        is_active=bool(row["is_active"]),
        last_login_at=row["last_login_at"],
        groups=groups,
    )


def list_users(conn: Connection) -> list[UserOut]:
    """Every account, by login name."""
    ids = [
        int(user_id)
        for (user_id,) in conn.execute(text("SELECT id FROM users ORDER BY username")).all()
    ]
    return [user_out(conn, user_id) for user_id in ids]


def group_out(conn: Connection, group_id: int) -> GroupOut:
    """One group with its members, or 404."""
    row = (
        conn.execute(
            text("SELECT id, name, description FROM groups WHERE id = :gid"), {"gid": group_id}
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Group not found")
    members = [
        UserRef(
            id=int(member["id"]),
            username=str(member["username"]),
            display_name=member["display_name"],
        )
        for member in conn.execute(
            text(
                "SELECT u.id, u.username, u.display_name FROM group_members gm "
                "JOIN users u ON u.id = gm.user_id WHERE gm.group_id = :gid ORDER BY u.username"
            ),
            {"gid": group_id},
        )
        .mappings()
        .all()
    ]
    return GroupOut(
        id=int(row["id"]),
        name=str(row["name"]),
        description=row["description"],
        members=members,
    )


def list_groups(conn: Connection) -> list[GroupOut]:
    """Every group, by name."""
    ids = [
        int(group_id)
        for (group_id,) in conn.execute(text("SELECT id FROM groups ORDER BY name")).all()
    ]
    return [group_out(conn, group_id) for group_id in ids]


def user_choices(conn: Connection) -> list[UserRef]:
    """Active accounts, by name - what an "add member" select offers."""
    return [
        UserRef(
            id=int(row["id"]),
            username=str(row["username"]),
            display_name=row["display_name"],
        )
        for row in conn.execute(
            text(
                "SELECT id, username, display_name FROM users WHERE is_active = TRUE "
                "ORDER BY COALESCE(NULLIF(display_name, ''), username)"
            )
        )
        .mappings()
        .all()
    ]


def _ensure_username_free(conn: Connection, username: str) -> None:
    if conn.execute(text("SELECT 1 FROM users WHERE username = :v"), {"v": username}).scalar():
        raise HTTPException(status_code=409, detail="A user with that username already exists")


def _ensure_email_free(conn: Connection, email: str, *, exclude_id: int | None = None) -> None:
    clause = "email = :value"
    params: dict[str, Any] = {"value": email}
    if exclude_id is not None:
        clause += " AND id <> :exclude"
        params["exclude"] = exclude_id
    if conn.execute(text(f"SELECT 1 FROM users WHERE {clause}"), params).scalar():
        raise HTTPException(status_code=409, detail="A user with that email already exists")


def _ensure_group_name_free(conn: Connection, name: str, *, exclude_id: int | None = None) -> None:
    clause = "name = :value"
    params: dict[str, Any] = {"value": name}
    if exclude_id is not None:
        clause += " AND id <> :exclude"
        params["exclude"] = exclude_id
    if conn.execute(text(f"SELECT 1 FROM groups WHERE {clause}"), params).scalar():
        raise HTTPException(status_code=409, detail="A group with that name already exists")


# --- the writes (one path for the API and the admin pages) ------------------


def create_user(
    engine: Engine,
    *,
    username: str,
    email: str,
    password: str,
    display_name: str | None,
    is_admin: bool,
    actor_id: int,
) -> UserOut:
    """Add an account that can sign in, and audit it (section 13).

    The transaction owns the uniqueness checks and the insert, so a form
    post on ``/admin/users`` and ``POST /api/v1/users`` cannot disagree
    about what a username is.
    """
    name = check_username(username)
    mail = check_email(email)
    secret = check_password(password)
    resolved_name = clean_text(display_name)
    with engine.begin() as conn:
        _ensure_username_free(conn, name)
        _ensure_email_free(conn, mail)
        user_id = conn.execute(
            text(
                "INSERT INTO users "
                "(username, email, display_name, password_hash, is_admin, is_active) "
                "VALUES (:username, :email, :display_name, :password_hash, :is_admin, TRUE) "
                "RETURNING id"
            ),
            {
                "username": name,
                "email": mail,
                "display_name": resolved_name,
                "password_hash": hash_password(secret),
                "is_admin": is_admin,
            },
        ).scalar_one()
        created = user_out(conn, int(user_id))
    write_audit(
        engine,
        action="user.create",
        actor_id=actor_id,
        target_type="user",
        target_id=created.id,
        details={"username": created.username, "is_admin": created.is_admin},
    )
    return created


def update_user(
    engine: Engine,
    user_id: int,
    *,
    email: str | None = None,
    display_name: str | None = None,
    is_admin: bool | None = None,
    is_active: bool | None = None,
    password: str | None = None,
    actor_id: int,
) -> UserOut:
    """Edit an account and audit what changed - never the password itself.

    ``None`` leaves a field alone. Two rules protect the caller from
    locking everyone out: you cannot take away your own admin flag, and you
    cannot deactivate your own account.
    """
    with engine.begin() as conn:
        current = conn.execute(
            text("SELECT username, is_admin, is_active FROM users WHERE id = :uid"),
            {"uid": user_id},
        ).first()
        if current is None:
            raise HTTPException(status_code=404, detail="User not found")
        username, was_admin, was_active = current
        if user_id == actor_id:
            if is_admin is False:
                raise HTTPException(status_code=400, detail="You cannot remove your own admin flag")
            if is_active is False:
                raise HTTPException(
                    status_code=400, detail="You cannot deactivate your own account"
                )
        updates: dict[str, Any] = {}
        changes: dict[str, Any] = {}
        if email is not None:
            mail = check_email(email)
            _ensure_email_free(conn, mail, exclude_id=user_id)
            updates["email"] = mail
            changes["email"] = mail
        if display_name is not None:
            resolved = clean_text(display_name)
            updates["display_name"] = resolved
            changes["display_name"] = resolved
        if is_admin is not None and is_admin != bool(was_admin):
            updates["is_admin"] = is_admin
            changes["is_admin"] = is_admin
        if is_active is not None and is_active != bool(was_active):
            updates["is_active"] = is_active
            changes["is_active"] = is_active
        if password is not None:
            updates["password_hash"] = hash_password(check_password(password))
            changes["password"] = "changed"
        if not updates:
            raise HTTPException(status_code=422, detail="Nothing to update")
        assignments = ", ".join(f"{column} = :{column}" for column in updates)
        params: dict[str, Any] = dict(updates)
        params["uid"] = user_id
        params["updated_at"] = datetime.now(timezone.utc)
        conn.execute(
            text(f"UPDATE users SET {assignments}, updated_at = :updated_at WHERE id = :uid"),
            params,
        )
        updated = user_out(conn, user_id)
        # A password reset or a deactivation must end every live session
        # (section 2: sessions are DB-backed so access can be cut off now).
        needs_session_revoke = bool(
            ("password_hash" in updates) or (is_active is False and bool(was_active))
        )
    if needs_session_revoke:
        expire_sessions_for_user(engine, user_id)
    write_audit(
        engine,
        action="user.update",
        actor_id=actor_id,
        target_type="user",
        target_id=user_id,
        details={"username": str(username), "changes": changes},
    )
    return updated


def create_group(engine: Engine, *, name: str, description: str | None, actor_id: int) -> GroupOut:
    """Start a group and audit it (section 13)."""
    resolved_name = check_group_name(name)
    resolved_description = clean_text(description)
    with engine.begin() as conn:
        _ensure_group_name_free(conn, resolved_name)
        group_id = conn.execute(
            text(
                "INSERT INTO groups (name, description) VALUES (:name, :description) RETURNING id"
            ),
            {"name": resolved_name, "description": resolved_description},
        ).scalar_one()
        created = group_out(conn, int(group_id))
    write_audit(
        engine,
        action="group.create",
        actor_id=actor_id,
        target_type="group",
        target_id=created.id,
        details={"name": created.name},
    )
    return created


def update_group(
    engine: Engine,
    group_id: int,
    *,
    name: str | None = None,
    description: str | None = None,
    actor_id: int,
) -> GroupOut:
    """Rename a group and/or rewrite its description, then audit it."""
    updates: dict[str, Any] = {}
    changes: dict[str, Any] = {}
    if name is not None:
        updates["name"] = check_group_name(name)
        changes["name"] = updates["name"]
    if description is not None:
        resolved = clean_text(description)
        updates["description"] = resolved
        changes["description"] = resolved
    if not updates:
        raise HTTPException(status_code=422, detail="Nothing to update")
    with engine.begin() as conn:
        group_out(conn, group_id)  # 404 when the group is gone
        if "name" in updates:
            _ensure_group_name_free(conn, str(updates["name"]), exclude_id=group_id)
        assignments = ", ".join(f"{column} = :{column}" for column in updates)
        params: dict[str, Any] = dict(updates)
        params["gid"] = group_id
        params["updated_at"] = datetime.now(timezone.utc)
        conn.execute(
            text(f"UPDATE groups SET {assignments}, updated_at = :updated_at WHERE id = :gid"),
            params,
        )
        updated = group_out(conn, group_id)
    write_audit(
        engine,
        action="group.update",
        actor_id=actor_id,
        target_type="group",
        target_id=group_id,
        details={"name": updated.name, "changes": changes},
    )
    return updated


def add_member(engine: Engine, group_id: int, user_id: int, *, actor_id: int) -> GroupOut:
    """Put somebody in a group - a permission change, so it is audited."""
    with engine.begin() as conn:
        group = group_out(conn, group_id)  # 404 when the group is gone
        person = conn.execute(
            text("SELECT username FROM users WHERE id = :uid"), {"uid": user_id}
        ).first()
        if person is None:
            raise HTTPException(status_code=404, detail="User not found")
        already = conn.execute(
            text("SELECT 1 FROM group_members WHERE group_id = :gid AND user_id = :uid"),
            {"gid": group_id, "uid": user_id},
        ).scalar()
        if already:
            raise HTTPException(status_code=409, detail="That user is already in this group")
        conn.execute(
            text("INSERT INTO group_members (group_id, user_id) VALUES (:gid, :uid)"),
            {"gid": group_id, "uid": user_id},
        )
        updated = group_out(conn, group_id)
    write_audit(
        engine,
        action="group.member_add",
        actor_id=actor_id,
        target_type="group",
        target_id=group_id,
        details={"group": group.name, "username": str(person[0])},
    )
    return updated


def remove_member(engine: Engine, group_id: int, user_id: int, *, actor_id: int) -> GroupOut:
    """Take somebody out of a group, and audit the grant that went away."""
    with engine.begin() as conn:
        group = group_out(conn, group_id)  # 404 when the group is gone
        person = conn.execute(
            text("SELECT username FROM users WHERE id = :uid"), {"uid": user_id}
        ).first()
        if person is None:
            raise HTTPException(status_code=404, detail="User not found")
        member = conn.execute(
            text("SELECT 1 FROM group_members WHERE group_id = :gid AND user_id = :uid"),
            {"gid": group_id, "uid": user_id},
        ).scalar()
        if not member:
            raise HTTPException(status_code=409, detail="That user is not in this group")
        conn.execute(
            text("DELETE FROM group_members WHERE group_id = :gid AND user_id = :uid"),
            {"gid": group_id, "uid": user_id},
        )
        updated = group_out(conn, group_id)
    write_audit(
        engine,
        action="group.member_remove",
        actor_id=actor_id,
        target_type="group",
        target_id=group_id,
        details={"group": group.name, "username": str(person[0])},
    )
    return updated


# --- the routes (section 12: session + users.admin) --------------------------


@router.get("/api/v1/users", response_model=list[UserOut])
def get_users(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> list[UserOut]:
    """Every account with its groups (section 12)."""
    engine = request.app.state.engine
    require_users_admin(engine, user)
    with engine.connect() as conn:
        return list_users(conn)


@router.post("/api/v1/users", response_model=UserOut, status_code=201)
def post_user(
    request: Request, payload: UserCreate, user: dict[str, Any] = Depends(get_current_user)
) -> UserOut:
    """Create an account (422 for a malformed body, 409 for a taken name)."""
    engine = request.app.state.engine
    require_users_admin(engine, user)
    return create_user(
        engine,
        username=payload.username,
        email=payload.email,
        password=payload.password,
        display_name=payload.display_name,
        is_admin=payload.is_admin,
        actor_id=int(user["user_id"]),
    )


@router.patch("/api/v1/users/{user_id}", response_model=UserOut)
def patch_user(
    request: Request,
    user_id: int,
    payload: UserPatch,
    user: dict[str, Any] = Depends(get_current_user),
) -> UserOut:
    """Edit an account: email, name, role, status or password."""
    engine = request.app.state.engine
    require_users_admin(engine, user)
    return update_user(
        engine,
        user_id,
        email=payload.email,
        display_name=payload.display_name,
        is_admin=payload.is_admin,
        is_active=payload.is_active,
        password=payload.password,
        actor_id=int(user["user_id"]),
    )


@router.get("/api/v1/groups", response_model=list[GroupOut])
def get_groups(
    request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> list[GroupOut]:
    """Every group with its members (section 12)."""
    engine = request.app.state.engine
    require_users_admin(engine, user)
    with engine.connect() as conn:
        return list_groups(conn)


@router.post("/api/v1/groups", response_model=GroupOut, status_code=201)
def post_group(
    request: Request, payload: GroupCreate, user: dict[str, Any] = Depends(get_current_user)
) -> GroupOut:
    """Create a group (409 when the name is taken)."""
    engine = request.app.state.engine
    require_users_admin(engine, user)
    return create_group(
        engine, name=payload.name, description=payload.description, actor_id=int(user["user_id"])
    )


@router.patch("/api/v1/groups/{group_id}", response_model=GroupOut)
def patch_group(
    request: Request,
    group_id: int,
    payload: GroupPatch,
    user: dict[str, Any] = Depends(get_current_user),
) -> GroupOut:
    """Rename a group and/or rewrite its description."""
    engine = request.app.state.engine
    require_users_admin(engine, user)
    if payload.name is None and payload.description is None:
        raise HTTPException(status_code=422, detail="Nothing to update")
    return update_group(
        engine,
        group_id,
        name=payload.name,
        description=payload.description,
        actor_id=int(user["user_id"]),
    )
