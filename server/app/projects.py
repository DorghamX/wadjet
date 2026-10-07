"""Project creation, stored settings and the visible list (sections 4, 7, 10, 12).

One implementation of the three things the JSON API and the pages both need:
validating a project key (the key is a URL slug and immutable, section 10),
turning stored settings JSON into the validated ``ProjectSettings`` object,
and deciding which projects a user may see (section 7). No route may invent
its own rules.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, cast

from pydantic import ValidationError
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import IntegrityError

from app.audit import write_audit
from app.permissions import PERMISSION_TEMPLATES, Permission, can
from wadjet_schema import ProjectSettings

#: Page routes claim these keys for themselves; a project may not take one.
RESERVED_KEYS = frozenset({"new"})

#: The immutable key: lowercase slug, first character alphanumeric, max 64.
KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

KEY_HELP = (
    "key must start with a lowercase letter or a digit and may contain "
    "lowercase letters, digits, dot, dash and underscore, up to 64 characters"
)


class ProjectKeyError(ValueError):
    """The submitted key is not a usable project key."""


class DuplicateProjectKey(ValueError):
    """A project already owns this key."""


def validate_key(key: str) -> str:
    """Return the normalized key, or raise ``ProjectKeyError``."""
    normalized = str(key).strip()
    if not KEY_PATTERN.match(normalized):
        raise ProjectKeyError(KEY_HELP)
    if normalized in RESERVED_KEYS:
        raise ProjectKeyError(f"key {normalized!r} is reserved by the pages")
    return normalized


def stored_settings(raw: Any) -> ProjectSettings:
    """Stored JSON as settings; null or (historically) invalid means defaults."""
    if not isinstance(raw, str) or not raw:
        return ProjectSettings()
    try:
        return ProjectSettings.model_validate_json(raw)
    except ValidationError:
        return ProjectSettings()


def _insert_project(
    conn: Connection, *, key: str, name: str, description: str | None, creator_id: int
) -> int:
    """Insert one project and hand its creator the project admin template."""
    resolved_key = validate_key(key)
    resolved_name = str(name).strip()
    if not resolved_name:
        raise ProjectKeyError("name is required")
    try:
        project_id = int(
            conn.execute(
                text(
                    "INSERT INTO projects (key, name, description, created_by) "
                    "VALUES (:key, :name, :description, :creator) RETURNING id"
                ),
                {
                    "key": resolved_key,
                    "name": resolved_name[:255],
                    "description": (str(description).strip() or None) if description else None,
                    "creator": creator_id,
                },
            ).scalar_one()
        )
    except IntegrityError as exc:
        raise DuplicateProjectKey(f"project key {resolved_key!r} already exists") from exc
    for permission in PERMISSION_TEMPLATES["project_admin"]:
        conn.execute(
            text(
                "INSERT INTO project_grants "
                "(project_id, subject_type, subject_id, permission) "
                "VALUES (:pid, 'user', :uid, :permission)"
            ),
            {"pid": project_id, "uid": creator_id, "permission": permission.value},
        )
    return project_id


def create_project(
    engine: Engine,
    *,
    key: str,
    name: str,
    description: str | None,
    creator_id: int,
    ip: str | None = None,
) -> int:
    """Create a project with its creator's grants, then audit it (section 13).

    The caller decides who may create projects; this function decides whether
    the payload can become a row. Both checks live in the service layer so the
    API endpoint and the page form cannot drift apart.
    """
    with engine.begin() as conn:
        project_id = _insert_project(
            conn, key=key, name=name, description=description, creator_id=creator_id
        )
    write_audit(
        engine,
        action="project.create",
        actor_id=creator_id,
        target_type="project",
        target_id=project_id,
        details={"key": key, "name": name},
        ip=ip,
    )
    return project_id


#: One row per project plus its newest analysis (NULL columns when nothing
#: has run yet): the projects list answers "what is broken" at a glance.
LIST_SQL = """
SELECT p.id, p.key, p.name, p.description,
       a.id AS analysis_id, a.status AS analysis_status,
       a.gate_status, a.metrics, a.created_at AS analysis_at
FROM projects p
LEFT JOIN LATERAL (
    SELECT id, status, gate_status, metrics, created_at
    FROM analyses
    WHERE project_id = p.id
    ORDER BY created_at DESC, id DESC
    LIMIT 1
) a ON TRUE
WHERE {visibility}
ORDER BY p.key
"""

#: A member sees only projects granted to them (directly or through a group);
#: admins see everything (section 7).
MEMBER_VISIBILITY = """
EXISTS (
    SELECT 1 FROM project_grants g
    WHERE g.project_id = p.id
      AND g.permission = 'project.browse'
      AND (
           (g.subject_type = 'user' AND g.subject_id = :uid)
           OR (g.subject_type = 'group'
               AND g.subject_id IN (
                   SELECT gm.group_id FROM group_members gm WHERE gm.user_id = :uid
               ))
      )
)
"""


def visible_projects(
    engine: Engine, *, user_id: int, is_admin: bool
) -> Sequence[Mapping[str, Any]]:
    """Every project this user may browse, newest analysis attached.

    The page and the JSON API both render *this* list, so "what you can see"
    has exactly one definition: a global admin sees all projects, everyone
    else sees only what they hold ``project.browse`` on.
    """
    visibility = "TRUE" if is_admin else MEMBER_VISIBILITY
    with engine.connect() as conn:
        rows = (
            conn.execute(text(LIST_SQL.format(visibility=visibility)), {"uid": user_id})
            .mappings()
            .all()
        )
    # SQLAlchemy's RowMapping declares an unresolvable key type (its _KeyType
    # is a Union alias, not a TypeVar); every column here is a literal string
    # name, so the mapping really is str -> value.
    return cast(Sequence[Mapping[str, Any]], rows)


def visible_project(engine: Engine, *, key: str, user_id: int) -> Mapping[str, Any] | None:
    """The project row when ``key`` exists *and* the caller may browse it.

    Section 7 makes the two failures indistinguishable on purpose: whoever
    cannot see a project must not learn whether it exists. Pages render one
    404 and the JSON API answers 404 - both call this, so the rule cannot
    drift apart between them.
    """
    with engine.connect() as conn:
        row = (
            conn.execute(
                text("SELECT id, key, name, description, settings FROM projects WHERE key = :key"),
                {"key": key},
            )
            .mappings()
            .first()
        )
    if row is None:
        return None
    if not can(engine, user_id, Permission.PROJECT_BROWSE, int(row["id"])):
        return None
    return cast(Mapping[str, Any], row)


# --- stored settings writes (sections 10, 13) ------------------------------


def _flatten(values: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """``{"scanners": {"enabled": True}}`` as ``{"scanners.enabled": True}``."""
    flat: dict[str, Any] = {}
    for key, value in values.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, name + "."))
        else:
            flat[name] = value
    return flat


def changed_keys(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """The settings paths that moved between two dumps, sorted.

    The audit entry names *keys*, never values: a settings change is a
    permission-relevant fact, but the values may hold paths and options.
    """
    before, after = _flatten(old), _flatten(new)
    return sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))


def save_settings(
    engine: Engine,
    *,
    project_id: int,
    payload: ProjectSettings,
    actor_id: int,
    ip: str | None = None,
) -> list[str]:
    """Replace the stored settings and audit what moved (section 13).

    The caller has already validated the body against ``ProjectSettings`` -
    this function owns the write and its audit row so the JSON API and the
    settings pages cannot disagree about either. Returns the changed paths;
    an empty list means nothing was written and nothing is audited.
    """
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT settings FROM projects WHERE id = :pid FOR UPDATE"),
            {"pid": project_id},
        ).first()
        if row is None:
            return []
        previous = stored_settings(row[0])
        conn.execute(
            text("UPDATE projects SET settings = :settings WHERE id = :pid"),
            {"settings": payload.model_dump_json(), "pid": project_id},
        )
    changed = changed_keys(previous.model_dump(mode="json"), payload.model_dump(mode="json"))
    if changed:
        write_audit(
            engine,
            action="project.settings_update",
            actor_id=actor_id,
            target_type="project",
            target_id=project_id,
            details={"changed": changed},
            ip=ip,
        )
    return changed


# --- project fields and the danger zone (section 10) -----------------------


class MissingProject(ValueError):
    """The project id no longer names a row."""


class UnknownGate(ValueError):
    """The submitted gate id does not name a quality gate."""


def validate_fields(name: str, description: str | None) -> tuple[str, str | None]:
    """Normalized ``(name, description)`` for the general settings form."""
    resolved_name = str(name).strip()
    if not resolved_name:
        raise ProjectKeyError("name is required")
    if len(resolved_name) > 255:
        raise ProjectKeyError("name must be 255 characters or fewer")
    resolved_description = str(description).strip() if description else None
    if resolved_description == "":
        resolved_description = None
    if resolved_description is not None and len(resolved_description) > 2000:
        raise ProjectKeyError("description must be 2000 characters or fewer")
    return resolved_name, resolved_description


def update_project(
    engine: Engine,
    *,
    project_id: int,
    name: str,
    description: str | None,
    actor_id: int,
    ip: str | None = None,
) -> dict[str, Any]:
    """Rename or re-describe a project, then audit it (section 13).

    The key is deliberately not a parameter: section 10 makes it immutable,
    so there is no code path here that could move it.
    """
    resolved_name, resolved_description = validate_fields(name, description)
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT name, description FROM projects WHERE id = :pid FOR UPDATE"),
            {"pid": project_id},
        ).first()
        if row is None:
            raise MissingProject(f"project {project_id} no longer exists")
        changed: dict[str, Any] = {}
        if row[0] != resolved_name:
            changed["name"] = resolved_name
        if (row[1] or None) != resolved_description:
            changed["description"] = resolved_description
        if changed:
            conn.execute(
                text(
                    "UPDATE projects SET name = :name, description = :description WHERE id = :pid"
                ),
                {
                    "name": resolved_name,
                    "description": resolved_description,
                    "pid": project_id,
                },
            )
    if changed:
        write_audit(
            engine,
            action="project.update",
            actor_id=actor_id,
            target_type="project",
            target_id=project_id,
            details={"changed": sorted(changed)},
            ip=ip,
        )
    return {"name": resolved_name, "description": resolved_description, "changed": sorted(changed)}


def set_gate(
    engine: Engine,
    *,
    project_id: int,
    gate_id: int | None,
    actor_id: int,
    ip: str | None = None,
) -> int | None:
    """Point a project at a gate (section 10: "Quality gate: choose the gate").

    ``None`` means the built-in default, which is what a project that has
    never chosen one already falls back to (see ``app.gate``). Choosing the
    same gate again writes nothing and audits nothing.
    """
    gate_name: str | None = None
    with engine.begin() as conn:
        if gate_id is not None:
            gate = conn.execute(
                text("SELECT name FROM quality_gates WHERE id = :gid"), {"gid": gate_id}
            ).first()
            if gate is None:
                raise UnknownGate(f"no quality gate with id {gate_id}")
            gate_name = str(gate[0])
        row = conn.execute(
            text("SELECT gate_id FROM projects WHERE id = :pid FOR UPDATE"), {"pid": project_id}
        ).first()
        if row is None:
            raise MissingProject(f"project {project_id} no longer exists")
        if row[0] == gate_id:
            return gate_id
        conn.execute(
            text("UPDATE projects SET gate_id = :gid WHERE id = :pid"),
            {"gid": gate_id, "pid": project_id},
        )
    write_audit(
        engine,
        action="project.gate_update",
        actor_id=actor_id,
        target_type="project",
        target_id=project_id,
        details={"gate_id": gate_id, "gate_name": gate_name},
        ip=ip,
    )
    return gate_id


#: Everything that references a project, children before parents. No foreign
#: key in the schema (migrations 0003, 0004, 0007) carries ON DELETE CASCADE,
#: so a delete walks this list itself - and a new project-referencing table
#: must be added here, which is why the list lives in one named constant.
PROJECT_CASCADE: tuple[tuple[str, str], ...] = (
    ("issue_comments", "issue_id IN (SELECT id FROM issues WHERE project_id = :pid)"),
    ("issue_requests", "issue_id IN (SELECT id FROM issues WHERE project_id = :pid)"),
    ("issue_events", "issue_id IN (SELECT id FROM issues WHERE project_id = :pid)"),
    ("issues", "project_id = :pid"),
    ("analyses", "project_id = :pid"),
    ("project_grants", "project_id = :pid"),
    ("api_tokens", "project_id = :pid"),
    ("projects", "id = :pid"),
)


def delete_project(
    engine: Engine, *, project_id: int, actor_id: int, ip: str | None = None
) -> dict[str, Any] | None:
    """Delete a project and everything hanging off it in one transaction.

    Returns the deleted ``{"key", "name"}`` for the audit row, or ``None``
    when the project was already gone (nothing to do, nothing to audit).
    """
    with engine.begin() as conn:
        row = (
            conn.execute(
                text("SELECT key, name FROM projects WHERE id = :pid FOR UPDATE"),
                {"pid": project_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        deleted = {"key": str(row["key"]), "name": str(row["name"])}
        for table, clause in PROJECT_CASCADE:
            conn.execute(text(f"DELETE FROM {table} WHERE {clause}"), {"pid": project_id})
    write_audit(
        engine,
        action="project.delete",
        actor_id=actor_id,
        target_type="project",
        target_id=project_id,
        details=deleted,
        ip=ip,
    )
    return deleted


# --- members (section 7) ---------------------------------------------------


#: The subject kinds a grant may name, and the table each one points at.
SUBJECT_TABLES = {"user": "users", "group": "groups"}

#: The design's members matrix columns ("Members and permissions"), in order.
MEMBER_COLUMNS: tuple[tuple[str, str], ...] = (
    ("project.browse", "Browse"),
    ("issue.comment", "Comment"),
    ("issue.assign", "Assign"),
    ("flag.confirm", "Confirm"),
    ("flag.false_positive", "False positive"),
    ("flag.accepted_risk", "Accepted risk"),
    ("flag.wont_fix", "Won't fix"),
    ("flag.reopen", "Reopen"),
    ("project.admin", "Admin"),
)


class MemberError(ValueError):
    """The submitted grant cannot become a row."""


def subject_kind(subject_type: str) -> str:
    """Normalize ``user``/``group``, or raise ``MemberError``."""
    kind = str(subject_type).strip().lower()
    if kind not in SUBJECT_TABLES:
        raise MemberError("subject_type must be 'user' or 'group'")
    return kind


#: One row per grant; the rows are grouped into subjects by the reader.
MEMBERS_SQL = """
SELECT g.subject_type, g.subject_id, g.permission,
       u.username, u.display_name, u.is_active,
       grp.name AS group_name,
       (SELECT count(*) FROM group_members gm WHERE gm.group_id = g.subject_id) AS group_size
FROM project_grants g
LEFT JOIN users u ON u.id = g.subject_id AND g.subject_type = 'user'
LEFT JOIN groups grp ON grp.id = g.subject_id AND g.subject_type = 'group'
WHERE g.project_id = :pid
ORDER BY g.subject_type, g.subject_id, g.permission
"""


def list_members(engine: Engine, project_id: int) -> list[dict[str, Any]]:
    """One entry per granted user or group, with the permissions it holds.

    Effective permissions are the union of direct and group grants (section
    7); this is the stored side of that union, which is exactly what the
    members matrix shows: who was granted what, by name.
    """
    with engine.connect() as conn:
        rows = cast(
            Sequence[Mapping[str, Any]],
            conn.execute(text(MEMBERS_SQL), {"pid": project_id}).mappings().all(),
        )
    grouped: dict[tuple[str, int], dict[str, Any]] = {}
    for row in rows:
        kind = str(row["subject_type"])
        subject_id = int(row["subject_id"])
        entry = grouped.get((kind, subject_id))
        if entry is None:
            if kind == "group":
                name = str(row["group_name"] or f"group {subject_id}")
                size = int(row["group_size"] or 0)
                people = "person" if size == 1 else "people"
                subtitle = f"Group, {size} {people}"
            else:
                name = str(row["display_name"] or row["username"] or f"user {subject_id}")
                active = bool(row["is_active"])
                subtitle = "User" if active else "User (disabled)"
            entry = {
                "subject_type": kind,
                "subject_id": subject_id,
                "name": name,
                "subtitle": subtitle,
                "permissions": [],
            }
            grouped[(kind, subject_id)] = entry
        entry["permissions"].append(str(row["permission"]))
    # The design lists groups first, then people; each group by name.
    return sorted(
        grouped.values(), key=lambda m: (m["subject_type"] != "group", str(m["name"]).lower())
    )


def grant(
    engine: Engine,
    *,
    project_id: int,
    subject_type: str,
    subject_id: int,
    template: str,
    actor_id: int,
    ip: str | None = None,
) -> dict[str, Any]:
    """Give a user or group a permission template, replacing what it held.

    Grants are stored one row per permission, so "add a member" is a
    replace-all of that subject's rows: the template (section 7) is the unit
    a human reasons about, and a half-updated subject would show a matrix
    nobody chose. Audited as a permission change (section 13).
    """
    kind = subject_kind(subject_type)
    if template not in PERMISSION_TEMPLATES:
        expected = ", ".join(sorted(PERMISSION_TEMPLATES))
        raise MemberError(f"unknown permission template {template!r}; expected one of: {expected}")
    permissions = sorted(PERMISSION_TEMPLATES[template], key=lambda p: p.value)
    with engine.begin() as conn:
        table = SUBJECT_TABLES[kind]
        if not conn.execute(
            text(f"SELECT 1 FROM {table} WHERE id = :sid"), {"sid": subject_id}
        ).scalar():
            raise MemberError(f"no {kind} with id {subject_id}")
        conn.execute(
            text(
                "DELETE FROM project_grants "
                "WHERE project_id = :pid AND subject_type = :kind AND subject_id = :sid"
            ),
            {"pid": project_id, "kind": kind, "sid": subject_id},
        )
        for permission in permissions:
            conn.execute(
                text(
                    "INSERT INTO project_grants "
                    "(project_id, subject_type, subject_id, permission) "
                    "VALUES (:pid, :kind, :sid, :permission)"
                ),
                {
                    "pid": project_id,
                    "kind": kind,
                    "sid": subject_id,
                    "permission": permission.value,
                },
            )
    write_audit(
        engine,
        action="permission.grant",
        actor_id=actor_id,
        target_type="project",
        target_id=project_id,
        details={
            "subject_type": kind,
            "subject_id": subject_id,
            "template": template,
            "permissions": [permission.value for permission in permissions],
        },
        ip=ip,
    )
    return {
        "subject_type": kind,
        "subject_id": subject_id,
        "template": template,
        "permissions": [permission.value for permission in permissions],
    }


def revoke(
    engine: Engine,
    *,
    project_id: int,
    subject_type: str,
    subject_id: int,
    actor_id: int,
    ip: str | None = None,
) -> bool:
    """Take every permission away from one user or group on this project.

    Returns ``False`` when there was nothing to revoke, so the caller can
    answer 404 instead of pretending an action happened.
    """
    kind = subject_kind(subject_type)
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "DELETE FROM project_grants "
                "WHERE project_id = :pid AND subject_type = :kind AND subject_id = :sid"
            ),
            {"pid": project_id, "kind": kind, "sid": subject_id},
        )
        if not result.rowcount:
            return False
    write_audit(
        engine,
        action="permission.revoke",
        actor_id=actor_id,
        target_type="project",
        target_id=project_id,
        details={"subject_type": kind, "subject_id": subject_id},
        ip=ip,
    )
    return True


def principal_choices(engine: Engine) -> dict[str, list[dict[str, Any]]]:
    """The users and groups the "add member" select offers, by name."""
    with engine.connect() as conn:
        users = cast(
            Sequence[Mapping[str, Any]],
            conn.execute(
                text(
                    "SELECT id, username, display_name FROM users WHERE is_active = TRUE "
                    "ORDER BY COALESCE(NULLIF(display_name, ''), username)"
                )
            )
            .mappings()
            .all(),
        )
        groups = cast(
            Sequence[Mapping[str, Any]],
            conn.execute(text("SELECT id, name FROM groups ORDER BY name")).mappings().all(),
        )
    return {
        "users": [
            {
                "value": f"user:{int(row['id'])}",
                "label": str(row["display_name"] or row["username"]),
                "hint": str(row["username"]),
            }
            for row in users
        ],
        "groups": [
            {"value": f"group:{int(row['id'])}", "label": str(row["name"]), "hint": "Group"}
            for row in groups
        ],
    }


__all__ = [
    "DuplicateProjectKey",
    "KEY_HELP",
    "LIST_SQL",
    "MEMBER_COLUMNS",
    "MEMBER_VISIBILITY",
    "MemberError",
    "MissingProject",
    "PROJECT_CASCADE",
    "ProjectKeyError",
    "SUBJECT_TABLES",
    "UnknownGate",
    "changed_keys",
    "create_project",
    "delete_project",
    "grant",
    "list_members",
    "principal_choices",
    "revoke",
    "save_settings",
    "set_gate",
    "stored_settings",
    "subject_kind",
    "update_project",
    "validate_fields",
    "validate_key",
    "visible_project",
    "visible_projects",
]
