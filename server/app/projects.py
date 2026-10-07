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
from app.permissions import PERMISSION_TEMPLATES
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


__all__ = [
    "DuplicateProjectKey",
    "KEY_HELP",
    "LIST_SQL",
    "MEMBER_VISIBILITY",
    "ProjectKeyError",
    "create_project",
    "stored_settings",
    "validate_key",
    "visible_projects",
]
