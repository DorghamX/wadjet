"""Project settings (section 10): read and write, validated server-side.

``GET /api/v1/projects/{project_id}/settings`` needs ``project.browse``,
``PUT`` needs ``project.admin``. The body is a complete ``ProjectSettings``
object - the schema fills defaults for anything the client omits - so the
stored ``projects.settings`` JSON is valid by construction, and unknown
keys (a smuggled free-form CLI arg, an unknown scanner) never land.
Every write lands in the audit log (section 15.4: settings changes).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import text

from app.audit import write_audit
from app.deps import get_current_user
from app.permissions import Permission, can
from wadjet_schema import ProjectSettings

router = APIRouter()


def _stored(raw: Any) -> ProjectSettings:
    """Stored JSON as settings; null or (historically) invalid means defaults."""
    if not isinstance(raw, str) or not raw:
        return ProjectSettings()
    try:
        return ProjectSettings.model_validate_json(raw)
    except ValidationError:
        return ProjectSettings()


def _flatten(values: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in values.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, name + "."))
        else:
            flat[name] = value
    return flat


def _changed_keys(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    before, after = _flatten(old), _flatten(new)
    return sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))


def _require_permission(
    engine: Any, user: dict[str, Any], project_id: int, permission: Permission, detail: str
) -> None:
    if not can(engine, int(user["user_id"]), permission, project_id):
        raise HTTPException(status_code=403, detail=detail)


@router.get("/api/v1/projects/{project_id}/settings", response_model=ProjectSettings)
def get_project_settings(
    project_id: int, request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> ProjectSettings:
    """The stored settings, validated, with defaults for anything unset."""
    engine = request.app.state.engine
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT settings FROM projects WHERE id = :pid"), {"pid": project_id}
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    _require_permission(
        engine, user, project_id, Permission.PROJECT_BROWSE, "project.browse permission required"
    )
    return _stored(row[0])


@router.put("/api/v1/projects/{project_id}/settings", response_model=ProjectSettings)
def put_project_settings(
    project_id: int,
    payload: ProjectSettings,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> ProjectSettings:
    """Replace the settings (an invalid body is rejected with 422 by the
    schema before anything is written)."""
    engine = request.app.state.engine
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT settings FROM projects WHERE id = :pid"), {"pid": project_id}
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    old = _stored(row[0])
    _require_permission(
        engine,
        user,
        project_id,
        Permission.PROJECT_ADMIN,
        "project.admin permission required",
    )
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE projects SET settings = :settings WHERE id = :pid"),
            {"settings": payload.model_dump_json(), "pid": project_id},
        )
    changed = _changed_keys(old.model_dump(mode="json"), payload.model_dump(mode="json"))
    if changed:
        write_audit(
            engine,
            action="project.settings_update",
            actor_id=int(user["user_id"]),
            target_type="project",
            target_id=project_id,
            details={"changed": changed},
        )
    return payload


__all__ = ["router"]
