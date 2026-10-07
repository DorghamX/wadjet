"""Project settings (section 10): read and write, validated server-side.

``GET /api/v1/projects/{project_id}/settings`` needs ``project.browse``,
``PUT`` needs ``project.admin``. The body is a complete ``ProjectSettings``
object - the schema fills defaults for anything the client omits - so the
stored ``projects.settings`` JSON is valid by construction, and unknown
keys (a smuggled free-form CLI arg, an unknown scanner) never land.
Every write lands in the audit log (section 15.4: settings changes).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text

from app.audit import write_audit
from app.deps import get_current_user
from app.permissions import Permission, can
from app.projects import (
    DuplicateProjectKey,
    ProjectKeyError,
    create_project,
    stored_settings,
    validate_key,
    visible_projects,
)
from wadjet_schema import ProjectSettings

router = APIRouter()


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
    return stored_settings(row[0])


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
    old = stored_settings(row[0])
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


class ProjectCreate(BaseModel):
    """The body of ``POST /api/v1/projects`` (section 12)."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("key")
    @classmethod
    def _usable_key(cls, value: str) -> str:
        return validate_key(value)

    @field_validator("name")
    @classmethod
    def _usable_name(cls, value: str) -> str:
        resolved = value.strip()
        if not resolved:
            raise ValueError("name is required")
        return resolved


def _is_global_admin(engine: Any, user: dict[str, Any]) -> bool:
    """The ``admin`` role of section 7: all permissions, everywhere."""
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT is_admin FROM users WHERE id = :uid AND is_active = TRUE"),
            {"uid": int(user["user_id"])},
        ).first()
    return bool(row and row[0])


class LatestAnalysis(BaseModel):
    """The newest analysis of a project, as the list reports it."""

    model_config = ConfigDict(extra="forbid")

    id: int
    status: str
    gate_status: str | None = None
    created_at: datetime


class ProjectListEntry(BaseModel):
    """One row of ``GET /api/v1/projects`` (section 12)."""

    model_config = ConfigDict(extra="forbid")

    id: int
    key: str
    name: str
    description: str | None = None
    analysis: LatestAnalysis | None = None


@router.get("/api/v1/projects", response_model=list[ProjectListEntry])
def get_projects(
    request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> list[ProjectListEntry]:
    """List the projects this session may browse.

    Same query, same rule as the projects page (section 7): a global admin
    sees every project, everyone else only the ones granted to them, directly
    or through a group. ``analysis`` is null until the project's first upload.
    """
    engine = request.app.state.engine
    rows = visible_projects(
        engine, user_id=int(user["user_id"]), is_admin=_is_global_admin(engine, user)
    )
    entries: list[ProjectListEntry] = []
    for row in rows:
        analysis: LatestAnalysis | None = None
        if row["analysis_id"] is not None:
            analysis = LatestAnalysis(
                id=int(row["analysis_id"]),
                status=str(row["analysis_status"]),
                gate_status=row["gate_status"],
                created_at=row["analysis_at"],
            )
        entries.append(
            ProjectListEntry(
                id=int(row["id"]),
                key=str(row["key"]),
                name=str(row["name"]),
                description=row["description"],
                analysis=analysis,
            )
        )
    return entries


@router.post("/api/v1/projects", status_code=201)
def post_projects(
    payload: ProjectCreate, request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any]:
    """Create a project.

    The guide defines no ``project.create`` permission (section 7 lists the
    whole set and it is not among them), so creation is a global-admin
    action; every member can browse, comment and triage what they are
    granted without being able to spawn projects.
    """
    engine = request.app.state.engine
    if not _is_global_admin(engine, user):
        raise HTTPException(status_code=403, detail="Only admins can create projects")
    try:
        project_id = create_project(
            engine,
            key=payload.key,
            name=payload.name,
            description=payload.description,
            creator_id=int(user["user_id"]),
            ip=request.client.host if request.client else None,
        )
    except ProjectKeyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except DuplicateProjectKey as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    return {
        "id": project_id,
        "key": payload.key,
        "name": payload.name,
        "description": payload.description,
    }


__all__ = ["router"]
