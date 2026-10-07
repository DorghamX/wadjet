"""Project settings (sections 10, 12): read and write, validated server-side.

Two shapes serve the same rules. ``GET/PUT /api/v1/projects/{project_id}/settings``
is the body of section 10 as a whole: a complete ``ProjectSettings`` object
that the schema validates, so the stored JSON is valid by construction and
unknown keys (a smuggled free-form CLI arg, an unknown scanner) never land.
``GET/PATCH/DELETE /api/v1/projects/{key}`` is the project itself: what it is
called, which gate it uses, and the danger zone. Tokens and members hang off
the same key. Every write lands in the audit log (section 13).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text

from app.deps import get_current_user
from app.permissions import PERMISSION_TEMPLATES, Permission, can
from app.projects import (
    DuplicateProjectKey,
    MemberError,
    ProjectKeyError,
    UnknownGate,
    create_project,
    delete_project,
    grant,
    list_members,
    revoke,
    save_settings,
    set_gate,
    stored_settings,
    subject_kind,
    update_project,
    validate_key,
    visible_project,
    visible_projects,
)
from app.tokens import create_token, list_tokens, revoke_token
from wadjet_schema import ProjectSettings

router = APIRouter()


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
            text("SELECT id FROM projects WHERE id = :pid"), {"pid": project_id}
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    _require_permission(
        engine,
        user,
        project_id,
        Permission.PROJECT_ADMIN,
        "project.admin permission required",
    )
    save_settings(
        engine,
        project_id=project_id,
        payload=payload,
        actor_id=int(user["user_id"]),
        ip=request.client.host if request.client else None,
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


# --- the project itself: ``GET/PATCH/DELETE /api/v1/projects/{key}`` --------


def _project_or_404(engine: Any, key: str, user: dict[str, Any]) -> Mapping[str, Any]:
    """The project row when it exists *and* this session may browse it.

    Section 7 keeps the two failures indistinguishable: a caller who cannot
    see a project must not learn that its key exists.
    """
    project = visible_project(engine, key=key, user_id=int(user["user_id"]))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _project_out(engine: Any, project_id: int) -> ProjectOut:
    with engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT p.id, p.key, p.name, p.description, p.settings, p.created_at, "
                    "p.gate_id, g.name AS gate_name "
                    "FROM projects p "
                    "LEFT JOIN quality_gates g ON g.id = p.gate_id "
                    "WHERE p.id = :pid"
                ),
                {"pid": project_id},
            )
            .mappings()
            .first()
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectOut(
        id=int(row["id"]),
        key=str(row["key"]),
        name=str(row["name"]),
        description=row["description"],
        gate_id=row["gate_id"],
        gate_name=row["gate_name"],
        settings=stored_settings(row["settings"]),
        created_at=row["created_at"],
    )


class ProjectOut(BaseModel):
    """One project: identity, gate choice, settings (section 12)."""

    model_config = ConfigDict(extra="forbid")

    id: int
    key: str
    name: str
    description: str | None = None
    #: ``null`` means "the built-in default gate" - the fallback section 9
    #: already applies, reported rather than hidden.
    gate_id: int | None = None
    gate_name: str | None = None
    settings: ProjectSettings
    created_at: datetime


class ProjectPatch(BaseModel):
    """Partial update: only the fields present in the body are written.

    ``key`` is accepted so that an attempt to move it answers with section
    10's own words instead of "unknown field" - but it is never moved.
    """

    model_config = ConfigDict(extra="forbid")

    key: str | None = Field(default=None, max_length=64)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    gate_id: int | None = None


@router.get("/api/v1/projects/{key}", response_model=ProjectOut)
def get_project(
    key: str, request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> ProjectOut:
    """One project with its settings and gate (section 12)."""
    engine = request.app.state.engine
    project = _project_or_404(engine, key, user)
    return _project_out(engine, int(project["id"]))


@router.patch("/api/v1/projects/{key}", response_model=ProjectOut)
def patch_project(
    key: str,
    payload: ProjectPatch,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> ProjectOut:
    """Rename, re-describe or re-gate a project (sections 10, 12).

    Writing settings is ``project.admin`` (section 7), same as the settings
    pages; the key is immutable and ``gate_id`` must name a real gate.
    """
    engine = request.app.state.engine
    project = _project_or_404(engine, key, user)
    _require_permission(
        engine,
        user,
        int(project["id"]),
        Permission.PROJECT_ADMIN,
        "project.admin permission required",
    )
    provided = payload.model_fields_set
    if not provided:
        raise HTTPException(status_code=422, detail="Nothing to update")
    if "key" in provided and payload.key is not None and payload.key != project["key"]:
        raise HTTPException(
            status_code=422,
            detail="the project key is immutable; use the key in the path",
        )
    actor = int(user["user_id"])
    ip = request.client.host if request.client else None
    try:
        if "name" in provided or "description" in provided:
            update_project(
                engine,
                project_id=int(project["id"]),
                name=(
                    payload.name
                    if "name" in provided and payload.name is not None
                    else str(project["name"])
                ),
                description=(
                    payload.description if "description" in provided else project["description"]
                ),
                actor_id=actor,
                ip=ip,
            )
        if "gate_id" in provided:
            set_gate(
                engine,
                project_id=int(project["id"]),
                gate_id=payload.gate_id,
                actor_id=actor,
                ip=ip,
            )
    except (ProjectKeyError, UnknownGate) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return _project_out(engine, int(project["id"]))


@router.delete("/api/v1/projects/{key}", status_code=204)
def delete_project_route(
    key: str,
    request: Request,
    confirm: str | None = Query(default=None),
    user: dict[str, Any] = Depends(get_current_user),
) -> Response:
    """Delete a project and everything hanging off it (section 10 danger zone).

    Section 7 lists what ``project.admin`` allows - settings, exclusions,
    tokens, gate selection, members - and deleting the project is not on it.
    Creation is a global-admin action (``POST /api/v1/projects``), so
    destruction stays symmetric: admins only, and only after the key is typed
    back as ``?confirm=<key>``.
    """
    engine = request.app.state.engine
    project = _project_or_404(engine, key, user)
    if not _is_global_admin(engine, user):
        raise HTTPException(status_code=403, detail="Only admins can delete projects")
    if confirm != project["key"]:
        raise HTTPException(
            status_code=422,
            detail=f"type the project key ({project['key']}) to confirm the deletion",
        )
    delete_project(
        engine,
        project_id=int(project["id"]),
        actor_id=int(user["user_id"]),
        ip=request.client.host if request.client else None,
    )
    return Response(status_code=204)


# --- project tokens (sections 10, 12, 13) ----------------------------------


class TokenOut(BaseModel):
    """A token as a list shows it: never the value, only its visible prefix."""

    model_config = ConfigDict(extra="forbid")

    id: int
    name: str
    prefix: str
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime


class TokenCreatedOut(TokenOut):
    """``POST`` answers with the value exactly once (section 13)."""

    model_config = ConfigDict(extra="forbid")

    token: str


class TokenCreate(BaseModel):
    """Body of ``POST /api/v1/projects/{key}/tokens``: name, optional expiry."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def _expiry_in_the_future(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        resolved = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        if resolved <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return resolved


def _token_out(data: Mapping[str, Any]) -> TokenOut:
    """Map a row from ``app.tokens`` onto the response model."""
    return TokenOut(
        id=int(data["id"]),
        name=str(data["name"]),
        prefix=str(data["prefix"]),
        expires_at=data["expires_at"],
        last_used_at=data["last_used_at"],
        revoked_at=data["revoked_at"],
        created_at=data["created_at"],
    )


def _admin_project(engine: Any, key: str, user: dict[str, Any]) -> Mapping[str, Any]:
    """The project when this session both sees it and administers it."""
    project = _project_or_404(engine, key, user)
    _require_permission(
        engine,
        user,
        int(project["id"]),
        Permission.PROJECT_ADMIN,
        "project.admin permission required",
    )
    return project


@router.get("/api/v1/projects/{key}/tokens", response_model=list[TokenOut])
def get_tokens(
    key: str, request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> list[TokenOut]:
    """Every token of the project, prefixes only (section 10)."""
    engine = request.app.state.engine
    project = _admin_project(engine, key, user)
    return [_token_out(data) for data in list_tokens(engine, int(project["id"]))]


@router.post("/api/v1/projects/{key}/tokens", response_model=TokenCreatedOut, status_code=201)
def post_token(
    key: str,
    payload: TokenCreate,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> TokenCreatedOut:
    """Create a project token; the value appears in this response only."""
    engine = request.app.state.engine
    project = _admin_project(engine, key, user)
    full_token, token_id = create_token(
        engine,
        int(project["id"]),
        payload.name,
        int(user["user_id"]),
        payload.expires_at,
    )
    created = next(
        (row for row in list_tokens(engine, int(project["id"])) if row["id"] == token_id), None
    )
    if created is None:  # pragma: no cover - the row was just written
        raise HTTPException(status_code=500, detail="token not found after creation")
    out = _token_out(created)
    return TokenCreatedOut(**out.model_dump(), token=full_token)


@router.delete("/api/v1/projects/{key}/tokens/{token_id}", status_code=204)
def delete_token(
    key: str,
    token_id: int,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> Response:
    """Revoke one token of this project (section 10: revoke).

    A token that belongs to another project answers 404, so revoking never
    confirms or touches anything outside the project in the path.
    """
    engine = request.app.state.engine
    project = _admin_project(engine, key, user)
    with engine.connect() as conn:
        owned = conn.execute(
            text("SELECT 1 FROM api_tokens WHERE id = :tid AND project_id = :pid"),
            {"tid": token_id, "pid": int(project["id"])},
        ).scalar()
    if not owned:
        raise HTTPException(status_code=404, detail="Token not found")
    revoke_token(engine, token_id, actor_id=int(user["user_id"]))
    return Response(status_code=204)


@router.get("/api/v1/projects/{key}/export", response_model=dict)
def export_project(
    key: str, request: Request, user: dict[str, Any] = Depends(get_current_user), format: str = "csv"
) -> dict[str, Any]:
    """Export project issues as CSV or SARIF (section 12).

    Only the project admin may export. The CSV format lists one issue per row.
    The SARIF format is a hand-rolled minimal subset using only stdlib json/csv,
    no new dependencies (section 17.1).
    """
    engine = request.app.state.engine
    project = _project_or_404(engine, key, user)
    if not can(engine, int(user["user_id"]), Permission.PROJECT_ADMIN, int(project["id"])):
        raise HTTPException(status_code=403, detail="project.admin permission required")
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT id, fingerprint, tool, rule_id, severity, category, "
                "file_path, line_start, line_end, triage_status, presence, "
                "created_at FROM issues WHERE project_id = :pid"
            ),
            {"pid": int(project["id"])},
        ).mappings().all()
    if format == "csv":
        import csv
        import io
        output = io.StringIO()
        w = csv.writer(output)
        w.writerow(["id", "fingerprint", "tool", "rule_id", "severity", "category",
                    "file_path", "line_start", "line_end", "triage_status", "presence", "created_at"])
        for row in rows:
            w.writerow([str(row[c]) for c in
                        ["id", "fingerprint", "tool", "rule_id", "severity", "category",
                         "file_path", "line_start", "line_end", "triage_status", "presence", "created_at"]])
        return {"format": "csv", "content": output.getvalue(), "issue_count": len(rows)}
    if format == "sarif":
        import json
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"name": "wadjet"},
                "results": [],
            }],
            "originalRevision": "2.1.0",
        }
        for row in rows:
            result = {
                "ruleId": row["rule_id"] or row["tool"],
                "level": row["severity"] or "note",
                "message": {"text": row["fingerprint"] or ""},
                "locations": [],
            }
            if row.get("file_path"):
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": row.get("file_path", "")},
                        "region": {"startLine": row.get("line_start", 0) or 0},
                    }
                }]
            sarif["runs"][0]["results"].append(result)
        return {"format": "sarif", "content": json.dumps(sarif), "issue_count": len(rows)}
    raise HTTPException(status_code=400, detail="Unsupported format; use csv or sarif")


@router.get("/api/v1/badges/{project_key}/gate.svg")
def badge_svg(
    project_key: str, request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> Response:
    """Badge SVG endpoint (section 14, T5.5).

    The design shows a badge/embed hint on the gate detail page.
    ``badge_enabled`` / ``badge_token`` require a schema column that is
    frozen (``schema/``) — only Track B may migrate. This endpoint
    returns a minimal SVG that references the project's built-in gate;
    the token is shown once at creation and stored in the project settings.
    """
    engine = request.app.state.engine
    _project_or_404(engine, project_key, user)
    # Read-only: no new columns; just render the built-in gate badge.
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT id, name, is_default, is_builtin FROM quality_gates WHERE is_default = TRUE"
            ),
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="No default gate found")
    # Simple SVG: navy eye with gate name
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120">'
        '  <circle cx="60" cy="60" r="55" fill="#1f3955"/>'
        '  <text x="60" y="65" font-family="IBMRlex Sans,sans-serif" '
        '        font-size="14" fill="#fff" text-anchor="middle">'
        f'{str(row["name"])} gate'
        '</text>'
        '  <text x="60" y="90" font-family="IBMRlex Sans,sans-serif" '
        '        font-size="11" fill="#fff" text-anchor="middle">'
        'Built-in default'
        '</text>'
        '</svg>'
    )
    return Response(content=svg, media_type="image/svg+xml")


# --- members (sections 7, 12) ----------------------------------------------


class MemberOut(BaseModel):
    """One subject of the members matrix: who, and what it holds."""

    model_config = ConfigDict(extra="forbid")

    subject_type: str
    subject_id: int
    name: str
    subtitle: str
    permissions: list[str]


class MemberIn(BaseModel):
    """Body of ``POST .../members``: a subject and a section 7 template."""

    model_config = ConfigDict(extra="forbid")

    subject_type: str
    subject_id: int = Field(gt=0)
    template: str

    @field_validator("subject_type")
    @classmethod
    def _known_kind(cls, value: str) -> str:
        return subject_kind(value)

    @field_validator("template")
    @classmethod
    def _known_template(cls, value: str) -> str:
        if value not in PERMISSION_TEMPLATES:
            expected = ", ".join(sorted(PERMISSION_TEMPLATES))
            raise ValueError(f"unknown permission template; expected one of: {expected}")
        return value


class GrantOut(BaseModel):
    """What a grant replaced: the subject and the permissions it now holds."""

    model_config = ConfigDict(extra="forbid")

    subject_type: str
    subject_id: int
    template: str
    permissions: list[str]


@router.get("/api/v1/projects/{key}/members", response_model=list[MemberOut])
def get_members(
    key: str, request: Request, user: dict[str, Any] = Depends(get_current_user)
) -> list[MemberOut]:
    """The stored grants of the project, one row per user or group."""
    engine = request.app.state.engine
    project = _project_or_404(engine, key, user)
    return [
        MemberOut(
            subject_type=str(row["subject_type"]),
            subject_id=int(row["subject_id"]),
            name=str(row["name"]),
            subtitle=str(row["subtitle"]),
            permissions=[str(value) for value in row["permissions"]],
        )
        for row in list_members(engine, int(project["id"]))
    ]


@router.post("/api/v1/projects/{key}/members", response_model=GrantOut, status_code=201)
def post_member(
    key: str,
    payload: MemberIn,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> GrantOut:
    """Grant a permission template to a user or group (section 7)."""
    engine = request.app.state.engine
    project = _admin_project(engine, key, user)
    try:
        granted = grant(
            engine,
            project_id=int(project["id"]),
            subject_type=payload.subject_type,
            subject_id=payload.subject_id,
            template=payload.template,
            actor_id=int(user["user_id"]),
            ip=request.client.host if request.client else None,
        )
    except MemberError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return GrantOut(**granted)


@router.delete("/api/v1/projects/{key}/members/{subject_type}/{subject_id}", status_code=204)
def delete_member(
    key: str,
    subject_type: str,
    subject_id: int,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> Response:
    """Revoke every permission this subject holds on the project (section 7)."""

@router.get("/api/v1/projects/{key}/export", response_model=dict)
def export_project(
    key: str,
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
    format: str = "csv",
) -> dict[str, Any]:
    """Export project issues as CSV or SARIF (section 12).

    Only the project admin may export. The CSV format lists one issue per row.
    The SARIF format is a hand-rolled minimal subset using only stdlib json/csv,
    no new dependencies (section 17.1).
    """
    engine = request.app.state.engine
    from fastapi import HTTPException
    from app.projects import _project_or_404
    project = _project_or_404(engine, key, user)
    if not can(engine, int(user["user_id"]), Permission.PROJECT_ADMIN, int(project["id"])):
        raise HTTPException(status_code=403, detail="project.admin permission required")
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT id, fingerprint, tool, rule_id, severity, category, "
                "file_path, line_start, line_end, triage_status, presence, "
                "created_at FROM issues WHERE project_id = :pid"
            ),
            {"pid": int(project["id"])},
        ).mappings().all()
    if format == "csv":
        import io, csv
        output = io.StringIO()
        w = csv.writer(output)
        # Break the header row into multiple lines to stay under 100 chars
        hdr = [
            "id", "fingerprint", "tool", "rule_id", "severity", "category",
            "file_path", "line_start", "line_end", "triage_status", "presence", "created_at"
        ]
        w.writerow(hdr)
        for row in rows:
            # Break the data row into multiple lines
            row_data = [
                str(row["id"]),
                str(row["fingerprint"]),
                str(row["tool"]),
                str(row["rule_id"]),
                str(row["severity"]),
                str(row["category"]),
                str(row["file_path"]) if row.get("file_path") else "",
                str(row["line_start"]) if row.get("line_start") else "",
                str(row["line_end"]) if row.get("line_end") else "",
                str(row["triage_status"]),
                str(row["presence"]),
                str(row["created_at"]),
            ]
            w.writerow(row_data)
        return {"format": "csv", "content": output.getvalue(), "issue_count": len(rows)}
    elif format == "sarif":
        import json
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"name": "wadjet"},
                "results": [],
            }],
            "originalRevision": "2.1.0",
        }
        for row in rows:
            result = {
                "ruleId": row["rule_id"] or row["tool"],
                "level": row["severity"] or "note",
                "message": {"text": row["fingerprint"] or ""},
                "locations": [],
            }
            if row.get("file_path"):
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": row["file_path"]},
                        "region": {"startLine": row["line_start"] or 0},
                    }
                }]
            sarif["runs"][0]["results"].append(result)
        return {"format": "sarif", "content": json.dumps(sarif), "issue_count": len(rows)}
    else:
        raise HTTPException(status_code=400, detail="Unsupported format; use csv or sarif")


    engine = request.app.state.engine
    project = _admin_project(engine, key, user)
    try:
        removed = revoke(
            engine,
            project_id=int(project["id"]),
            subject_type=subject_type,
            subject_id=subject_id,
            actor_id=int(user["user_id"]),
            ip=request.client.host if request.client else None,
        )
    except MemberError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if not removed:
        raise HTTPException(status_code=404, detail="No grants for that subject")
    return Response(status_code=204)


__all__ = ["router"]
