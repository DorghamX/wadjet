"""Issue list (section 12: ``GET /api/v1/projects/{key}/issues``).

Session-authenticated and filtered with the same code the issues page uses
(``app.issues``): status, severity, category, tool, file, assignee, presence
and free text, then sort and pagination. Visibility follows ``visible_project``
- an unknown key and a project you may not browse both answer 404, so the
endpoint never confirms that somebody else's project exists.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from app.deps import get_current_user
from app.issue_requests import create_request, load_request, resolve_request
from app.issues import (
    BadIssueAction,
    BadIssueFilter,
    IssueFilters,
    IssuePermissionDenied,
    add_comment,
    assign_issue,
    list_comments,
    load_issue_by_id,
    query_issues,
    set_triage,
)
from app.projects import visible_project

router = APIRouter()


class AssigneeOut(BaseModel):
    """Who owns the issue; ``null`` for unassigned."""

    model_config = ConfigDict(extra="forbid")

    id: int
    username: str
    display_name: str | None = None


class IssueOut(BaseModel):
    """One issue as a list shows it: identity, place and state (section 12)."""

    model_config = ConfigDict(extra="forbid")

    id: int
    title: str
    tool: str
    rule_id: str
    severity: str
    category: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    triage_status: str
    presence: str
    package: str | None = None
    vuln_id: str | None = None
    assignee: AssigneeOut | None = None
    first_seen_analysis_id: int | None = None
    last_seen_analysis_id: int | None = None


class IssueListOut(BaseModel):
    """A page of issues and the size of the set the filters match."""

    model_config = ConfigDict(extra="forbid")

    total: int
    page: int
    per_page: int
    issues: list[IssueOut]


def _issue_out(row: Mapping[str, Any]) -> IssueOut:
    assignee: AssigneeOut | None = None
    if row["assignee_id"] is not None:
        assignee = AssigneeOut(
            id=int(row["assignee_id"]),
            username=str(row["assignee_username"]),
            display_name=row["assignee_name"],
        )
    return IssueOut(
        id=int(row["id"]),
        title=str(row["title"]),
        tool=str(row["tool"]),
        rule_id=str(row["rule_id"]),
        severity=str(row["severity"]),
        category=str(row["category"]),
        file_path=row["file_path"],
        line_start=row["line_start"],
        line_end=row["line_end"],
        triage_status=str(row["triage_status"]),
        presence=str(row["presence"]),
        package=row["package"],
        vuln_id=row["vuln_id"],
        assignee=assignee,
        first_seen_analysis_id=row["first_seen_analysis_id"],
        last_seen_analysis_id=row["last_seen_analysis_id"],
    )


@router.get("/api/v1/projects/{key}/issues", response_model=IssueListOut)
def list_issues(
    request: Request, key: str, user: dict[str, Any] = Depends(get_current_user)
) -> IssueListOut:
    """Filter, sort and page one project's issues (section 12).

    Unknown filter values are refused with 422 rather than quietly dropped:
    a client that asked for ``status=bogus`` must be told, not shown every
    issue. Pagination beyond the last page returns an empty list, not an
    error - ``total`` is how a client knows where the end is.
    """
    engine = request.app.state.engine
    project = visible_project(engine, key=key, user_id=int(user["user_id"]))
    if project is None:
        raise HTTPException(status_code=404, detail="No such project")
    try:
        filters = IssueFilters.from_query(request.query_params.multi_items())
    except BadIssueFilter as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    rows, total = query_issues(engine, project_id=int(project["id"]), filters=filters)
    return IssueListOut(
        total=total,
        page=filters.page,
        per_page=filters.per_page,
        issues=[_issue_out(row) for row in rows],
    )


class TriageIn(BaseModel):
    """``PATCH /api/v1/issues/{id}``: the status to set and why (section 8)."""

    model_config = ConfigDict(extra="forbid")

    triage_status: str
    reason: str | None = None


class AssignIn(BaseModel):
    """``POST .../assign``: who owns it now; ``null`` unassigns (explicitly)."""

    model_config = ConfigDict(extra="forbid")

    assignee_id: int | None


class CommentIn(BaseModel):
    """``POST .../comments``: the comment body, markdown subset (section 8)."""

    model_config = ConfigDict(extra="forbid")

    body: str


class CommentOut(BaseModel):
    """One comment as the API returns it (deleted ones never appear)."""

    model_config = ConfigDict(extra="forbid")

    id: int
    author: AssigneeOut
    body_md: str
    created_at: datetime
    edited_at: datetime | None = None


class IssueDetailOut(IssueOut):
    """One issue in full: what it is, what was done about it (section 12)."""

    triage_reason: str | None = None
    triaged_by: AssigneeOut | None = None
    triaged_at: datetime | None = None
    description: str | None = None
    impact: str | None = None
    fix: str | None = None
    snippet: str | None = None
    cwe: str | None = None
    installed_version: str | None = None
    fixed_versions: list[str] | None = None
    references: list[str] | None = None


class RequestIn(BaseModel):
    """``POST .../requests``: ask for an action (section 8, section 4 vocab)."""

    model_config = ConfigDict(extra="forbid")

    action: str
    target_user_id: int
    message: str


class ResolveIn(BaseModel):
    """``POST /api/v1/requests/{id}/resolve``: how it ends (section 8)."""

    model_config = ConfigDict(extra="forbid")

    resolution: str
    note: str | None = None


class RequestOut(BaseModel):
    """One request as the API returns it (section 12)."""

    model_config = ConfigDict(extra="forbid")

    id: int
    issue_id: int
    action: str
    message: str | None = None
    state: str
    requested_by: AssigneeOut
    target: AssigneeOut | None = None
    resolved_by: AssigneeOut | None = None
    resolved_note: str | None = None
    resolved_at: datetime | None = None


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _issue_by_id(request: Request, issue_id: int, user: dict[str, Any]) -> dict[str, Any]:
    """The issue, but only if its project may be browsed by this user.

    "No such issue" answers for all three states - unknown id, other
    project's issue, project without a grant - so the endpoint never
    confirms that an id belongs to somebody else's project (section 7).
    """
    engine = request.app.state.engine
    issue = load_issue_by_id(engine, issue_id=issue_id)
    if issue is None:
        raise HTTPException(status_code=404, detail="No such issue")
    project = visible_project(engine, key=str(issue["project_key"]), user_id=int(user["user_id"]))
    if project is None:
        raise HTTPException(status_code=404, detail="No such issue")
    return issue


def _reload(engine: Any, issue_id: int) -> dict[str, Any]:
    row = load_issue_by_id(engine, issue_id=issue_id)
    if row is None:  # pragma: no cover - the row was just written
        raise HTTPException(status_code=404, detail="No such issue")
    return row


def _detail_out(row: Mapping[str, Any]) -> IssueDetailOut:
    triaged_by: AssigneeOut | None = None
    if row["triaged_by"] is not None:
        triaged_by = AssigneeOut(
            id=int(row["triaged_by"]),
            username=str(row["triager_username"]),
            display_name=row["triager_name"],
        )
    return IssueDetailOut(
        **_issue_out(row).model_dump(),
        triage_reason=row["triage_reason"],
        triaged_by=triaged_by,
        triaged_at=row["triaged_at"],
        description=row["description"],
        impact=row["impact"],
        fix=row["fix"],
        snippet=row["snippet"],
        cwe=row["cwe"],
        installed_version=row["installed_version"],
        fixed_versions=row["fixed_versions"],
        references=row["references"],
    )


def _comment_out(row: Mapping[str, Any]) -> CommentOut:
    return CommentOut(
        id=int(row["id"]),
        author=AssigneeOut(
            id=int(row["author_id"]),
            username=str(row["author_username"]),
            display_name=row["author_name"],
        ),
        body_md=str(row["body_md"]),
        created_at=row["created_at"],
        edited_at=row["edited_at"],
    )


def _request_by_id(request: Request, request_id: int, user: dict[str, Any]) -> dict[str, Any]:
    """The request, but only if its project may be browsed by this user.

    "No such request" answers for both states - unknown id and somebody
    else's project - the same rule the issue endpoints follow (section 7).
    """
    engine = request.app.state.engine
    row = load_request(engine, request_id=request_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such request")
    project = visible_project(engine, key=str(row["project_key"]), user_id=int(user["user_id"]))
    if project is None:
        raise HTTPException(status_code=404, detail="No such request")
    return row


def _request_out(row: Mapping[str, Any]) -> RequestOut:
    target: AssigneeOut | None = None
    if row["target_user_id"] is not None:
        target = AssigneeOut(
            id=int(row["target_user_id"]),
            username=str(row["target_username"]),
            display_name=row["target_name"],
        )
    resolved_by: AssigneeOut | None = None
    if row["resolved_by"] is not None:
        resolved_by = AssigneeOut(
            id=int(row["resolved_by"]),
            username=str(row["resolver_username"]),
            display_name=row["resolver_name"],
        )
    return RequestOut(
        id=int(row["id"]),
        issue_id=int(row["issue_id"]),
        action=str(row["requested_action"]),
        message=row["message"],
        state=str(row["state"]),
        requested_by=AssigneeOut(
            id=int(row["requested_by"]),
            username=str(row["requester_username"]),
            display_name=row["requester_name"],
        ),
        target=target,
        resolved_by=resolved_by,
        resolved_note=row["resolved_note"],
        resolved_at=row["resolved_at"],
    )


def _guarded(action: Callable[[], Any]) -> Any:
    """Run a service call, translating its errors to section-12 answers."""
    try:
        return action()
    except IssuePermissionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except BadIssueAction as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/v1/issues/{issue_id}", response_model=IssueDetailOut)
def get_issue(
    request: Request, issue_id: int, user: dict[str, Any] = Depends(get_current_user)
) -> IssueDetailOut:
    """One issue in full: snippet, explanation, triage state (section 12)."""
    return _detail_out(_issue_by_id(request, issue_id, user))


@router.patch("/api/v1/issues/{issue_id}", response_model=IssueDetailOut)
def triage_issue(
    request: Request,
    issue_id: int,
    body: TriageIn,
    user: dict[str, Any] = Depends(get_current_user),
) -> IssueDetailOut:
    """Set the triage status with a reason where section 8 demands one.

    403 when the user lacks that status's ``flag.*`` permission, 422 when
    the status is unknown or the reason is missing or too short - the same
    rules the page's buttons follow, because both call one service.
    """
    engine = request.app.state.engine
    issue = _issue_by_id(request, issue_id, user)
    _guarded(
        lambda: set_triage(
            engine,
            issue=issue,
            status=body.triage_status,
            reason=body.reason,
            actor_id=int(user["user_id"]),
            ip=_ip(request),
        )
    )
    return _detail_out(_reload(engine, issue_id))


@router.post("/api/v1/issues/{issue_id}/assign", response_model=IssueDetailOut)
def assign(
    request: Request,
    issue_id: int,
    body: AssignIn,
    user: dict[str, Any] = Depends(get_current_user),
) -> IssueDetailOut:
    """Assign to a project member, or unassign with a null id (section 8)."""
    engine = request.app.state.engine
    issue = _issue_by_id(request, issue_id, user)
    _guarded(
        lambda: assign_issue(
            engine,
            issue=issue,
            assignee_id=body.assignee_id,
            actor_id=int(user["user_id"]),
        )
    )
    return _detail_out(_reload(engine, issue_id))


@router.get("/api/v1/issues/{issue_id}/comments", response_model=list[CommentOut])
def list_issue_comments(
    request: Request, issue_id: int, user: dict[str, Any] = Depends(get_current_user)
) -> list[CommentOut]:
    """Every live comment, oldest first (section 12)."""
    engine = request.app.state.engine
    _issue_by_id(request, issue_id, user)
    return [_comment_out(row) for row in list_comments(engine, issue_id=issue_id)]


@router.post("/api/v1/issues/{issue_id}/comments", response_model=CommentOut, status_code=201)
def create_issue_comment(
    request: Request,
    issue_id: int,
    body: CommentIn,
    user: dict[str, Any] = Depends(get_current_user),
) -> CommentOut:
    """Post a comment; 403 without ``issue.comment``, 422 when empty (8, 12)."""
    engine = request.app.state.engine
    issue = _issue_by_id(request, issue_id, user)
    comment_id = _guarded(
        lambda: add_comment(engine, issue=issue, author_id=int(user["user_id"]), body=body.body)
    )
    rows = list_comments(engine, issue_id=issue_id, comment_id=int(comment_id))
    if not rows:  # pragma: no cover - the row was just written
        raise HTTPException(status_code=404, detail="No such comment")
    return _comment_out(rows[0])


@router.post("/api/v1/issues/{issue_id}/requests", response_model=RequestOut, status_code=201)
def create_issue_request(
    request: Request,
    issue_id: int,
    body: RequestIn,
    user: dict[str, Any] = Depends(get_current_user),
) -> RequestOut:
    """Ask for an action (section 8): 403 without ``issue.request``, 422 for
    a message too short, a target who cannot give it, or an action the
    asker could take themselves - the page's panel rules, one service."""
    engine = request.app.state.engine
    issue = _issue_by_id(request, issue_id, user)
    request_id = _guarded(
        lambda: create_request(
            engine,
            issue=issue,
            requested_action=body.action,
            target_user_id=body.target_user_id,
            message=body.message,
            actor_id=int(user["user_id"]),
        )
    )
    created = load_request(engine, request_id=int(request_id))
    if created is None:  # pragma: no cover - the row was just written
        raise HTTPException(status_code=404, detail="No such request")
    return _request_out(created)


@router.post("/api/v1/requests/{request_id}/resolve", response_model=RequestOut)
def resolve_request_endpoint(
    request: Request,
    request_id: int,
    body: ResolveIn,
    user: dict[str, Any] = Depends(get_current_user),
) -> RequestOut:
    """Approve, decline or cancel (section 8): only the target decides, only
    the requester cancels, only while it is pending; approval of a flag
    action applies the flag as the target, quoting the message as reason."""
    engine = request.app.state.engine
    row = _request_by_id(request, request_id, user)
    updated = _guarded(
        lambda: resolve_request(
            engine,
            request=row,
            resolution=body.resolution,
            note=body.note,
            actor_id=int(user["user_id"]),
            ip=_ip(request),
        )
    )
    return _request_out(updated)


__all__ = ["router"]
