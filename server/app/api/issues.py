"""Issue list (section 12: ``GET /api/v1/projects/{key}/issues``).

Session-authenticated and filtered with the same code the issues page uses
(``app.issues``): status, severity, category, tool, file, assignee, presence
and free text, then sort and pagination. Visibility follows ``visible_project``
- an unknown key and a project you may not browse both answer 404, so the
endpoint never confirms that somebody else's project exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from app.deps import get_current_user
from app.issues import BadIssueFilter, IssueFilters, query_issues
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


__all__ = ["router"]
