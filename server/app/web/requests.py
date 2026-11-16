"""The detail page's request forms (section 8): ask, decide, cancel.

Two posts, one funnel: both answer through ``issue_detail``'s ``_answer``,
so with htmx the swapped region is the detail body (the timeline picks up
the new or decided request), and without it the browser is redirected back
to the issue - POST/Redirect/GET, error shown in the banner. The panel's
form posts to the first route; the decide/cancel buttons in the timeline
carry their own ``resolution`` and post to the second.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.issue_requests import create_request, load_request, resolve_request
from app.issues import BadIssueAction, IssuePermissionDenied
from app.projects import visible_project
from app.web.issue_detail import (
    _answer,
    _ip,
    _issue_not_found,
    _load,
    _project_not_found,
)
from app.web.routes import PageUser, render, require_page_user

router = APIRouter(include_in_schema=False)


def _request_not_found(request: Request, user: PageUser, request_id: int) -> HTMLResponse:
    """Unknown id and a request outside this user's projects share one 404."""
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "projects",
            "title": "Request not found",
            "message": f"No request #{request_id} in any project you can see.",
        },
        status_code=404,
    )


@router.post("/projects/{key}/issues/{issue_id}/requests")
async def request_action(
    request: Request, key: str, issue_id: int, user: PageUser = Depends(require_page_user)
) -> Response:
    """Ask somebody who holds the permission (section 8, design panel)."""
    project, issue = _load(request, user, key, issue_id)
    if project is None:
        return _project_not_found(request, user, key)
    if issue is None:
        return _issue_not_found(request, user, key, issue_id)
    form = await request.form()
    raw_target = str(form.get("target") or "")
    error: str | None = None
    try:
        create_request(
            request.app.state.engine,
            issue=issue,
            requested_action=str(form.get("action") or ""),
            target_user_id=int(raw_target) if raw_target.isdigit() else None,
            message=str(form.get("message") or ""),
            actor_id=user.id,
        )
    except (IssuePermissionDenied, BadIssueAction) as exc:
        error = str(exc)
    return _answer(request, user, project, issue_id, error=error)


@router.post("/requests/{request_id}/resolve")
async def resolve_action(
    request: Request, request_id: int, user: PageUser = Depends(require_page_user)
) -> Response:
    """Approve, decline or cancel; only the two people concerned may (8)."""
    engine = request.app.state.engine
    row = load_request(engine, request_id=request_id)
    if row is None:
        return _request_not_found(request, user, request_id)
    project = visible_project(engine, key=str(row["project_key"]), user_id=user.id)
    if project is None:
        return _request_not_found(request, user, request_id)
    form = await request.form()
    error: str | None = None
    try:
        resolve_request(
            engine,
            request=row,
            resolution=str(form.get("resolution") or ""),
            note=str(form.get("note") or ""),
            actor_id=user.id,
            ip=_ip(request),
        )
    except (IssuePermissionDenied, BadIssueAction) as exc:
        error = str(exc)
    next_url = str(form.get("next") or "")
    if (
        error is None
        and not request.headers.get("HX-Request")
        and next_url.startswith("/")
        and not next_url.startswith("//")
    ):
        # Posted from a page that is not this issue's - the inbox sends
        # its decisions here with next=/inbox. Same-origin only, so the
        # redirect cannot leave the site; the detail page, which posts
        # without next, keeps landing on the issue itself.
        return RedirectResponse(next_url, status_code=303)
    # The request always belongs to one issue: back to that issue's page.
    return _answer(request, user, project, int(row["issue_id"]), error=error)


__all__ = ["router"]
