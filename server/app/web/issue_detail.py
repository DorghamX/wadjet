"""The issue detail page (section 14): one issue, its story, its controls.

Two panes from the design: the left column says what the finding is (code,
explanation, fix) and what happened (activity, comments); the right rail
holds the controls - status, assignee, and, for someone who cannot change
the status, the request panel that replaces the buttons and says why.

Every action posts back to the route that owns it. With htmx the answer is
``issue_detail_body.html`` swapped into ``#issue-detail``; without it the
browser gets a whole page - success by redirect (POST/Redirect/GET),
failure with the error shown - so the page works with JavaScript off and
from the keyboard alike.

The copy and the permission words live here, next to the templates; the
rules they enforce (reason lengths, who may flag what) live in
``app.issues`` and are shared with the JSON API.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.fingerprint import CONTEXT_LINES
from app.issues import (
    BadIssueAction,
    IssuePermissionDenied,
    add_comment,
    allowed_status_actions,
    assign_issue,
    delete_comment,
    edit_comment,
    issue_timeline,
    load_comment,
    load_issue,
    permission_holders,
    project_members,
    render_comment,
    set_triage,
)
from app.permissions import Permission, can
from app.projects import visible_project
from app.web.issues import ACTION_ORDER, BUTTON_LABELS, SEVERITY_EDGES, STATUS_CHIPS
from app.web.projects import SCANNER_LABELS
from app.web.routes import PageUser, render, require_page_user, timeago

router = APIRouter(include_in_schema=False)

#: Timeline phrases: status -> how the design says it out loud.
_STATUS_PHRASES = {
    "open": "open",
    "confirmed": "confirmed",
    "false_positive": "a false positive",
    "accepted_risk": "an accepted risk",
    "wont_fix": "won't fix",
}

#: What a request reads as in the timeline; seeded rows use the older
#: ``flag_*`` spelling, section 4 the bare one - both must render.
_REQUEST_PHRASES = {
    "confirm": "confirm this",
    "false_positive": "mark this as a false positive",
    "accepted_risk": "accept this risk",
    "wont_fix": "mark this as won't fix",
    "flag_false_positive": "mark this as a false positive",
    "flag_accepted_risk": "accept this risk",
    "flag_wont_fix": "mark this as won't fix",
    "fix_help": "help fix this",
    "other": "help with this",
}

#: The request states as chips (word + color, like every status).
_REQUEST_CHIPS = {
    "pending": ("wn", "Pending"),
    "approved": ("ok", "Approved"),
    "declined": ("bad", "Declined"),
    "cancelled": ("nt", "Cancelled"),
}

#: What each permission reads as next to a request target (design copy).
_CAPABILITY_PHRASES = {
    Permission.FLAG_CONFIRM: "confirm issues",
    Permission.FLAG_FALSE_POSITIVE: "flag false positives",
    Permission.FLAG_ACCEPTED_RISK: "accept risks",
    Permission.FLAG_WONT_FIX: "mark won't fix",
    Permission.ISSUE_ASSIGN: "assign issues",
}

#: The panel's actions minus what the user can already do themselves.
#: First field is the *status* - the same word the triage buttons submit -
#: so "missing" lines up against what allowed_status_actions returns.
_REQUESTABLE = (
    ("confirmed", "Mark confirmed", Permission.FLAG_CONFIRM),
    ("false_positive", "Mark as false positive", Permission.FLAG_FALSE_POSITIVE),
    ("accepted_risk", "Accept risk", Permission.FLAG_ACCEPTED_RISK),
    ("wont_fix", "Won't fix", Permission.FLAG_WONT_FIX),
)


def _phrase(status: str | None) -> str:
    return _STATUS_PHRASES.get(str(status), str(status or "").replace("_", " "))


def _who(display_name: Any, username: Any) -> str:
    return str(display_name or username or "Someone")


def _event_line(item: dict[str, Any]) -> str:
    """One timeline event as a sentence (design copy, section 8)."""
    payload = item.get("payload") or {}
    actor = _who(item.get("actor_name"), item.get("actor_username"))
    kind = str(item["type"])
    analysis = payload.get("analysis")
    if kind == "created":
        return f"Found in analysis #{analysis}"
    if kind == "resolved_by_scan":
        return f"No longer present after analysis #{analysis}"
    if kind == "reopened_by_scan":
        return f"Found again in analysis #{analysis}"
    if kind == "flag_carried_over":
        return f"Carried over as {_phrase(payload.get('status'))} in analysis #{analysis}"
    if kind == "assigned":
        name = payload.get("assignee")
        return f"{actor} assigned this to {name}" if name else f"{actor} unassigned this"
    if kind in ("status_changed", "triaged"):  # 'triaged' is the seed's spelling
        status = payload.get("status")
        line = (
            f"{actor} reopened this"
            if status == "open"
            else f"{actor} marked this as {_phrase(status)}"
        )
        reason = payload.get("reason")
        return f'{line}: "{reason}"' if reason else line
    return f"{actor} {kind.replace('_', ' ')}"


def _activity_view(
    item: dict[str, Any],
    *,
    user: PageUser,
    is_project_admin: bool,
) -> dict[str, Any]:
    """Shape one feed entry for the template: text, chip, and the edit rights."""
    kind = str(item["kind"])
    view: dict[str, Any] = {"kind": kind, "when": timeago(item["created_at"])}
    if kind == "comment":
        view.update(
            id=int(item["id"]),
            author=_who(item["author_name"], item["author_username"]),
            html=render_comment(str(item["body_md"])),
            body=str(item["body_md"]),
            edited=item["edited_at"] is not None,
            can_edit=int(item["author_id"]) == user.id,
            can_delete=int(item["author_id"]) == user.id or is_project_admin,
        )
        return view
    if kind == "request":
        chip, word = _REQUEST_CHIPS.get(str(item["state"]), ("nt", str(item["state"]).title()))
        requester = _who(item["requester_name"], item["requester_username"])
        target = _who(item["target_name"], item["target_username"])
        action = str(item["requested_action"])
        phrase = _REQUEST_PHRASES.get(action, f"act on this ({action})")
        view.update(
            text=f'{requester} asked {target} to {phrase}: "{item["message"]}"',
            chip=chip,
            word=word,
        )
        return view
    view["text"] = _event_line(item)
    return view


def _snippet_view(issue: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The stored snippet with line numbers and the flagged rows marked.

    The agent stores up to ``CONTEXT_LINES`` lines above and below the
    finding (``app.fingerprint``), so the numbering is derivable - a snippet
    that does not follow the convention (a trimmed dependency advisory) is
    shown as one flagged block without numbers.
    """
    snippet = issue["snippet"]
    if not snippet:
        return None
    lines = str(snippet).splitlines()
    line_start, line_end = issue["line_start"], issue["line_end"]
    if line_start is None or line_end is None:
        return [{"number": None, "text": line, "flagged": True} for line in lines]
    flagged = max(1, int(line_end) - int(line_start) + 1)
    above = min(CONTEXT_LINES, max(0, int(line_start) - 1))
    above = min(above, max(0, len(lines) - 1))
    first = int(line_start) - above
    return [
        {"number": first + index, "text": line, "flagged": above <= index < above + flagged}
        for index, line in enumerate(lines)
    ]


def _meta_line(issue: dict[str, Any]) -> str:
    """``app/billing/export.py, line 42. First seen in analysis #119.``"""
    parts: list[str] = []
    if issue["file_path"]:
        place = str(issue["file_path"])
        if issue["line_start"] is not None:
            place += f", line {issue['line_start']}"
        parts.append(place)
    elif issue["package"]:
        package = str(issue["package"])
        if issue["installed_version"]:
            package += f" {issue['installed_version']}"
        parts.append(package)
    if issue["first_seen_analysis_id"] is not None:
        parts.append(f"First seen in analysis #{issue['first_seen_analysis_id']}")
    return ". ".join(parts) + ("." if parts else "")


def _rule_label(issue: dict[str, Any]) -> str:
    tool = str(issue["tool"])
    label = SCANNER_LABELS.get(tool, tool.replace("_", "-"))
    rule_id = str(issue["rule_id"] or "")
    return f"{label} {rule_id}".strip() if rule_id else label


def _request_panel_view(
    engine: Any, *, project_id: int, allowed: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The actions this user may not take, and who may take them for them."""
    missing = [entry for entry in _REQUESTABLE if entry[0] not in allowed]
    targets: dict[int, dict[str, Any]] = {}
    for _, _, permission in missing:
        for holder in permission_holders(engine, project_id=project_id, permission=permission):
            entry = targets.setdefault(
                int(holder["id"]),
                {
                    "id": int(holder["id"]),
                    "name": _who(holder["display_name"], holder["username"]),
                    "caps": [],
                },
            )
            phrase = _CAPABILITY_PHRASES[permission]
            if phrase not in entry["caps"]:
                entry["caps"].append(phrase)
    actions = [{"value": value, "label": label} for value, label, _ in missing]
    for target in targets.values():
        target["capability"] = ", ".join(target["caps"])
    return actions, list(targets.values())


def _detail_context(
    request: Request,
    user: PageUser,
    project: Any,
    issue: dict[str, Any],
    *,
    error: str | None = None,
) -> dict[str, Any]:
    """Everything both templates of the detail page read."""
    engine = request.app.state.engine
    project_id = int(project["id"])
    allowed = allowed_status_actions(engine, user_id=user.id, project_id=project_id)
    can_assign = can(engine, user.id, Permission.ISSUE_ASSIGN, project_id=project_id)
    can_comment = can(engine, user.id, Permission.ISSUE_COMMENT, project_id=project_id)
    can_request = can(engine, user.id, Permission.ISSUE_REQUEST, project_id=project_id)
    is_project_admin = can(engine, user.id, Permission.PROJECT_ADMIN, project_id=project_id)

    current = str(issue["triage_status"])
    edge, severity_word = SEVERITY_EDGES.get(
        str(issue["severity"]), ("", str(issue["severity"]).title())
    )
    chip, status_word = STATUS_CHIPS.get(current, ("nt", current.replace("_", " ").title()))
    assignee = issue["assignee_name"] or issue["assignee_username"]

    members = project_members(engine, project_id=project_id) if can_assign else []
    request_actions: list[dict[str, Any]] = []
    request_targets: list[dict[str, Any]] = []
    if can_request and any(action[0] not in allowed for action in _REQUESTABLE):
        request_actions, request_targets = _request_panel_view(
            engine, project_id=project_id, allowed=allowed
        )

    activity = [
        _activity_view(item, user=user, is_project_admin=is_project_admin)
        for item in issue_timeline(engine, issue_id=int(issue["id"]))
    ]

    triager = issue["triager_name"] or issue["triager_username"]
    return {
        "user": user,
        "nav": "projects",
        "project": {"key": project["key"], "name": project["name"]},
        "issue": {
            "id": int(issue["id"]),
            "title": str(issue["title"]),
            "rule": _rule_label(issue),
            "severity_class": f"sv {edge}".strip(),
            "severity_word": severity_word,
            "chip": chip,
            "status_word": status_word,
            "meta": _meta_line(issue),
            "description": issue["description"],
            "impact": issue["impact"],
            "fix": issue["fix"],
            "triage_reason": issue["triage_reason"],
            "triager": triager,
            "triaged_at": issue["triaged_at"],
            "assignee": str(assignee) if assignee else None,
            "resolved": issue["presence"] == "resolved",
        },
        "snippet": _snippet_view(issue),
        "activity": activity,
        "status_buttons": [
            {"status": status, "label": BUTTON_LABELS[status], "enabled": status in allowed}
            for status in ACTION_ORDER
            if status != current
        ],
        "can_flag": bool(allowed),
        "can_assign": can_assign,
        "can_comment": can_comment,
        "members": [
            {
                "id": int(member["id"]),
                "name": _who(member["display_name"], member["username"]),
                "selected": issue["assignee_id"] is not None
                and int(member["id"]) == int(issue["assignee_id"]),
            }
            for member in members
        ],
        "request_actions": request_actions,
        "request_targets": request_targets,
        "show_request": bool(request_actions and request_targets),
        "error": error,
    }


def _load(
    request: Request, user: PageUser, key: str, issue_id: int
) -> tuple[Any, dict[str, Any] | None]:
    """Project (via the one visibility rule) and issue, or (None, None)."""
    engine = request.app.state.engine
    project = visible_project(engine, key=key, user_id=user.id)
    if project is None:
        return None, None
    return project, load_issue(engine, project_id=int(project["id"]), issue_id=issue_id)


def _project_not_found(request: Request, user: PageUser, key: str) -> HTMLResponse:
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "projects",
            "title": "Project not found",
            "message": f"No project with the key {key!r}, or you do not have permission to see it.",
        },
        status_code=404,
    )


def _issue_not_found(request: Request, user: PageUser, key: str, issue_id: int) -> HTMLResponse:
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "projects",
            "title": "Issue not found",
            "message": f"No issue #{issue_id} in project {key!r}.",
        },
        status_code=404,
    )


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _answer(
    request: Request,
    user: PageUser,
    project: Any,
    issue_id: int,
    *,
    error: str | None,
) -> Response:
    """One funnel for every action: partial with htmx, PRG without, 400 on error."""
    engine = request.app.state.engine
    issue = load_issue(engine, project_id=int(project["id"]), issue_id=issue_id)
    if issue is None:  # pragma: no cover - the row exists; it was just acted on
        return _issue_not_found(request, user, str(project["key"]), issue_id)
    context = _detail_context(request, user, project, issue, error=error)
    if error is None and request.headers.get("hx-request") != "true":
        return RedirectResponse(
            url=f"/projects/{project['key']}/issues/{issue_id}", status_code=303
        )
    if request.headers.get("hx-request") == "true":
        return render(
            request, "issue_detail_body.html", context=context, status_code=400 if error else 200
        )
    return render(request, "issue_detail.html", context=context, status_code=400 if error else 200)


@router.get("/projects/{key}/issues/{issue_id}")
def issue_detail_page(
    request: Request, key: str, issue_id: int, user: PageUser = Depends(require_page_user)
) -> Response:
    """The whole page: what it is, what happened, what you may do about it."""
    project, issue = _load(request, user, key, issue_id)
    if project is None:
        return _project_not_found(request, user, key)
    if issue is None:
        return _issue_not_found(request, user, key, issue_id)
    return render(
        request,
        "issue_detail.html",
        context=_detail_context(request, user, project, issue),
    )


@router.post("/projects/{key}/issues/{issue_id}/triage")
async def triage_action(
    request: Request, key: str, issue_id: int, user: PageUser = Depends(require_page_user)
) -> Response:
    """Flag or reopen. The button's ``status`` decides, the reason rules judge."""
    project, issue = _load(request, user, key, issue_id)
    if project is None:
        return _project_not_found(request, user, key)
    if issue is None:
        return _issue_not_found(request, user, key, issue_id)
    form = await request.form()
    error: str | None = None
    try:
        set_triage(
            request.app.state.engine,
            issue=issue,
            status=str(form.get("status") or ""),
            reason=str(form.get("reason") or ""),
            actor_id=user.id,
            ip=_ip(request),
        )
    except (IssuePermissionDenied, BadIssueAction) as exc:
        error = str(exc)
    return _answer(request, user, project, issue_id, error=error)


@router.post("/projects/{key}/issues/{issue_id}/assign")
async def assign_action(
    request: Request, key: str, issue_id: int, user: PageUser = Depends(require_page_user)
) -> Response:
    """Assign to a member of this project (or unassign with the empty value)."""
    project, issue = _load(request, user, key, issue_id)
    if project is None:
        return _project_not_found(request, user, key)
    if issue is None:
        return _issue_not_found(request, user, key, issue_id)
    form = await request.form()
    raw = str(form.get("assignee_id") or "")
    assignee_id = int(raw) if raw.isdigit() else None
    error: str | None = None
    try:
        assign_issue(
            request.app.state.engine,
            issue=issue,
            assignee_id=assignee_id,
            actor_id=user.id,
        )
    except (IssuePermissionDenied, BadIssueAction) as exc:
        error = str(exc)
    return _answer(request, user, project, issue_id, error=error)


@router.post("/projects/{key}/issues/{issue_id}/comments")
async def comment_action(
    request: Request, key: str, issue_id: int, user: PageUser = Depends(require_page_user)
) -> Response:
    """Post a comment (section 8: markdown subset, sanitized on render)."""
    project, issue = _load(request, user, key, issue_id)
    if project is None:
        return _project_not_found(request, user, key)
    if issue is None:
        return _issue_not_found(request, user, key, issue_id)
    form = await request.form()
    error: str | None = None
    try:
        add_comment(
            request.app.state.engine,
            issue=issue,
            author_id=user.id,
            body=str(form.get("body") or ""),
        )
    except (IssuePermissionDenied, BadIssueAction) as exc:
        error = str(exc)
    return _answer(request, user, project, issue_id, error=error)


def _comment_scope(
    request: Request, user: PageUser, key: str, issue_id: int, comment_id: int
) -> tuple[Any, dict[str, Any] | None, dict[str, Any] | None]:
    """Project, issue and comment - all three, or the answer is 404."""
    project, issue = _load(request, user, key, issue_id)
    if project is None or issue is None:
        return project, issue, None
    comment = load_comment(request.app.state.engine, comment_id=comment_id)
    if comment is None or int(comment["issue_id"]) != issue_id:
        return project, issue, None
    return project, issue, comment


@router.post("/projects/{key}/issues/{issue_id}/comments/{comment_id}/edit")
async def comment_edit_action(
    request: Request,
    key: str,
    issue_id: int,
    comment_id: int,
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Edit your own comment; the service refuses anyone else's (section 8)."""
    project, issue, comment = _comment_scope(request, user, key, issue_id, comment_id)
    if project is None:
        return _project_not_found(request, user, key)
    if issue is None or comment is None:
        return _issue_not_found(request, user, key, issue_id)
    form = await request.form()
    error: str | None = None
    try:
        edit_comment(
            request.app.state.engine,
            comment=comment,
            actor_id=user.id,
            body=str(form.get("body") or ""),
        )
    except (IssuePermissionDenied, BadIssueAction) as exc:
        error = str(exc)
    return _answer(request, user, project, issue_id, error=error)


@router.post("/projects/{key}/issues/{issue_id}/comments/{comment_id}/delete")
async def comment_delete_action(
    request: Request,
    key: str,
    issue_id: int,
    comment_id: int,
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Delete: the author or an admin (section 8). Soft - the row stays."""
    project, issue, comment = _comment_scope(request, user, key, issue_id, comment_id)
    if project is None:
        return _project_not_found(request, user, key)
    if issue is None or comment is None:
        return _issue_not_found(request, user, key, issue_id)
    error: str | None = None
    try:
        delete_comment(
            request.app.state.engine,
            comment=comment,
            actor_id=user.id,
            project_id=int(project["id"]),
        )
    except (IssuePermissionDenied, BadIssueAction) as exc:
        error = str(exc)
    return _answer(request, user, project, issue_id, error=error)


__all__ = ["BUTTON_LABELS", "router"]
