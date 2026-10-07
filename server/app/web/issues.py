"""The issues list page (section 14: filters on the left, one row per issue).

One route in three dresses: a whole page for a browser, the sidebar plus
table (``HX-Target: issues-body``) when a facet or pagination link is
clicked, and the table alone (``HX-Target: issues-table``) while you type in
the search box - only the region below the input is replaced there, so the
caret never leaves the field.

Every URL is built from ``IssueFilters.params``, so no link can forget a
filter. Facet links deliberately carry *no* text or sort of their own: those
travel with the form (``hx-include``), which is how a search you just typed
survives the next click. A facet link also works without JavaScript - it
simply drops the search, which is the one degradation of the no-JS path.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.issues import (
    PRESENCES,
    SEVERITIES,
    TRIAGE_STATUSES,
    BadIssueFilter,
    IssueFilters,
    facet_counts,
    query_issues,
)
from app.projects import visible_project
from app.web.projects import SCANNER_LABELS
from app.web.routes import PageUser, render, require_page_user

router = APIRouter(include_in_schema=False)

#: (css class, word) per triage status: the design wants a word, not a color.
STATUS_CHIPS = {
    "open": ("nt", "Open"),
    "confirmed": ("ok", "Confirmed"),
    "false_positive": ("wn", "False positive"),
    "accepted_risk": ("wn", "Accepted risk"),
    "wont_fix": ("nt", "Won't fix"),
}

#: The design's colored left edge (``.sv``) plus the word, per severity.
SEVERITY_EDGES = {
    "blocker": ("s1", "Blocker"),
    "critical": ("s2", "Critical"),
    "high": ("s3", "High"),
    "medium": ("s4", "Medium"),
    "low": ("", "Low"),
    "info": ("", "Info"),
}

#: Presence in the design's capitalization.
PRESENCE_WORDS = {"present": "Present", "resolved": "Resolved"}

#: What the sort menu offers (section 12's ``sort``), in the order shown.
SORT_LABELS = {
    "severity": "Severity, worst first",
    "status": "Status, open first",
    "file": "File, A to Z",
    "first_seen": "First seen, newest",
    "last_seen": "Last seen, newest",
    "title": "Title, A to Z",
}

#: Keys "Clear filters" drops. Sort and per_page survive: they are how you
#: look at the list, not what you are looking for.
_CLEAR_KEYS = {
    "status": None,
    "severity": None,
    "category": None,
    "tool": None,
    "file": None,
    "presence": None,
    "assignee": None,
    "text": None,
    "page": None,
}

#: (query key, heading, values in display order, value -> word). The design's
#: sidebar order: Status, Severity, Tool; presence is section 12's filter.
_GROUPS: Sequence[tuple[str, str, Sequence[str], Callable[[str], str]]] = (
    ("status", "Status", TRIAGE_STATUSES, lambda value: STATUS_CHIPS[value][1]),
    ("severity", "Severity", SEVERITIES, lambda value: SEVERITY_EDGES[value][1]),
    (
        "tool",
        "Tool",
        (),
        lambda value: SCANNER_LABELS.get(value, value.replace("_", "-")),
    ),
    ("presence", "Presence", PRESENCES, lambda value: PRESENCE_WORDS[value]),
)


# --- view models (plain dicts: Jinja reads them, nothing else does) --------


def _url(filters: IssueFilters, **changes: str | int | None) -> str:
    """A ready-to-click query string: ``?status=open``, or a bare ``?`` when a
    change cleared every filter - still a valid link back to the whole list.
    """
    return "?" + urlencode(filters.params(**changes))


def _facet_url(filters: IssueFilters, name: str, value: str | None) -> str:
    """A facet link: every other filter kept, page reset.

    Text and sort are deliberately left out. They travel with the form on
    every keystroke, so a link rendered before you typed cannot drag an old
    search back behind your back - and leaving them out is also what keeps
    each parameter appearing exactly once in the request.
    """
    return _url(filters, **{name: value, "text": None, "sort": None, "page": None})


def _facet_groups(filters: IssueFilters, counts: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
    """One block per filter group, each entry a link that toggles itself.

    A value is listed when the project has issues like it *or* when it is the
    active filter: an active facet that matches nothing still has to say so.
    """
    groups: list[dict[str, Any]] = []
    for name, heading, order, word in _GROUPS:
        seen = counts.get(name, {})
        values = order or sorted(seen, key=lambda value: word(value).lower())
        rows: list[dict[str, Any]] = []
        for value in values:
            count = seen.get(value, 0)
            active = getattr(filters, name) == value
            if count == 0 and not active:
                continue
            rows.append(
                {
                    "word": word(value),
                    "count": count,
                    "active": active,
                    "url": _facet_url(filters, name, None if active else value),
                }
            )
        if rows:
            groups.append({"heading": heading, "rows": rows})
    return groups


def _row_view(row: Mapping[str, Any]) -> dict[str, Any]:
    """One table row: severity word + edge, status word + color, location."""
    severity = str(row["severity"])
    status = str(row["triage_status"])
    edge, severity_word = SEVERITY_EDGES.get(severity, ("", severity.title()))
    chip, status_word = STATUS_CHIPS.get(status, ("nt", status.replace("_", " ").title()))
    tool = str(row["tool"])
    label = SCANNER_LABELS.get(tool, tool.replace("_", "-"))
    rule_id = str(row["rule_id"] or "")
    location: str | None = None
    if row["file_path"]:
        location = str(row["file_path"])
        if row["line_start"] is not None:
            location += f":{row['line_start']}"
    assignee = row["assignee_name"] or row["assignee_username"]
    return {
        "id": int(row["id"]),
        "title": str(row["title"]),
        "rule": f"{label} {rule_id}".strip() if rule_id else label,
        "severity_class": f"sv {edge}".strip(),
        "severity_word": severity_word,
        "chip": chip,
        "status_word": status_word,
        "resolved": row["presence"] == "resolved",
        "location": location,
        "assignee": str(assignee) if assignee else None,
    }


def _page_urls(filters: IssueFilters, total: int) -> tuple[str | None, str | None, int]:
    """Previous/next URLs and the page count (empty pages are not an error)."""
    pages = max(1, (total + filters.per_page - 1) // filters.per_page)
    previous = _url(filters, page=filters.page - 1) if filters.page > 1 else None
    following = _url(filters, page=filters.page + 1) if filters.page < pages else None
    return previous, following, pages


def _bad_filter(request: Request, user: PageUser, key: str, message: str) -> HTMLResponse:
    """A filter the server will not guess at (400, naming what was expected)."""
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "projects",
            "title": "Unknown filter",
            "message": f"{message} The list is at /projects/{key}/issues.",
        },
        status_code=400,
    )


# --- the page --------------------------------------------------------------


def _not_found(request: Request, user: PageUser, key: str) -> HTMLResponse:
    """Unknown key and "not granted" share one answer (section 7)."""
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


@router.get("/projects/{key}/issues")
def issues_page(
    request: Request, key: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """Filters on the left, one row per issue (section 14).

    The same request answers three ways: the full page, the sidebar + table
    for a facet click, or the table alone while the search box is typed in -
    told apart by the ``HX-Target`` header htmx sends with each partial.
    """
    engine = request.app.state.engine
    project = visible_project(engine, key=key, user_id=user.id)
    if project is None:
        return _not_found(request, user, key)
    try:
        filters = IssueFilters.from_query(request.query_params.multi_items())
    except BadIssueFilter as exc:
        return _bad_filter(request, user, key, str(exc))

    project_id = int(project["id"])
    rows, total = query_issues(engine, project_id=project_id, filters=filters)
    counts = facet_counts(engine, project_id=project_id)
    previous, following, pages = _page_urls(filters, total)
    filtered = bool(
        filters.status
        or filters.severity
        or filters.category
        or filters.tool
        or filters.file
        or filters.presence
        or filters.assignee
        or filters.text
    )
    context: dict[str, Any] = {
        "user": user,
        "nav": "projects",
        "project": {"key": project["key"], "name": project["name"]},
        "filters": filters,
        "filtered": filtered,
        "clear_url": _url(filters, **_CLEAR_KEYS),
        "total": total,
        "issues": [_row_view(row) for row in rows],
        "facets": _facet_groups(filters, counts),
        "sorts": list(SORT_LABELS.items()),
        "prev_url": previous,
        "next_url": following,
        "page_count": pages,
        "first_page_url": _url(filters, page=None),
    }
    if request.headers.get("hx-request") == "true":
        template = (
            "issues_table.html"
            if request.headers.get("hx-target") == "issues-table"
            else "issues_body.html"
        )
    else:
        template = "issues.html"
    return render(request, template, context=context)


__all__ = ["router"]
