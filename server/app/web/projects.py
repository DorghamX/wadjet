"""Project pages (section 14): the list at ``/`` and the overview below it.

The list answers "what is broken" at a glance: gate status first, then the
severity counts the last gate saw, coverage and the last analysis. The
overview explains one project: failing conditions at the top with their
actual values, the metric cards, the trend over the last analyses and the
scanners that produced the latest one.

Numbers on both pages come from the *latest analysis* snapshot (what the
gate judged), except the flagged count, which is live because triage is not
part of the gate metrics - see ``docs/decisions.md``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import Engine, text

from app.projects import (
    DuplicateProjectKey,
    ProjectKeyError,
    create_project,
    stored_settings,
    validate_key,
    visible_project,
    visible_projects,
)
from app.web.routes import PageUser, render, require_page_user, timeago

router = APIRouter(include_in_schema=False)

#: Human labels for the section 9 metrics (banner and cards).
METRIC_LABELS = {
    "issues_total": "Issues",
    "issues_blocker": "Blocker issues",
    "issues_critical": "Critical issues",
    "issues_high": "High issues",
    "issues_medium": "Medium issues",
    "issues_low": "Low issues",
    "vulnerabilities": "Vulnerabilities",
    "secrets": "Secrets",
    "dependency_vulns": "Vulnerable dependencies",
    "dependency_vulns_with_fix": "Dependencies with a fix",
    "bugs": "Bugs",
    "code_smells": "Code smells",
    "coverage_line_percent": "Line coverage",
    "all_scanners_completed": "All enabled scanners completed",
}

#: How a condition reads after "Fails when" (design copy).
OPERATOR_PHRASES = {
    ">": "Fails when above",
    ">=": "Fails when at least",
    "<": "Fails when below",
    "<=": "Fails when at most",
    "==": "Fails when equal to",
}

#: Adapter keys as the design spells them.
SCANNER_LABELS = {
    "bandit": "Bandit",
    "pip_audit": "pip-audit",
    "ruff": "Ruff",
    "detect_secrets": "detect-secrets",
    "coverage": "Coverage report",
}

#: The ten newest analyses of one project: trend, scanners and history.
ANALYSES_SQL = """
SELECT id, status, gate_status, gate_details, metrics, scanner_runs, created_at
FROM analyses
WHERE project_id = :pid
ORDER BY created_at DESC, id DESC
LIMIT 10
"""


# --- formatting helpers (one place, used by both pages) --------------------


def _number(value: Any) -> str:
    """An integer-looking count without a trailing ``.0``."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "0"
    return str(int(number)) if number == int(number) else f"{number:g}"


def _percent(value: Any) -> str:
    """A measured percentage: ``76.4%``."""
    try:
        return f"{float(value):.1f}%"
    except (TypeError, ValueError):
        return "no report"


def _threshold_percent(value: Any) -> str:
    """A threshold percentage: ``85%`` (design copy, no forced decimals)."""
    try:
        return f"{float(value):g}%"
    except (TypeError, ValueError):
        return str(value)


def _count(metrics: dict[str, Any], name: str) -> str:
    return _number(metrics.get(name, 0))


def _gate_chip(analysis_id: Any, status: Any, gate_status: Any) -> tuple[str, str]:
    """(css class, word) for the gate column: a word as well as a color."""
    if analysis_id is None:
        return "nt", "No analysis"
    if status != "complete":
        return "wn", "Incomplete"
    if gate_status == "failed":
        return "bad", "Failed"
    return "ok", "Passed"


def _condition_sentence(condition: dict[str, Any]) -> str:
    """``Critical issues: 3. Fails when above 0.`` - the design's phrasing."""
    metric = str(condition.get("metric", ""))
    if metric == "all_scanners_completed":
        return "Not every scanner completed - see the scanners below."
    label = METRIC_LABELS.get(metric, metric.replace("_", " "))
    phrase = OPERATOR_PHRASES.get(str(condition.get("operator")), "Fails when")
    threshold = (
        _threshold_percent(condition.get("threshold"))
        if (metric == "coverage_line_percent")
        else _number(condition.get("threshold"))
    )
    if condition.get("reason") == "no coverage report":
        return f"{label}: no coverage report. {phrase} {threshold}."
    actual: Any = condition.get("actual")
    if actual is None:
        actual_text = "no data"
    elif metric == "coverage_line_percent":
        actual_text = _percent(actual)
    else:
        actual_text = _number(actual)
    return f"{label}: {actual_text}. {phrase} {threshold}."


def _scanner_rows(raw: Any, metrics: dict[str, Any], settings: Any) -> list[dict[str, str]]:
    """One row per scanner of the latest analysis, plus the coverage report."""
    runs = raw if isinstance(raw, dict) else {}
    rows: list[dict[str, str]] = []
    for name, run in runs.items():
        detail = run if isinstance(run, dict) else {}
        ok = detail.get("status") == "ok"
        row = {
            "label": SCANNER_LABELS.get(name, str(name).replace("_", " ")),
            "chip": "ok" if ok else "bad",
            "status": "Complete" if ok else "Failed",
        }
        if not ok and detail.get("error"):
            row["detail"] = str(detail["error"])
        rows.append(row)
    if settings.scanners.coverage.enabled:
        found = "coverage_line_percent" in metrics
        rows.append(
            {
                "label": "Coverage report",
                "chip": "ok" if found else "wn",
                "status": "Found" if found else "No report",
            }
        )
    return rows


# --- the projects list -----------------------------------------------------


def _list_rows(engine: Engine, user: PageUser) -> list[dict[str, Any]]:
    """Every project this user may browse, with its latest analysis summary."""
    rows = visible_projects(engine, user_id=user.id, is_admin=user.is_admin)
    projects: list[dict[str, Any]] = []
    for row in rows:
        metrics = row["metrics"] if isinstance(row["metrics"], dict) else {}
        analysis_id = row["analysis_id"]
        chip, label = _gate_chip(analysis_id, row["analysis_status"], row["gate_status"])
        coverage: Any = metrics.get("coverage_line_percent")
        projects.append(
            {
                "key": row["key"],
                "name": row["name"],
                "description": row["description"],
                "gate_chip": chip,
                "gate_label": label,
                "blocker": _count(metrics, "issues_blocker") if analysis_id else "-",
                "critical": _count(metrics, "issues_critical") if analysis_id else "-",
                "high": _count(metrics, "issues_high") if analysis_id else "-",
                "coverage": _percent(coverage)
                if coverage is not None
                else ("No report" if analysis_id else "-"),
                "analysis_id": analysis_id,
                "analysis_at": row["analysis_at"],
            }
        )
    return projects


def _render_list(request: Request, user: PageUser, *, status_code: int = 200) -> HTMLResponse:
    projects = _list_rows(request.app.state.engine, user)
    return render(
        request,
        "projects.html",
        context={"user": user, "nav": "projects", "projects": projects},
        status_code=status_code,
    )


@router.get("/")
def home(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """``/`` is the projects list (section 14)."""
    return _render_list(request, user)


@router.get("/projects")
def projects_page(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """Same list, at the address the top bar links to."""
    return _render_list(request, user)


# --- creating a project ----------------------------------------------------


def _not_allowed(request: Request, user: PageUser) -> HTMLResponse:
    """403 page: the guide defines no project-create permission (admins only)."""
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "projects",
            "title": "Only admins can create projects",
            "message": "Ask an admin to create the project, then add yourself as a member.",
        },
        status_code=403,
    )


@router.get("/projects/new")
def new_project_form(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """The create form (the design's "New project" button)."""
    if not user.is_admin:
        return _not_allowed(request, user)
    return render(
        request,
        "project_new.html",
        context={"user": user, "nav": "projects", "error": None, "form": None},
    )


@router.post("/projects")
def create_project_form(
    request: Request,
    key: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Create from the form, then land on the new project's overview."""
    if not user.is_admin:
        return _not_allowed(request, user)
    form = {"key": key, "name": name, "description": description}
    try:
        resolved_key = validate_key(key)
        create_project(
            request.app.state.engine,
            key=resolved_key,
            name=name,
            description=description or None,
            creator_id=user.id,
            ip=request.client.host if request.client else None,
        )
    except (ProjectKeyError, DuplicateProjectKey) as exc:
        return render(
            request,
            "project_new.html",
            context={"user": user, "nav": "projects", "error": str(exc), "form": form},
            status_code=400,
        )
    return RedirectResponse(url=f"/projects/{resolved_key}", status_code=303)


# --- the project overview --------------------------------------------------


def _banner(latest: Any) -> dict[str, Any] | None:
    """The gate banner: title, reference and the conditions that triggered."""
    if latest is None:
        return None
    failed = latest["gate_status"] == "failed"
    incomplete = latest["status"] != "complete"
    if failed:
        css_class, title = "ban", "Quality gate failed"
    elif incomplete:
        css_class, title = "ban wn", "Analysis incomplete"
    else:
        css_class, title = "ban ok", "Quality gate passed"
    details = latest["gate_details"] if isinstance(latest["gate_details"], dict) else {}
    conditions = details.get("conditions") or []
    sentences = [_condition_sentence(c) for c in conditions if c.get("triggered")]
    if failed and not sentences:
        sentences = ["A condition in the quality gate failed."]
    return {
        "cls": css_class,
        "title": title,
        "reference": f"on analysis #{latest['id']}, {timeago(latest['created_at'])}",
        "sentences": sentences,
    }


def _cards(metrics: dict[str, Any], false_positives: int) -> list[dict[str, str]]:
    """The four design cards; the flagged count is live (triage, not the gate)."""
    coverage = metrics.get("coverage_line_percent")
    return [
        {"value": _count(metrics, "issues_total"), "label": "Open issues"},
        {
            "value": _percent(coverage) if coverage is not None else "No report",
            "label": "Line coverage",
        },
        {"value": _count(metrics, "dependency_vulns"), "label": "Vulnerable dependencies"},
        {"value": str(false_positives), "label": "Flagged false positive"},
    ]


def _trend(analyses: list[Any]) -> dict[str, Any] | None:
    """Open issues over the last 10 analyses, oldest first (bars are heights)."""
    if not analyses:
        return None
    points = [
        (
            analysis["id"],
            int((analysis["metrics"] or {}).get("issues_total", 0) or 0),
        )
        for analysis in analyses
    ]
    points.reverse()
    peak = max(total for _aid, total in points)
    bars = [
        {"height": 2 if total == 0 else max(6, round(total / peak * 90)) if peak else 6}
        for _aid, total in points
    ]
    label = ", ".join(f"analysis #{aid}: {total}" for aid, total in points)
    return {"bars": bars, "label": f"Open issues per analysis: {label}"}


def _history(analyses: list[Any]) -> list[dict[str, Any]]:
    """The five most recent analyses: what ran, and what the gate said."""
    rows = []
    for analysis in analyses[:5]:
        incomplete = analysis["status"] != "complete"
        gate_status = analysis["gate_status"]
        if gate_status == "failed":
            gate_chip, gate_label = "bad", "Failed"
        elif gate_status == "passed":
            gate_chip, gate_label = "ok", "Passed"
        else:
            gate_chip, gate_label = "nt", "Inconclusive"
        rows.append(
            {
                "id": analysis["id"],
                "when": timeago(analysis["created_at"]),
                "status_chip": "wn" if incomplete else "ok",
                "status_label": "Incomplete" if incomplete else "Complete",
                "gate_chip": gate_chip,
                "gate_label": gate_label,
            }
        )
    return rows


@router.get("/projects/{key}")
def project_overview(
    request: Request, key: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """``/projects/{key}``: gate banner, cards, trend, scanners, history."""
    engine = request.app.state.engine
    # Unknown key and "not granted" answer the same way: no existence leak.
    project = visible_project(engine, key=key, user_id=user.id)
    if project is None:
        return render(
            request,
            "error.html",
            context={
                "user": user,
                "nav": "projects",
                "title": "Project not found",
                "message": f"No project with the key {key!r}, or you do not have permission "
                "to see it.",
            },
            status_code=404,
        )

    settings = stored_settings(project["settings"])
    with engine.connect() as conn:
        analyses = conn.execute(text(ANALYSES_SQL), {"pid": project["id"]}).mappings().all()
        false_positives = int(
            conn.execute(
                text(
                    "SELECT count(*) FROM issues "
                    "WHERE project_id = :pid AND triage_status = 'false_positive'"
                ),
                {"pid": project["id"]},
            ).scalar()
            or 0
        )

    latest = analyses[0] if analyses else None
    if latest is None:
        metrics: dict[str, Any] = {}
    else:
        metrics = latest["metrics"] if isinstance(latest["metrics"], dict) else {}
    context: dict[str, Any] = {
        "user": user,
        "nav": "projects",
        "project": {
            "key": project["key"],
            "name": project["name"],
            "description": project["description"],
        },
        "banner": _banner(latest),
        "cards": _cards(metrics, false_positives) if latest else None,
        "trend": _trend(list(analyses)),
        "scanners": (_scanner_rows(latest["scanner_runs"], metrics, settings) if latest else None),
        "history": _history(list(analyses)),
        "has_analyses": latest is not None,
    }
    return render(request, "project_overview.html", context=context)


__all__ = ["router"]
