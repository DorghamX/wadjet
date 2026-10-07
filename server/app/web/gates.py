"""Quality gates pages (section 9, design "Quality gate").

``/gates`` lists every gate with how many conditions it holds and which
projects use it; ``/gates/{id}`` is the design's window - conditions as
"fail when" rows that anyone with a session may read and a ``gates.admin``
edits in place (metric, operator, threshold, Remove, Add condition, Save).

The writes call the same service functions the JSON API uses
(``app.api.gates.add_gate`` / ``edit_gate`` / ``remove_gate``), so a form
post and a PATCH cannot disagree about what a gate is; reading needs only a
login because the API's list endpoint is session-scoped too.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy import Engine, text

from app.api.gates import (
    ConditionIn,
    add_gate,
    edit_gate,
    load_conditions,
    load_gate,
    remove_gate,
)
from app.gate import ALL_METRICS, OPERATORS
from app.permissions import Permission, can
from app.web.projects import METRIC_LABELS
from app.web.routes import PageUser, render, require_page_user
from app.web.settings import OPERATOR_WORDS

router = APIRouter(include_in_schema=False)

#: What a ``?saved=<code>`` redirect tells the reader (design copy).
NOTICES = {
    "created": "Gate created. Add its conditions and save.",
    "gate": "Gate saved. The next analysis is judged by it.",
    "deleted": "Gate deleted.",
}


def _notice(request: Request) -> str | None:
    """The sentence a redirect carries, or nothing for a plain visit."""
    code = request.query_params.get("saved")
    if code is None:
        return None
    return NOTICES.get(code, "Saved.")


def _can_edit(engine: Engine, user: PageUser) -> bool:
    """``gates.admin`` (section 7): global, so no project id to pass."""
    return can(engine, user.id, Permission.GATES_ADMIN)


def _forbidden(request: Request, user: PageUser) -> HTMLResponse:
    """403: writing gates needs ``gates.admin`` (section 7)."""
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "gates",
            "title": "Gate editing is restricted",
            "message": "Creating, editing and deleting gates needs the gates.admin "
            "permission. Ask an admin to grant it.",
        },
        status_code=403,
    )


def _gate_missing(request: Request, user: PageUser) -> HTMLResponse:
    """404: no gate with that id (gates are readable by every session)."""
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "gates",
            "title": "Gate not found",
            "message": "There is no quality gate with that id. It may have been deleted.",
        },
        status_code=404,
    )


# --- the list --------------------------------------------------------------


def _list_rows(engine: Engine) -> list[dict[str, Any]]:
    """Every gate: identity, flags, and the two counts the table shows."""
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT g.id, g.name, g.is_default, g.is_builtin, "
                    "(SELECT count(*) FROM projects p WHERE p.gate_id = g.id) AS used_by, "
                    "(SELECT count(*) FROM gate_conditions c WHERE c.gate_id = g.id) AS conditions "
                    "FROM quality_gates g ORDER BY g.is_default DESC, g.id"
                )
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


def _list_page(
    request: Request,
    user: PageUser,
    *,
    notice: str | None = None,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    engine = request.app.state.engine
    return render(
        request,
        "gates_list.html",
        context={
            "user": user,
            "nav": "gates",
            "gates": _list_rows(engine),
            "can_edit": _can_edit(engine, user),
            "notice": notice,
            "error": error,
        },
        status_code=status_code,
    )


# --- the detail ------------------------------------------------------------


def _thresholds(metric: str, raw: Any) -> tuple[str, str]:
    """One threshold as (the number to edit with, the words to read)."""
    value = f"{float(raw):g}"
    if metric == "coverage_line_percent":
        return value, f"{value}%"
    return value, value


def _condition_rows(conditions: list[Any]) -> list[dict[str, str]]:
    """Stored conditions as the rows both modes of the template render."""
    rows: list[dict[str, str]] = []
    for condition in conditions:
        metric = str(condition.metric)
        value, words = _thresholds(metric, condition.threshold)
        rows.append(
            {
                "metric": metric,
                "label": METRIC_LABELS.get(metric, metric.replace("_", " ")),
                "operator": str(condition.operator),
                "word": OPERATOR_WORDS.get(str(condition.operator), str(condition.operator)),
                "value": value,
                "words": words,
            }
        )
    return rows


def _detail_page(
    request: Request,
    user: PageUser,
    gate_id: int,
    *,
    rows: list[dict[str, str]] | None = None,
    notice: str | None = None,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    """Render ``/gates/{id}``, optionally over rows a failed post typed."""
    engine = request.app.state.engine
    with engine.connect() as conn:
        gate = load_gate(conn, gate_id)
        if gate is None:
            return _gate_missing(request, user)
        if rows is None:
            rows = _condition_rows(load_conditions(conn, gate_id))
        used_by = int(
            conn.execute(
                text("SELECT count(*) FROM projects WHERE gate_id = :gid"), {"gid": gate_id}
            ).scalar_one()
        )
    return render(
        request,
        "gates_detail.html",
        context={
            "user": user,
            "nav": "gates",
            "gate": {
                "id": int(gate.id),
                "name": str(gate.name),
                "is_default": bool(gate.is_default),
                "is_builtin": bool(gate.is_builtin),
                "used_by": used_by,
                "conditions": rows,
            },
            "metrics": [
                {"value": metric, "label": METRIC_LABELS.get(metric, metric.replace("_", " "))}
                for metric in ALL_METRICS
            ],
            "operators": [
                {"value": operator, "word": OPERATOR_WORDS.get(operator, operator)}
                for operator in OPERATORS
            ],
            "can_edit": _can_edit(engine, user),
            "notice": notice,
            "error": error,
        },
        status_code=status_code,
    )


def _first_error(rows: list[dict[str, str]]) -> str | None:
    """Validate posted rows as ``ConditionIn`` does; the first problem wins."""
    for row in rows:
        try:
            threshold = float(row["value"])
        except ValueError:
            return "A threshold must be a number, for example 0 or 85."
        try:
            ConditionIn(metric=row["metric"], operator=row["operator"], threshold=threshold)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(piece) for piece in first["loc"])
            return f"{where}: {first['msg']}" if where else str(first["msg"])
    return None


# --- the routes ------------------------------------------------------------


@router.get("/gates")
def gates_list(request: Request, user: PageUser = Depends(require_page_user)) -> Response:
    """Every gate, its condition count and its adopters (section 9)."""
    return _list_page(request, user, notice=_notice(request))


@router.post("/gates")
def create_gate(
    request: Request,
    name: str = Form(...),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Start a gate from a name; its conditions are added on the detail page."""
    engine = request.app.state.engine
    if not _can_edit(engine, user):
        return _forbidden(request, user)
    cleaned = name.strip()
    if not cleaned:
        return _list_page(request, user, error="Give the gate a name.", status_code=400)
    try:
        created = add_gate(engine, name=cleaned, conditions=[], actor_id=user.id)
    except HTTPException as exc:
        return _list_page(request, user, error=str(exc.detail), status_code=400)
    return RedirectResponse(url=f"/gates/{created.id}?saved=created", status_code=303)


@router.get("/gates/{gate_id}")
def gate_detail(
    request: Request, gate_id: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """One gate as the design's window: read-only without ``gates.admin``."""
    if not gate_id.isdigit():
        return _gate_missing(request, user)
    return _detail_page(request, user, int(gate_id), notice=_notice(request))


@router.post("/gates/{gate_id}")
async def save_gate(
    request: Request, gate_id: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """Replace the gate's conditions with the rows on the page (section 9)."""
    engine = request.app.state.engine
    if not _can_edit(engine, user):
        return _forbidden(request, user)
    if not gate_id.isdigit():
        return _gate_missing(request, user)
    numeric_id = int(gate_id)
    form = await request.form()
    metrics = form.getlist("metric")
    operators = form.getlist("operator")
    thresholds = form.getlist("threshold")
    if not (len(metrics) == len(operators) == len(thresholds)):
        return _detail_page(
            request,
            user,
            numeric_id,
            error="Every condition needs a metric, an operator and a threshold.",
            status_code=400,
        )
    rows = [
        {"metric": str(metric), "operator": str(operator), "value": str(threshold)}
        for metric, operator, threshold in zip(metrics, operators, thresholds, strict=True)
    ]
    error = _first_error(rows)
    if error is not None:
        # What was typed stays on screen, exactly like the settings tabs.
        return _detail_page(request, user, numeric_id, rows=rows, error=error, status_code=400)
    conditions = [
        ConditionIn(
            metric=row["metric"],
            operator=row["operator"],
            threshold=float(row["value"]),
        )
        for row in rows
    ]
    try:
        edit_gate(engine, numeric_id, name=None, conditions=conditions, actor_id=user.id)
    except HTTPException as exc:
        if exc.status_code == 404:
            return _gate_missing(request, user)
        return _detail_page(request, user, numeric_id, error=str(exc.detail), status_code=400)
    return RedirectResponse(url=f"/gates/{numeric_id}?saved=gate", status_code=303)


@router.post("/gates/{gate_id}/delete")
def delete_gate(
    request: Request, gate_id: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """Delete an unused, non-built-in gate (the API's rules, section 9)."""
    engine = request.app.state.engine
    if not _can_edit(engine, user):
        return _forbidden(request, user)
    if not gate_id.isdigit():
        return _gate_missing(request, user)
    numeric_id = int(gate_id)
    try:
        remove_gate(engine, numeric_id, actor_id=user.id)
    except HTTPException as exc:
        if exc.status_code == 404:
            return _gate_missing(request, user)
        return _detail_page(request, user, numeric_id, error=str(exc.detail), status_code=400)
    return RedirectResponse(url="/gates?saved=deleted", status_code=303)
