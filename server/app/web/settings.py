"""Project settings pages (section 10, design "Project settings").

Six tabs under one shell - ``General | Scanners | Scope | Quality gate |
Tokens | Members`` - because they are six views of one project, not six
pages: every tab loads the same project through ``visible_project`` and
writes through the same service functions the JSON API uses (``app.projects``),
so a form post and a PATCH cannot disagree about what a setting means.

Everything here needs ``project.admin`` (section 7: "Settings, exclusions,
tokens, gate selection, members"). A member who is not an admin gets one 403
that names the permission, and the overview only links to Settings for the
people who can open it.
"""

from __future__ import annotations

from datetime import datetime, time, timezone
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy import Engine, text

from app.permissions import Permission, can
from app.projects import (
    MEMBER_COLUMNS,
    MemberError,
    MissingProject,
    ProjectKeyError,
    UnknownGate,
    delete_project,
    grant,
    list_members,
    principal_choices,
    revoke,
    save_settings,
    set_gate,
    stored_settings,
    update_project,
    visible_project,
)
from app.tokens import create_token, list_tokens, revoke_token
from app.web.projects import METRIC_LABELS
from app.web.routes import PageUser, render, require_page_user, timeago
from wadjet_schema import DEFAULT_EXCLUSION_GLOBS, ProjectSettings

router = APIRouter(include_in_schema=False)

#: The sub-tab row of the design's settings window, in order.
TABS: tuple[tuple[str, str], ...] = (
    ("general", "General"),
    ("scanners", "Scanners"),
    ("scope", "Scope"),
    ("gate", "Quality gate"),
    ("tokens", "Tokens"),
    ("members", "Members"),
)

TAB_LABELS = dict(TABS)

#: What a ``?saved=<code>`` redirect tells the reader (design copy: plain
#: verbs, specific about what changed).
NOTICES = {
    "general": "Saved. This project's name and description are updated.",
    "scanners": "Scanner settings saved. The next scan picks them up.",
    "scope": "Scope saved. Exclusions apply to every scanner.",
    "gate": "Quality gate selection saved. The next analysis is judged by it.",
    "granted": "Permissions updated for that member.",
    "removed": "That member's permissions were removed.",
    "revoked": "Token revoked. It can no longer authenticate.",
}

#: The scanners tab's fields, as the flat strings a form carries.
SCANNER_VALUE_KEYS = (
    "bandit_enabled",
    "bandit_skipped",
    "bandit_confidence",
    "bandit_timeout",
    "pip_audit_enabled",
    "pip_audit_files",
    "pip_audit_severity",
    "pip_audit_timeout",
    "ruff_enabled",
    "ruff_families",
    "ruff_timeout",
    "detect_secrets_enabled",
    "detect_secrets_timeout",
    "coverage_enabled",
    "coverage_path",
    "coverage_timeout",
    "fail_on_scanner_error",
    "timeout_seconds",
)

#: Adapter keys in the order the design's table lists them.
SCANNER_LABELS = {
    "bandit": "Bandit",
    "pip_audit": "pip-audit",
    "ruff": "Ruff",
    "detect_secrets": "detect-secrets",
    "coverage": "Coverage report",
}

#: One line under each scanner's options, in the design's voice.
SCANNER_NOTES = {
    "detect_secrets": "Secret values are never uploaded.",
    "coverage": "Read the report at this path after the tests run.",
}

#: How a condition reads in the gate picker: "Fail when X *is above* 0".
OPERATOR_WORDS = {
    ">": "is above",
    ">=": "is at least",
    "<": "is below",
    "<=": "is at most",
    "==": "is",
}

#: Section 7's templates, in the order the add-member select offers them.
TEMPLATE_CHOICES = (
    ("viewer", "Viewer", "Browse the project, its issues and analyses."),
    ("developer", "Developer", "Browse, comment, request an action and assign."),
    ("triager", "Triager", "Developer plus every flag permission."),
    ("project_admin", "Project admin", "Everything in the project, including settings."),
)


# --- the shell -------------------------------------------------------------


def _notice(request: Request) -> str | None:
    """The sentence a redirect carries, or nothing for a plain visit."""
    code = request.query_params.get("saved")
    if code is None:
        return None
    return NOTICES.get(code, "Saved.")


def _page(
    request: Request,
    user: PageUser,
    project: dict[str, Any],
    tab: str,
    *,
    notice: str | None = None,
    error: str | None = None,
    status_code: int = 200,
    **extra: Any,
) -> HTMLResponse:
    """Render one settings tab inside the shared shell."""
    context: dict[str, Any] = {
        "user": user,
        "nav": "projects",
        "project": project,
        "tab": tab,
        "tab_label": TAB_LABELS[tab],
        "tabs": [{"slug": slug, "label": label, "on": slug == tab} for slug, label in TABS],
        "notice": notice,
        "error": error,
        **extra,
    }
    # Tabs that only sometimes carry these (a created token, a failed post)
    # still get a defined value, so the template never reads an undefined.
    context.setdefault("form", None)
    context.setdefault("new_token", None)
    return render(request, f"settings_{tab}.html", context=context, status_code=status_code)


def _project_missing(request: Request, user: PageUser, key: str) -> HTMLResponse:
    """404: unknown key and "not granted" answer the same way (section 7)."""
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


def _restricted(request: Request, user: PageUser) -> HTMLResponse:
    """403: the settings need ``project.admin`` (section 7)."""
    return render(
        request,
        "error.html",
        context={
            "user": user,
            "nav": "projects",
            "title": "Project settings are restricted",
            "message": "Changing settings, tokens, the gate and members needs the "
            "project.admin permission on this project. Ask a project admin or an "
            "admin to grant it.",
        },
        status_code=403,
    )


def _load(
    request: Request, key: str, tab: str, user: PageUser
) -> tuple[dict[str, Any], ProjectSettings] | HTMLResponse:
    """Resolve the project for one settings tab, or answer with the failure.

    Order matters: visibility first (an unknown key and a key you may not
    see stay indistinguishable), then the tab, then the permission - so a
    bad tab on somebody else's project still says nothing about it.
    """
    engine = request.app.state.engine
    project = visible_project(engine, key=key, user_id=user.id)
    if project is None:
        return _project_missing(request, user, key)
    if tab not in TAB_LABELS:
        return render(
            request,
            "error.html",
            context={
                "user": user,
                "nav": "projects",
                "title": "No such settings page",
                "message": f"There is no settings tab {tab!r}. Pick one of: "
                f"{', '.join(TAB_LABELS)}.",
            },
            status_code=404,
        )
    if not can(engine, user.id, Permission.PROJECT_ADMIN, int(project["id"])):
        return _restricted(request, user)
    resolved: dict[str, Any] = {
        "id": int(project["id"]),
        "key": str(project["key"]),
        "name": str(project["name"]),
        "description": project["description"],
    }
    return resolved, stored_settings(project["settings"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _saved(key: str, tab: str, code: str) -> RedirectResponse:
    """Back to the tab that did the work, carrying its confirmation."""
    return RedirectResponse(url=f"/projects/{key}/settings/{tab}?saved={code}", status_code=303)


# --- shared form helpers ---------------------------------------------------


def _messages(exc: ValidationError) -> str:
    """Pydantic's errors as one line a person can act on."""
    parts: list[str] = []
    for error in exc.errors():
        where = ".".join(str(piece) for piece in error["loc"])
        parts.append(f"{where}: {error['msg']}" if where else str(error["msg"]))
    return "; ".join(parts)


def _flag(values: dict[str, str], name: str) -> bool:
    return bool(str(values.get(name, "")).strip())


def _split(raw: str) -> list[str]:
    """``"B101, B602"`` (or one per line) as a clean list."""
    out: list[str] = []
    for chunk in str(raw).replace("\n", ",").split(","):
        piece = chunk.strip()
        if piece and piece not in out:
            out.append(piece)
    return out


def _lines(raw: str) -> list[str]:
    """A textarea as one trimmed entry per non-empty line."""
    return [line.strip() for line in str(raw).splitlines() if line.strip()]


def _number(raw: str, *, empty: float | None = None) -> float | None:
    """A form number, or ``empty`` when the box is blank."""
    value = str(raw).strip()
    if not value:
        return empty
    return float(value)


def _seconds(value: float | None) -> str:
    if value is None:
        return ""
    return str(int(value)) if float(value).is_integer() else str(value)


# --- general ---------------------------------------------------------------


def _general_extra(
    project: dict[str, Any], user: PageUser, values: dict[str, str] | None = None
) -> dict[str, Any]:
    return {
        "form": values
        or {"name": str(project["name"]), "description": project["description"] or ""},
        # The danger zone is a global-admin action, like creating one.
        "can_delete": user.is_admin,
    }


# --- scanners --------------------------------------------------------------


def _scanner_values(settings: ProjectSettings) -> dict[str, str]:
    """Stored settings as the flat strings the scanners form carries."""
    scanners = settings.scanners
    return {
        "bandit_enabled": "on" if scanners.bandit.enabled else "",
        "bandit_skipped": ", ".join(scanners.bandit.skipped_test_ids),
        "bandit_confidence": scanners.bandit.minimum_confidence or "",
        "bandit_timeout": _seconds(scanners.bandit.timeout),
        "pip_audit_enabled": "on" if scanners.pip_audit.enabled else "",
        "pip_audit_files": ", ".join(scanners.pip_audit.dependency_files),
        "pip_audit_severity": scanners.pip_audit.dependency_default_severity or "",
        "pip_audit_timeout": _seconds(scanners.pip_audit.timeout),
        "ruff_enabled": "on" if scanners.ruff.enabled else "",
        "ruff_families": ", ".join(scanners.ruff.families),
        "ruff_timeout": _seconds(scanners.ruff.timeout),
        "detect_secrets_enabled": "on" if scanners.detect_secrets.enabled else "",
        "detect_secrets_timeout": _seconds(scanners.detect_secrets.timeout),
        "coverage_enabled": "on" if scanners.coverage.enabled else "",
        "coverage_path": scanners.coverage.report_path or "",
        "coverage_timeout": _seconds(scanners.coverage.timeout),
        "fail_on_scanner_error": "on" if settings.fail_on_scanner_error else "",
        "timeout_seconds": _seconds(settings.timeout_seconds),
    }


def _scanner_rows(values: dict[str, str]) -> list[dict[str, Any]]:
    """One table row per scanner: enable switch, structured options, timeout.

    Structured fields only (section 10) - there is nowhere on this page to
    type a CLI flag, which is the point of the settings schema.
    """
    rows: list[dict[str, Any]] = []
    for key, label in SCANNER_LABELS.items():
        fields: list[dict[str, Any]] = []
        if key == "bandit":
            fields = [
                {
                    "name": "bandit_skipped",
                    "label": "Skipped test IDs",
                    "value": values["bandit_skipped"],
                    "hint": "Comma separated, for example B101, B602",
                },
                {
                    "name": "bandit_confidence",
                    "label": "Minimum confidence",
                    "value": values["bandit_confidence"],
                    "choices": [
                        ("", "Any"),
                        ("low", "Low"),
                        ("medium", "Medium"),
                        ("high", "High"),
                    ],
                },
            ]
        elif key == "pip_audit":
            fields = [
                {
                    "name": "pip_audit_files",
                    "label": "Dependency files",
                    "value": values["pip_audit_files"],
                    "hint": "Comma separated, for example requirements.txt, requirements-dev.txt",
                },
                {
                    "name": "pip_audit_severity",
                    "label": "Default severity",
                    "value": values["pip_audit_severity"],
                    "choices": [
                        ("", "From the advisory"),
                        ("blocker", "Blocker"),
                        ("critical", "Critical"),
                        ("high", "High"),
                        ("medium", "Medium"),
                        ("low", "Low"),
                        ("info", "Info"),
                    ],
                },
            ]
        elif key == "ruff":
            fields = [
                {
                    "name": "ruff_families",
                    "label": "Rule families",
                    "value": values["ruff_families"],
                    "hint": "Comma separated, for example F, B, C90, PLE",
                },
            ]
        elif key == "coverage":
            fields = [
                {
                    "name": "coverage_path",
                    "label": "Report path",
                    "value": values["coverage_path"],
                    "hint": "Repo relative, for example coverage.xml",
                },
            ]
        rows.append(
            {
                "key": key,
                "label": label,
                "enabled": values[f"{key}_enabled"] == "on",
                "note": SCANNER_NOTES.get(key),
                "fields": fields,
                "timeout": values[f"{key}_timeout"],
            }
        )
    return rows


def _settings_from_values(values: dict[str, str], base: ProjectSettings) -> ProjectSettings:
    """The stored settings with this form's scanner section replaced."""
    dump = base.model_dump(mode="json")
    dump["scanners"] = {
        "bandit": {
            "enabled": _flag(values, "bandit_enabled"),
            "skipped_test_ids": _split(values.get("bandit_skipped", "")),
            "minimum_confidence": values.get("bandit_confidence", "").strip() or None,
            "timeout": _number(values.get("bandit_timeout", "")),
        },
        "pip_audit": {
            "enabled": _flag(values, "pip_audit_enabled"),
            "dependency_files": _split(values.get("pip_audit_files", "")),
            "dependency_default_severity": values.get("pip_audit_severity", "").strip() or None,
            "timeout": _number(values.get("pip_audit_timeout", "")),
        },
        "ruff": {
            "enabled": _flag(values, "ruff_enabled"),
            "families": _split(values.get("ruff_families", "")),
            "timeout": _number(values.get("ruff_timeout", "")),
        },
        "detect_secrets": {
            "enabled": _flag(values, "detect_secrets_enabled"),
            "timeout": _number(values.get("detect_secrets_timeout", "")),
        },
        "coverage": {
            "enabled": _flag(values, "coverage_enabled"),
            "report_path": values.get("coverage_path", "").strip() or None,
            "timeout": _number(values.get("coverage_timeout", "")),
        },
    }
    dump["fail_on_scanner_error"] = _flag(values, "fail_on_scanner_error")
    dump["timeout_seconds"] = _number(values.get("timeout_seconds", "")) or base.timeout_seconds
    return ProjectSettings.model_validate(dump)


# --- scope -----------------------------------------------------------------


def _scope_values(settings: ProjectSettings) -> dict[str, str]:
    return {
        "include": "\n".join(settings.scope.include),
        "exclude": "\n".join(settings.scope.exclude),
    }


def _scope_from_values(values: dict[str, str], base: ProjectSettings) -> ProjectSettings:
    dump = base.model_dump(mode="json")
    dump["scope"] = {
        "include": _lines(values.get("include", "")),
        "exclude": _lines(values.get("exclude", "")),
    }
    return ProjectSettings.model_validate(dump)


# --- quality gate ----------------------------------------------------------


def _gate_choices(engine: Engine, project_id: int) -> tuple[list[dict[str, Any]], int | None]:
    """Every gate with its conditions and how many projects use it.

    The project's own choice is ``None`` until it has one, which is the
    built-in default (section 9) - the picker says so rather than pretending
    nothing is selected.
    """
    with engine.connect() as conn:
        selected = conn.execute(
            text("SELECT gate_id FROM projects WHERE id = :pid"), {"pid": project_id}
        ).scalar()
        gates = (
            conn.execute(
                text(
                    "SELECT g.id, g.name, g.is_default, g.is_builtin, "
                    "(SELECT count(*) FROM projects p WHERE p.gate_id = g.id) AS used_by "
                    "FROM quality_gates g ORDER BY g.is_default DESC, g.id"
                )
            )
            .mappings()
            .all()
        )
        conditions = (
            conn.execute(
                text(
                    "SELECT gate_id, metric, operator, threshold "
                    "FROM gate_conditions ORDER BY gate_id, id"
                )
            )
            .mappings()
            .all()
        )
    by_gate: dict[int, list[str]] = {}
    for condition in conditions:
        metric = str(condition["metric"])
        label = METRIC_LABELS.get(metric, metric.replace("_", " "))
        threshold = condition["threshold"]
        if metric == "coverage_line_percent":
            rendered = f"{float(threshold):g}%"
        else:
            rendered = f"{float(threshold):g}"
        sentence = (
            f"Fail when {label} {OPERATOR_WORDS.get(str(condition['operator']), 'fails when')} "
            f"{rendered}"
        )
        by_gate.setdefault(int(condition["gate_id"]), []).append(sentence)
    choices = [
        {
            "id": int(gate["id"]),
            "name": str(gate["name"]),
            "is_default": bool(gate["is_default"]),
            "used_by": int(gate["used_by"]),
            "conditions": by_gate.get(int(gate["id"]), []),
            # No choice yet *is* the built-in default (section 9), so the
            # picker shows what the gate engine would actually use.
            "on": (
                int(gate["id"]) == int(selected)
                if selected is not None
                else bool(gate["is_default"])
            ),
        }
        for gate in gates
    ]
    return choices, (int(selected) if selected is not None else None)


# --- tokens ----------------------------------------------------------------


def _token_rows(engine: Engine, project_id: int) -> list[dict[str, Any]]:
    """Tokens for the table: prefix, when, and a word for their state."""
    now = datetime.now(timezone.utc)
    rows: list[dict[str, Any]] = []
    for data in list_tokens(engine, project_id):
        expires = data["expires_at"]
        if data["revoked_at"] is not None:
            chip, state = "bad", "Revoked"
        elif expires is not None and expires < now:
            chip, state = "nt", "Expired"
        else:
            chip, state = "ok", "Active"
        rows.append(
            {
                "id": int(data["id"]),
                "name": str(data["name"]),
                "prefix": str(data["prefix"]),
                "state_chip": chip,
                "state_label": state,
                "created": timeago(data["created_at"]),
                "last_used": timeago(data["last_used_at"]),
                "expires": timeago(expires) if expires is not None else "Never",
                "revoked": data["revoked_at"] is not None,
            }
        )
    return rows


def _expiry(raw: str) -> datetime | None:
    """An expiry date field as the end of that day in UTC, or ``None``."""
    value = str(raw).strip()
    if not value:
        return None
    try:
        day = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError("Expiry must be a date such as 2027-01-31, or leave it empty.") from exc
    moment = datetime.combine(day, time(23, 59, 59), tzinfo=timezone.utc)
    if moment <= datetime.now(timezone.utc):
        raise ValueError("Expiry must be in the future.")
    return moment


# --- members ---------------------------------------------------------------


def _member_matrix(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The design's matrix: each subject with a Yes/No per permission column."""
    for row in rows:
        held = set(row["permissions"])
        row["cells"] = [
            {"label": label, "yes": permission in held} for permission, label in MEMBER_COLUMNS
        ]
    return rows


def _members_extra(engine: Engine, project_id: int) -> dict[str, Any]:
    """Everything the members tab renders, also rebuilt after a failed post."""
    return {
        "members": _member_matrix(list_members(engine, project_id)),
        "columns": [
            {"permission": permission, "label": label} for permission, label in MEMBER_COLUMNS
        ],
        "choices": principal_choices(engine),
        "templates": [
            {"value": value, "label": label, "hint": hint}
            for value, label, hint in TEMPLATE_CHOICES
        ],
    }


# --- the tabs --------------------------------------------------------------


@router.get("/projects/{key}/settings")
def settings_index(
    request: Request, key: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """The tab row lives under General; the bare path lands there."""
    return RedirectResponse(url=f"/projects/{key}/settings/general", status_code=303)


@router.get("/projects/{key}/settings/{tab}")
def settings_page(
    request: Request, key: str, tab: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """Render one settings tab (section 10)."""
    loaded = _load(request, key, tab, user)
    if isinstance(loaded, Response):
        return loaded
    project, settings = loaded
    engine = request.app.state.engine
    extra: dict[str, Any]
    if tab == "general":
        extra = _general_extra(project, user)
    elif tab == "scanners":
        values = _scanner_values(settings)
        extra = {"values": values, "scanners": _scanner_rows(values)}
    elif tab == "scope":
        extra = {
            "values": _scope_values(settings),
            "defaults": list(DEFAULT_EXCLUSION_GLOBS),
        }
    elif tab == "gate":
        choices, selected = _gate_choices(engine, int(project["id"]))
        extra = {"gates": choices, "selected_gate": selected}
    elif tab == "tokens":
        extra = {"tokens": _token_rows(engine, int(project["id"])), "new_token": None}
    else:
        extra = _members_extra(engine, int(project["id"]))
    return _page(request, user, project, tab, notice=_notice(request), **extra)


# --- general ---------------------------------------------------------------


@router.post("/projects/{key}/settings/general")
def save_general(
    request: Request,
    key: str,
    name: str = Form(...),
    description: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Save the name and description; the key field is read-only (section 10)."""
    loaded = _load(request, key, "general", user)
    if isinstance(loaded, Response):
        return loaded
    project, _settings = loaded
    values = {"name": name, "description": description}
    try:
        update_project(
            request.app.state.engine,
            project_id=int(project["id"]),
            name=name,
            description=description,
            actor_id=user.id,
            ip=_ip(request),
        )
    except (ProjectKeyError, MissingProject) as exc:
        return _page(
            request,
            user,
            project,
            "general",
            error=str(exc),
            status_code=400,
            **_general_extra(project, user, values),
        )
    return _saved(key, "general", "general")


@router.post("/projects/{key}/settings/general/delete")
def delete_project_page(
    request: Request,
    key: str,
    confirm_key: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """The danger zone: type the key to confirm (section 10).

    Deleting a project is the mirror of creating one - a global-admin
    action, because section 7 does not list deletion among what
    ``project.admin`` allows.
    """
    loaded = _load(request, key, "general", user)
    if isinstance(loaded, Response):
        return loaded
    project, _settings = loaded
    if not user.is_admin:
        return _page(
            request,
            user,
            project,
            "general",
            error="Only admins can delete a project.",
            status_code=403,
            **_general_extra(project, user),
        )
    if confirm_key != project["key"]:
        return _page(
            request,
            user,
            project,
            "general",
            error=f"Type the project key ({project['key']}) to confirm the deletion.",
            status_code=400,
            **_general_extra(project, user),
        )
    delete_project(
        request.app.state.engine,
        project_id=int(project["id"]),
        actor_id=user.id,
        ip=_ip(request),
    )
    return RedirectResponse(url="/", status_code=303)


# --- scanners and scope ----------------------------------------------------


@router.post("/projects/{key}/settings/scanners")
async def save_scanners(
    request: Request, key: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """Replace the scanner section and the scan-level options (section 10)."""
    loaded = _load(request, key, "scanners", user)
    if isinstance(loaded, Response):
        return loaded
    project, settings = loaded
    form = await request.form()
    values = {name: str(form.get(name, "")) for name in SCANNER_VALUE_KEYS}
    try:
        payload = _settings_from_values(values, settings)
    except (ValidationError, ValueError) as exc:
        error = _messages(exc) if isinstance(exc, ValidationError) else str(exc)
        return _page(
            request,
            user,
            project,
            "scanners",
            error=error,
            status_code=400,
            values=values,
            scanners=_scanner_rows(values),
        )
    save_settings(
        request.app.state.engine,
        project_id=int(project["id"]),
        payload=payload,
        actor_id=user.id,
        ip=_ip(request),
    )
    return _saved(key, "scanners", "scanners")


@router.post("/projects/{key}/settings/scope")
async def save_scope(
    request: Request, key: str, user: PageUser = Depends(require_page_user)
) -> Response:
    """Replace include paths and exclusion globs (section 10)."""
    loaded = _load(request, key, "scope", user)
    if isinstance(loaded, Response):
        return loaded
    project, settings = loaded
    form = await request.form()
    values = {name: str(form.get(name, "")) for name in ("include", "exclude")}
    try:
        payload = _scope_from_values(values, settings)
    except (ValidationError, ValueError) as exc:
        error = _messages(exc) if isinstance(exc, ValidationError) else str(exc)
        return _page(
            request,
            user,
            project,
            "scope",
            error=error,
            status_code=400,
            values=values,
            defaults=list(DEFAULT_EXCLUSION_GLOBS),
        )
    save_settings(
        request.app.state.engine,
        project_id=int(project["id"]),
        payload=payload,
        actor_id=user.id,
        ip=_ip(request),
    )
    return _saved(key, "scope", "scope")


# --- quality gate ----------------------------------------------------------


@router.post("/projects/{key}/settings/gate")
def save_gate(
    request: Request,
    key: str,
    gate_id: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Point the project at one gate; empty means the built-in default."""
    loaded = _load(request, key, "gate", user)
    if isinstance(loaded, Response):
        return loaded
    project, _settings = loaded
    engine = request.app.state.engine
    choices, _selected = _gate_choices(engine, int(project["id"]))
    raw_gate = str(gate_id).strip()
    if raw_gate:
        try:
            chosen: int | None = int(raw_gate)
        except ValueError:
            return _page(
                request,
                user,
                project,
                "gate",
                error="Pick one of the gates below.",
                status_code=400,
                gates=choices,
                selected_gate=_selected,
            )
    else:
        chosen = None
    try:
        set_gate(
            engine,
            project_id=int(project["id"]),
            gate_id=chosen,
            actor_id=user.id,
            ip=_ip(request),
        )
    except UnknownGate as exc:
        return _page(
            request,
            user,
            project,
            "gate",
            error=str(exc),
            status_code=400,
            gates=choices,
            selected_gate=_selected,
        )
    return _saved(key, "gate", "gate")


# --- tokens ----------------------------------------------------------------


@router.post("/projects/{key}/settings/tokens")
def create_token_page(
    request: Request,
    key: str,
    name: str = Form(...),
    expires: str = Form(""),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Create a token and show it once (sections 10, 13)."""
    loaded = _load(request, key, "tokens", user)
    if isinstance(loaded, Response):
        return loaded
    project, _settings = loaded
    engine = request.app.state.engine
    tokens = _token_rows(engine, int(project["id"]))
    if not name.strip():
        return _page(
            request,
            user,
            project,
            "tokens",
            error="Give the token a name so you can recognise it later.",
            status_code=400,
            tokens=tokens,
            new_token=None,
            form={"name": name, "expires": expires},
        )
    try:
        expiry = _expiry(expires)
    except ValueError as exc:
        return _page(
            request,
            user,
            project,
            "tokens",
            error=str(exc),
            status_code=400,
            tokens=tokens,
            new_token=None,
            form={"name": name, "expires": expires},
        )
    full_token, token_id = create_token(engine, int(project["id"]), name, user.id, expiry)
    return _page(
        request,
        user,
        project,
        "tokens",
        notice="Token created. This is the only time the value is shown.",
        tokens=_token_rows(engine, int(project["id"])),
        new_token={"value": full_token, "id": token_id, "name": name},
        form={"name": "", "expires": ""},
    )


@router.post("/projects/{key}/settings/tokens/revoke")
def revoke_token_page(
    request: Request,
    key: str,
    token_id: int = Form(...),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Revoke one token of this project (section 10: revoke)."""
    loaded = _load(request, key, "tokens", user)
    if isinstance(loaded, Response):
        return loaded
    project, _settings = loaded
    engine = request.app.state.engine
    with engine.connect() as conn:
        owned = conn.execute(
            text("SELECT 1 FROM api_tokens WHERE id = :tid AND project_id = :pid"),
            {"tid": token_id, "pid": int(project["id"])},
        ).scalar()
    if not owned:
        return _page(
            request,
            user,
            project,
            "tokens",
            error="That token does not belong to this project.",
            status_code=404,
            tokens=_token_rows(engine, int(project["id"])),
            new_token=None,
        )
    revoke_token(engine, token_id, actor_id=user.id)
    return _saved(key, "tokens", "revoked")


# --- members ---------------------------------------------------------------


@router.post("/projects/{key}/settings/members")
def save_member(
    request: Request,
    key: str,
    subject: str = Form(...),
    template: str = Form(...),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Grant a permission template to one user or group (sections 7, 10)."""
    loaded = _load(request, key, "members", user)
    if isinstance(loaded, Response):
        return loaded
    project, _settings = loaded
    engine = request.app.state.engine
    kind, _, raw_id = str(subject).partition(":")
    try:
        subject_id = int(raw_id)
    except ValueError:
        subject_id = -1
    try:
        grant(
            engine,
            project_id=int(project["id"]),
            subject_type=kind,
            subject_id=subject_id,
            template=template,
            actor_id=user.id,
            ip=_ip(request),
        )
    except MemberError as exc:
        return _page(
            request,
            user,
            project,
            "members",
            error=str(exc),
            status_code=400,
            **_members_extra(engine, int(project["id"])),
        )
    return _saved(key, "members", "granted")


@router.post("/projects/{key}/settings/members/remove")
def remove_member(
    request: Request,
    key: str,
    subject: str = Form(...),
    user: PageUser = Depends(require_page_user),
) -> Response:
    """Take every permission away from one user or group (section 7)."""
    loaded = _load(request, key, "members", user)
    if isinstance(loaded, Response):
        return loaded
    project, _settings = loaded
    engine = request.app.state.engine
    kind, _, raw_id = str(subject).partition(":")
    try:
        subject_id = int(raw_id)
    except ValueError:
        subject_id = -1
    try:
        removed = revoke(
            engine,
            project_id=int(project["id"]),
            subject_type=kind,
            subject_id=subject_id,
            actor_id=user.id,
            ip=_ip(request),
        )
    except MemberError as exc:
        return _page(
            request,
            user,
            project,
            "members",
            error=str(exc),
            status_code=400,
            **_members_extra(engine, int(project["id"])),
        )
    if not removed:
        return _page(
            request,
            user,
            project,
            "members",
            error="That user or group has no permissions on this project.",
            status_code=404,
            **_members_extra(engine, int(project["id"])),
        )
    return _saved(key, "members", "removed")


__all__ = ["router"]
