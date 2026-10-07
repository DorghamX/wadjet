"""Issue filtering and workflow (sections 8, 12 and 14).

The filter half: one query builder, two callers - ``GET
/api/v1/projects/{key}/issues`` and the issues page accept the same filters,
sort the same way and page the same way, so an API call and a link from the
dashboard always agree. The filter *vocabulary* lives here because it is the
contract both callers validate against; the words and colors the design
paints it with belong to the pages.

The workflow half (T4.4): loading one issue, flagging it, assigning it,
commenting on it and reading its timeline. Authorization lives here rather
than in the routes (section 13), so the page and the JSON API cannot drift
apart on who may do what.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

import nh3
from markdown_it import MarkdownIt
from sqlalchemy import Engine, text

from app.audit import write_audit
from app.permissions import Permission, can

#: Triage vocabulary (section 4), in the order the sidebar lists it.
TRIAGE_STATUSES = ("open", "confirmed", "false_positive", "accepted_risk", "wont_fix")

#: Severity, most severe first - the order the agent reports in (section 5.1).
SEVERITIES = ("blocker", "critical", "high", "medium", "low", "info")

#: Presence (section 4): an issue can leave the list without losing its record.
PRESENCES = ("present", "resolved")

#: Categories scanners file findings under (section 6).
CATEGORIES = ("vulnerability", "dependency", "secret", "bug", "code_smell")

#: Sort keys (section 12 documents ``sort``); anything else is refused.
SORTS = ("severity", "status", "file", "first_seen", "last_seen", "title")

#: What an absent parameter means.
DEFAULT_SORT = "severity"
DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 200

#: The columns a list shows. Snippets, descriptions and fixes belong to the
#: issue detail page (T4.4) - a row here is identity, place and state.
_ISSUE_SELECT = """
SELECT i.id, i.title, i.tool, i.rule_id, i.severity, i.category, i.file_path,
       i.line_start, i.line_end, i.triage_status, i.presence, i.package,
       i.vuln_id, i.assignee_id, i.first_seen_analysis_id, i.last_seen_analysis_id,
       u.display_name AS assignee_name, u.username AS assignee_username
FROM issues i
LEFT JOIN users u ON u.id = i.assignee_id
"""

#: One ORDER BY per sort key. Every one ends in ``i.id`` so two issues with
#: the same severity or file cannot swap places between pages.
_SORT_SQL = {
    "severity": (
        "CASE i.severity WHEN 'blocker' THEN 0 WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END ASC, i.id DESC"
    ),
    "status": (
        "CASE i.triage_status WHEN 'open' THEN 0 WHEN 'confirmed' THEN 1 "
        "WHEN 'false_positive' THEN 2 WHEN 'accepted_risk' THEN 3 ELSE 4 END ASC, i.id DESC"
    ),
    "file": "i.file_path ASC NULLS LAST, i.line_start ASC NULLS LAST, i.id ASC",
    "first_seen": "i.first_seen_analysis_id DESC NULLS LAST, i.id DESC",
    "last_seen": "i.last_seen_analysis_id DESC NULLS LAST, i.id DESC",
    "title": "i.title ASC, i.id ASC",
}

#: Counts behind one facet group (the page's sidebar; the API needs none).
_FACET_SQL = {
    "status": (
        "SELECT triage_status AS value, count(*) AS total FROM issues "
        "WHERE project_id = :pid GROUP BY triage_status"
    ),
    "severity": (
        "SELECT severity AS value, count(*) AS total FROM issues "
        "WHERE project_id = :pid GROUP BY severity"
    ),
    "tool": (
        "SELECT tool AS value, count(*) AS total FROM issues WHERE project_id = :pid GROUP BY tool"
    ),
    "presence": (
        "SELECT presence AS value, count(*) AS total FROM issues "
        "WHERE project_id = :pid GROUP BY presence"
    ),
}


class BadIssueFilter(ValueError):
    """A filter value the server will not guess at (unknown status, page 0...)."""


def _like(value: str) -> str:
    """Escape LIKE wildcards: searching for ``100%`` must not match everything."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _first(pairs: Sequence[tuple[str, str]], name: str) -> str | None:
    """The first value of a query key; an empty one means "not set".

    The first occurrence wins: a URL's own parameters are written before any
    form values carried alongside them, so the more specific value - the one
    a link states on its own - is the one read.
    """
    for key, value in pairs:
        if key == name:
            return value
    return None


def _choice(
    pairs: Sequence[tuple[str, str]],
    name: str,
    allowed: Sequence[str],
    *,
    what: str,
) -> str | None:
    raw = _first(pairs, name)
    if not raw:
        return None
    if raw not in allowed:
        raise BadIssueFilter(f"unknown {what} {raw!r}; expected one of: {', '.join(allowed)}")
    return raw


def _whole_number(
    pairs: Sequence[tuple[str, str]],
    name: str,
    default: int,
    *,
    ceiling: int | None = None,
) -> int:
    raw = _first(pairs, name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise BadIssueFilter(f"{name} must be a whole number, not {raw!r}") from exc
    if value < 1:
        raise BadIssueFilter(f"{name} starts at 1, not {value}")
    return min(value, ceiling) if ceiling else value


@dataclass(frozen=True)
class IssueFilters:
    """One parsed view of the query string (section 12's filter list)."""

    status: str | None = None
    severity: str | None = None
    category: str | None = None
    tool: str | None = None
    file: str | None = None
    presence: str | None = None
    assignee: str | None = None
    text: str | None = None
    sort: str = DEFAULT_SORT
    page: int = 1
    per_page: int = DEFAULT_PER_PAGE

    @classmethod
    def from_query(cls, pairs: Sequence[tuple[str, str]]) -> IssueFilters:
        """Parse a query string; a value outside the vocabulary raises.

        Free-form values (tool, file, text) are not guessed at: a tool the
        server has never heard of simply matches nothing, which is the truth.
        """
        assignee = _first(pairs, "assignee")
        if assignee and assignee != "none" and not assignee.isdigit():
            raise BadIssueFilter(f"assignee must be a user id or 'none', not {assignee!r}")
        return cls(
            status=_choice(pairs, "status", TRIAGE_STATUSES, what="status"),
            severity=_choice(pairs, "severity", SEVERITIES, what="severity"),
            category=_choice(pairs, "category", CATEGORIES, what="category"),
            tool=_first(pairs, "tool") or None,
            file=_first(pairs, "file") or None,
            presence=_choice(pairs, "presence", PRESENCES, what="presence"),
            assignee=assignee or None,
            text=_first(pairs, "text") or None,
            sort=_choice(pairs, "sort", SORTS, what="sort") or DEFAULT_SORT,
            page=_whole_number(pairs, "page", 1),
            per_page=_whole_number(pairs, "per_page", DEFAULT_PER_PAGE, ceiling=MAX_PER_PAGE),
        )

    def params(self, **changes: str | int | None) -> dict[str, str]:
        """This state as a query dict, with ``changes`` applied.

        The page renders every facet and pagination link from it, so a link
        can never forget a filter: a change of ``None`` drops that key
        (clearing the filter) and anything else replaces it. Values left unset
        are omitted, which keeps URLs short and the address bar honest.
        """
        current: dict[str, str | int | None] = {
            "status": self.status,
            "severity": self.severity,
            "category": self.category,
            "tool": self.tool,
            "file": self.file,
            "presence": self.presence,
            "assignee": self.assignee,
            "text": self.text,
            "sort": None if self.sort == DEFAULT_SORT else self.sort,
            "page": None if self.page == 1 else self.page,
            "per_page": None if self.per_page == DEFAULT_PER_PAGE else self.per_page,
        }
        unknown = set(changes) - set(current)
        if unknown:
            raise ValueError(f"not a filter: {', '.join(sorted(unknown))}")
        current.update(changes)
        values = {key: (None if value is None else str(value)) for key, value in current.items()}
        # Defaults are worth no parameter, whether they came from the state
        # or from the change a link is making: page 1, the default sort and
        # the default size are exactly what an absent parameter already means.
        if values["sort"] == DEFAULT_SORT:
            values["sort"] = None
        if values["page"] == "1":
            values["page"] = None
        if values["per_page"] == str(DEFAULT_PER_PAGE):
            values["per_page"] = None
        return {key: value for key, value in values.items() if value}


def _where(project_id: int, filters: IssueFilters) -> tuple[str, dict[str, Any]]:
    """The WHERE clause the page query and the count must share."""
    clauses = ["i.project_id = :pid"]
    params: dict[str, Any] = {"pid": project_id}
    for column, value, name in (
        ("i.triage_status", filters.status, "status"),
        ("i.severity", filters.severity, "severity"),
        ("i.category", filters.category, "category"),
        ("i.tool", filters.tool, "tool"),
        ("i.presence", filters.presence, "presence"),
    ):
        if value is not None:
            clauses.append(f"{column} = :{name}")
            params[name] = value
    if filters.file is not None:
        clauses.append("i.file_path LIKE :file ESCAPE '\\'")
        params["file"] = _like(filters.file) + "%"
    if filters.assignee is not None:
        if filters.assignee == "none":
            clauses.append("i.assignee_id IS NULL")
        else:
            clauses.append("i.assignee_id = :assignee")
            params["assignee"] = int(filters.assignee)
    if filters.text is not None:
        clauses.append(
            "(i.title ILIKE :q ESCAPE '\\' OR i.file_path ILIKE :q ESCAPE '\\' "
            "OR i.rule_id ILIKE :q ESCAPE '\\')"
        )
        params["q"] = f"%{_like(filters.text)}%"
    return " AND ".join(clauses), params


def query_issues(
    engine: Engine, *, project_id: int, filters: IssueFilters
) -> tuple[Sequence[Mapping[str, Any]], int]:
    """One page of issues, plus how many issues match the filters in total."""
    where, params = _where(project_id, filters)
    with engine.connect() as conn:
        total = int(
            conn.execute(text(f"SELECT count(*) FROM issues i WHERE {where}"), params).scalar_one()
        )
        sql = (
            f"{_ISSUE_SELECT} WHERE {where} ORDER BY {_SORT_SQL[filters.sort]} "
            "LIMIT :limit OFFSET :offset"
        )
        rows = (
            conn.execute(
                text(sql),
                {
                    **params,
                    "limit": filters.per_page,
                    "offset": (filters.page - 1) * filters.per_page,
                },
            )
            .mappings()
            .all()
        )
    return cast(Sequence[Mapping[str, Any]], rows), total


def facet_counts(engine: Engine, *, project_id: int) -> dict[str, dict[str, int]]:
    """How many issues sit behind each filter, over the whole project.

    The counts deliberately ignore the active filters: they label the set you
    would get by clicking that link, so a count that shrank while you filtered
    would be a lie about it.
    """
    counts: dict[str, dict[str, int]] = {}
    with engine.connect() as conn:
        for group, sql in _FACET_SQL.items():
            rows = conn.execute(text(sql), {"pid": project_id}).all()
            counts[group] = {str(value): int(total) for value, total in rows if value is not None}
    return counts


# --- the issue itself: detail, triage, assignment, comments (T4.4) ---------


class IssueNotFound(LookupError):
    """No such issue in this project (routes answer 404)."""


class IssuePermissionDenied(Exception):
    """The user lacks the permission this action needs (routes answer 403)."""


class BadIssueAction(ValueError):
    """The action as submitted is not valid: reason, body, assignee, status."""


#: Section 8: these three statuses need a reason of at least REASON_MIN
#: characters - the ones that close a finding on human judgement.
REASON_STATUSES = frozenset({"false_positive", "accepted_risk", "wont_fix"})

#: Reason and comment size limits (section 13: field size limits).
REASON_MIN = 10
REASON_MAX = 2000
COMMENT_MAX = 10000

#: One click must not sweep the whole project past this many issues.
MAX_BULK = 500

#: Which permission each status transition needs (section 7).
FLAG_PERMISSIONS: dict[str, Permission] = {
    "confirmed": Permission.FLAG_CONFIRM,
    "false_positive": Permission.FLAG_FALSE_POSITIVE,
    "accepted_risk": Permission.FLAG_ACCEPTED_RISK,
    "wont_fix": Permission.FLAG_WONT_FIX,
    "open": Permission.FLAG_REOPEN,
}

#: Comment markdown subset (section 8): anything outside these tags is
#: unwrapped by nh3, and raw HTML never enters in the first place.
_COMMENT_TAGS = {"p", "br", "strong", "em", "code", "pre", "ul", "ol", "li", "blockquote", "a"}
_COMMENT_ATTRIBUTES: dict[str, set[str]] = {"a": {"href", "title"}}

_MD = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False})


def render_comment(body_md: str) -> str:
    """Comment markdown to safe HTML (sections 8 and 13).

    Two independent layers: ``html: False`` escapes every raw tag the author
    typed, and nh3 re-filters the renderer's output down to the subset above.
    The comment body comes from a user, so neither layer may be skipped.
    """
    rendered = _MD.render(body_md)
    return nh3.clean(
        rendered,
        tags=_COMMENT_TAGS,
        attributes=_COMMENT_ATTRIBUTES,
        url_schemes={"http", "https", "mailto"},
    )


def _require(engine: Engine, user_id: int, project_id: int, permission: Permission) -> None:
    """Permission gate shared by every action below (section 13)."""
    if not can(engine, user_id, permission, project_id=project_id):
        raise IssuePermissionDenied(f"{permission.value} permission required.")


def allowed_status_actions(engine: Engine, *, user_id: int, project_id: int) -> set[str]:
    """The statuses this user may set here - an empty set means no triage."""
    return {
        status
        for status, permission in FLAG_PERMISSIONS.items()
        if can(engine, user_id, permission, project_id=project_id)
    }


def _clean_reason(status: str, reason: str | None) -> str | None:
    """Trim the reason and enforce section 8's rule about when one is needed."""
    cleaned = (reason or "").strip()
    if status in REASON_STATUSES and len(cleaned) < REASON_MIN:
        raise BadIssueAction(
            f"A reason of at least {REASON_MIN} characters is required to mark an issue "
            "as false positive, accepted risk or won't fix."
        )
    if len(cleaned) > REASON_MAX:
        raise BadIssueAction(f"A reason may be at most {REASON_MAX} characters.")
    return cleaned or None


def _validate_status(status: str) -> None:
    if status not in TRIAGE_STATUSES:
        raise BadIssueAction(
            f"Unknown status {status!r}; expected one of: {', '.join(TRIAGE_STATUSES)}"
        )


def _triage_event(conn: Any, issue_id: int, actor_id: int, status: str, reason: str | None) -> None:
    payload: dict[str, str] = {"status": status}
    if reason:
        payload["reason"] = reason
    conn.execute(
        text(
            "INSERT INTO issue_events (issue_id, actor_id, type, payload) "
            "VALUES (:iid, :actor, 'status_changed', :payload)"
        ),
        {"iid": issue_id, "actor": actor_id, "payload": json.dumps(payload)},
    )


#: The detail row's SELECT: every issue column plus the names a page shows
#: and the key of the project it belongs to.
_DETAIL_SELECT = (
    "SELECT i.*, p.key AS project_key, "
    "au.display_name AS assignee_name, au.username AS assignee_username, "
    "tu.display_name AS triager_name, tu.username AS triager_username "
    "FROM issues i "
    "JOIN projects p ON p.id = i.project_id "
    "LEFT JOIN users au ON au.id = i.assignee_id "
    "LEFT JOIN users tu ON tu.id = i.triaged_by "
)


def _detail_row(engine: Engine, where: str, params: dict[str, Any]) -> dict[str, Any] | None:
    with engine.connect() as conn:
        row = conn.execute(text(_DETAIL_SELECT + where), params).mappings().first()
    return dict(row) if row else None


def load_issue(engine: Engine, *, project_id: int, issue_id: int) -> dict[str, Any] | None:
    """The full detail row, scoped to one project; ``None`` when not found.

    Scoping by project in the query itself is what makes an issue of another
    project indistinguishable from an issue that does not exist.
    """
    return _detail_row(
        engine, "WHERE i.id = :iid AND i.project_id = :pid", {"iid": issue_id, "pid": project_id}
    )


def load_issue_by_id(engine: Engine, *, issue_id: int) -> dict[str, Any] | None:
    """One issue by its id alone, with the project key it belongs to.

    Finding the row is not seeing it: callers still run the key through
    ``visible_project`` before answering, so a stranger cannot tell an issue
    id apart from a typo.
    """
    return _detail_row(engine, "WHERE i.id = :iid", {"iid": issue_id})


def set_triage(
    engine: Engine,
    *,
    issue: Mapping[str, Any],
    status: str,
    reason: str | None,
    actor_id: int,
    ip: str | None = None,
) -> bool:
    """Flag one issue (section 8): permission per status, reason rules, event.

    Returns ``True`` when the status actually changed - re-flagging an issue
    to the status it already has is a no-op, not a second timeline entry.
    """
    _validate_status(status)
    _require(engine, actor_id, int(issue["project_id"]), FLAG_PERMISSIONS[status])
    cleaned = _clean_reason(status, reason)
    if str(issue["triage_status"]) == status:
        return False
    changed = False
    with engine.begin() as conn:
        updated = conn.execute(
            text(
                "UPDATE issues SET triage_status = :status, triage_reason = :reason, "
                "triaged_by = :actor, triaged_at = now() "
                "WHERE id = :iid AND triage_status IS DISTINCT FROM :status"
            ),
            {"status": status, "reason": cleaned, "actor": actor_id, "iid": int(issue["id"])},
        )
        changed = bool(updated.rowcount)
        if changed:
            _triage_event(conn, int(issue["id"]), actor_id, status, cleaned)
    if not changed:
        return False
    write_audit(
        engine,
        action=f"flag.{'reopen' if status == 'open' else status}",
        actor_id=actor_id,
        target_type="issue",
        target_id=int(issue["id"]),
        details={"status": status, **({"reason": cleaned} if cleaned else {})},
        ip=ip,
    )
    return True


def bulk_triage(
    engine: Engine,
    *,
    project_id: int,
    issue_ids: Sequence[int],
    status: str,
    reason: str | None,
    actor_id: int,
    ip: str | None = None,
) -> int:
    """Flag many issues in one transaction (section 8's bulk triage).

    Everything is validated before the first write - one permission check,
    one reason check - so a bulk action either applies completely or not at
    all. Returns how many issues actually changed.
    """
    _validate_status(status)
    _require(engine, actor_id, project_id, FLAG_PERMISSIONS[status])
    cleaned = _clean_reason(status, reason)
    if not issue_ids:
        raise BadIssueAction("Select at least one issue.")
    unique = list(dict.fromkeys(int(i) for i in issue_ids))
    if len(unique) > MAX_BULK:
        raise BadIssueAction(f"Select at most {MAX_BULK} issues at a time.")
    placeholders = ", ".join(f":id{n}" for n in range(len(unique)))
    params: dict[str, Any] = {
        "status": status,
        "reason": cleaned,
        "actor": actor_id,
        "pid": project_id,
    }
    params.update({f"id{n}": value for n, value in enumerate(unique)})
    with engine.begin() as conn:
        changed_rows = conn.execute(
            text(
                "UPDATE issues SET triage_status = :status, triage_reason = :reason, "
                "triaged_by = :actor, triaged_at = now() "
                f"WHERE project_id = :pid AND id IN ({placeholders}) "
                "AND triage_status IS DISTINCT FROM :status "
                "RETURNING id"
            ),
            params,
        ).fetchall()
        for (changed_id,) in changed_rows:
            _triage_event(conn, int(changed_id), actor_id, status, cleaned)
    for (changed_id,) in changed_rows:
        write_audit(
            engine,
            action=f"flag.{'reopen' if status == 'open' else status}",
            actor_id=actor_id,
            target_type="issue",
            target_id=int(changed_id),
            details={"status": status, **({"reason": cleaned} if cleaned else {})},
            ip=ip,
        )
    return len(changed_rows)


def project_members(engine: Engine, *, project_id: int) -> list[dict[str, Any]]:
    """Everyone who may be assigned this issue (section 8: any member).

    A member holds at least one permission in the project - directly or
    through a group - or is a global admin, and is active.
    """
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT u.id, u.username, u.display_name FROM users u "
                    "WHERE u.is_active AND ("
                    "  u.is_admin"
                    "  OR EXISTS (SELECT 1 FROM project_grants g WHERE g.project_id = :pid "
                    "             AND g.subject_type = 'user' AND g.subject_id = u.id)"
                    "  OR EXISTS (SELECT 1 FROM project_grants g "
                    "             JOIN group_members gm ON gm.group_id = g.subject_id "
                    "             WHERE g.project_id = :pid AND g.subject_type = 'group' "
                    "             AND gm.user_id = u.id)"
                    ") ORDER BY COALESCE(NULLIF(u.display_name, ''), u.username)"
                ),
                {"pid": project_id},
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


def permission_holders(
    engine: Engine, *, project_id: int, permission: Permission
) -> list[dict[str, Any]]:
    """Users holding one permission here - the target list of a request (8)."""
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT u.id, u.username, u.display_name FROM users u "
                    "WHERE u.is_active AND ("
                    "  u.is_admin"
                    "  OR EXISTS (SELECT 1 FROM project_grants g WHERE g.project_id = :pid "
                    "             AND g.permission = :perm "
                    "             AND ((g.subject_type = 'user' AND g.subject_id = u.id)"
                    "                  OR (g.subject_type = 'group' AND EXISTS ("
                    "                        SELECT 1 FROM group_members gm "
                    "                        WHERE gm.group_id = g.subject_id "
                    "                        AND gm.user_id = u.id))))"
                    ") ORDER BY COALESCE(NULLIF(u.display_name, ''), u.username)"
                ),
                {"pid": project_id, "perm": permission.value},
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


def assign_issue(
    engine: Engine,
    *,
    issue: Mapping[str, Any],
    assignee_id: int | None,
    actor_id: int,
) -> bool:
    """Assign or unassign (section 8): ``issue.assign``, members only.

    Returns ``True`` when the assignee actually changed; the timeline entry
    carries the name the assignee had at that moment, not a later rename.
    """
    project_id = int(issue["project_id"])
    _require(engine, actor_id, project_id, Permission.ISSUE_ASSIGN)
    assignee: Mapping[str, Any] | None = None
    if assignee_id is not None:
        members = project_members(engine, project_id=project_id)
        assignee = next((m for m in members if int(m["id"]) == int(assignee_id)), None)
        if assignee is None:
            raise BadIssueAction("Pick someone who is a member of this project.")
    with engine.begin() as conn:
        updated = conn.execute(
            text(
                "UPDATE issues SET assignee_id = :aid "
                "WHERE id = :iid AND assignee_id IS DISTINCT FROM :aid"
            ),
            {"aid": assignee_id, "iid": int(issue["id"])},
        )
        if not updated.rowcount:
            return False
        name = (
            str(assignee["display_name"] or assignee["username"]) if assignee is not None else None
        )
        conn.execute(
            text(
                "INSERT INTO issue_events (issue_id, actor_id, type, payload) "
                "VALUES (:iid, :actor, 'assigned', :payload)"
            ),
            {
                "iid": int(issue["id"]),
                "actor": actor_id,
                "payload": json.dumps({"assignee_id": assignee_id, "assignee": name}),
            },
        )
    return True


def _clean_comment(body: str | None) -> str:
    cleaned = (body or "").strip()
    if not cleaned:
        raise BadIssueAction("Write something first.")
    if len(cleaned) > COMMENT_MAX:
        raise BadIssueAction(f"A comment may be at most {COMMENT_MAX} characters.")
    return cleaned


def add_comment(
    engine: Engine, *, issue: Mapping[str, Any], author_id: int, body: str | None
) -> int:
    """Post a comment (section 8): ``issue.comment``.

    No comment *event* is written: the timeline renders the comment row
    itself, where the live state (edited, deleted) lives.
    """
    project_id = int(issue["project_id"])
    _require(engine, author_id, project_id, Permission.ISSUE_COMMENT)
    cleaned = _clean_comment(body)
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "INSERT INTO issue_comments (issue_id, author_id, body_md) "
                "VALUES (:iid, :author, :body) RETURNING id"
            ),
            {"iid": int(issue["id"]), "author": author_id, "body": cleaned},
        ).scalar_one()
    return int(row)


def load_comment(engine: Engine, *, comment_id: int) -> dict[str, Any] | None:
    """One comment row (author and issue are checked by the caller)."""
    with engine.connect() as conn:
        row = (
            conn.execute(text("SELECT * FROM issue_comments WHERE id = :cid"), {"cid": comment_id})
            .mappings()
            .first()
        )
    return dict(row) if row else None


def list_comments(
    engine: Engine, *, issue_id: int, comment_id: int | None = None
) -> list[dict[str, Any]]:
    """Live comments with their authors, oldest first.

    Deleted rows disappear; ``comment_id`` narrows the query to one comment
    (used to answer a create with the row it just wrote).
    """
    sql = (
        "SELECT c.id, c.issue_id, c.author_id, c.body_md, c.created_at, c.edited_at, "
        "u.display_name AS author_name, u.username AS author_username "
        "FROM issue_comments c JOIN users u ON u.id = c.author_id "
        "WHERE c.issue_id = :iid AND c.deleted_at IS NULL"
    )
    params: dict[str, Any] = {"iid": issue_id}
    if comment_id is not None:
        sql += " AND c.id = :cid"
        params["cid"] = comment_id
    sql += " ORDER BY c.created_at ASC, c.id ASC"
    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
    return [dict(row) for row in rows]


def edit_comment(
    engine: Engine, *, comment: Mapping[str, Any], actor_id: int, body: str | None
) -> None:
    """Edit your own comment (section 8: edit own - admins edit their own too)."""
    if int(comment["author_id"]) != actor_id:
        raise IssuePermissionDenied("You can only edit your own comments.")
    cleaned = _clean_comment(body)
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE issue_comments SET body_md = :body, edited_at = now() "
                "WHERE id = :cid AND deleted_at IS NULL"
            ),
            {"body": cleaned, "cid": int(comment["id"])},
        )


def delete_comment(
    engine: Engine, *, comment: Mapping[str, Any], actor_id: int, project_id: int
) -> None:
    """Delete a comment: the author, an admin, or nobody (section 8).

    Admin means global admin or ``project.admin`` here - ``can`` answers for
    both. The row is kept with ``deleted_at`` set; the timeline stops showing
    it, but the database still knows what happened.
    """
    is_author = int(comment["author_id"]) == actor_id
    if not is_author and not can(engine, actor_id, Permission.PROJECT_ADMIN, project_id=project_id):
        raise IssuePermissionDenied("Only the author or an admin can delete a comment.")
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE issue_comments SET deleted_at = now() WHERE id = :cid"),
            {"cid": int(comment["id"])},
        )


def issue_timeline(engine: Engine, *, issue_id: int) -> list[dict[str, Any]]:
    """Events, comments and requests as one feed, newest first (section 8).

    Comment and request *events* are deliberately skipped: those rows render
    from their own tables, where the live state (edited, pending, declined)
    lives - an event copy would be a stale second telling of the same thing.
    """
    with engine.connect() as conn:
        events = (
            conn.execute(
                text(
                    "SELECT e.id, e.type, e.payload, e.created_at, e.actor_id, "
                    "u.display_name AS actor_name, u.username AS actor_username "
                    "FROM issue_events e LEFT JOIN users u ON u.id = e.actor_id "
                    "WHERE e.issue_id = :iid "
                    "AND e.type NOT IN ('comment', 'request_created', 'request_resolved')"
                ),
                {"iid": issue_id},
            )
            .mappings()
            .all()
        )
        comments = (
            conn.execute(
                text(
                    "SELECT c.id, c.body_md, c.created_at, c.edited_at, c.author_id, "
                    "u.display_name AS author_name, u.username AS author_username "
                    "FROM issue_comments c JOIN users u ON u.id = c.author_id "
                    "WHERE c.issue_id = :iid AND c.deleted_at IS NULL"
                ),
                {"iid": issue_id},
            )
            .mappings()
            .all()
        )
        requests = (
            conn.execute(
                text(
                    "SELECT r.id, r.requested_action, r.message, r.state, r.created_at, "
                    "r.requested_by, r.target_user_id, "
                    "u.display_name AS requester_name, u.username AS requester_username, "
                    "t.display_name AS target_name, t.username AS target_username "
                    "FROM issue_requests r "
                    "JOIN users u ON u.id = r.requested_by "
                    "LEFT JOIN users t ON t.id = r.target_user_id "
                    "WHERE r.issue_id = :iid"
                ),
                {"iid": issue_id},
            )
            .mappings()
            .all()
        )
    items = [{"kind": "event", **dict(row)} for row in events]
    items += [{"kind": "comment", **dict(row)} for row in comments]
    items += [{"kind": "request", **dict(row)} for row in requests]
    items.sort(key=lambda item: (item["created_at"], int(item["id"])), reverse=True)
    return items


def matching_issue_ids(
    engine: Engine, *, project_id: int, filters: IssueFilters, cap: int
) -> list[int]:
    """Every issue id behind the current filters, capped (bulk "select all")."""
    where, params = _where(project_id, filters)
    with engine.connect() as conn:
        rows = conn.execute(
            text(f"SELECT i.id FROM issues i WHERE {where} ORDER BY i.id LIMIT :cap"),
            {**params, "cap": cap},
        ).all()
    return [int(row[0]) for row in rows]


__all__ = [
    "BadIssueAction",
    "BadIssueFilter",
    "CATEGORIES",
    "COMMENT_MAX",
    "DEFAULT_PER_PAGE",
    "DEFAULT_SORT",
    "FLAG_PERMISSIONS",
    "IssueFilters",
    "IssueNotFound",
    "IssuePermissionDenied",
    "MAX_BULK",
    "MAX_PER_PAGE",
    "PRESENCES",
    "REASON_MIN",
    "REASON_STATUSES",
    "SEVERITIES",
    "SORTS",
    "TRIAGE_STATUSES",
    "add_comment",
    "allowed_status_actions",
    "assign_issue",
    "bulk_triage",
    "delete_comment",
    "edit_comment",
    "facet_counts",
    "issue_timeline",
    "list_comments",
    "load_comment",
    "load_issue",
    "load_issue_by_id",
    "matching_issue_ids",
    "permission_holders",
    "project_members",
    "query_issues",
    "render_comment",
    "set_triage",
]
