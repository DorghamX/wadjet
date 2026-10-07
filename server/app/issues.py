"""Issue filtering (sections 8, 12 and 14): one query builder, two callers.

``GET /api/v1/projects/{key}/issues`` and the issues page accept the same
filters, sort the same way and page the same way, so an API call and a link
from the dashboard always agree. The filter *vocabulary* lives here because
it is the contract both callers validate against; the words and colors the
design paints it with belong to the pages.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import Engine, text

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


__all__ = [
    "BadIssueFilter",
    "CATEGORIES",
    "DEFAULT_PER_PAGE",
    "DEFAULT_SORT",
    "IssueFilters",
    "MAX_PER_PAGE",
    "PRESENCES",
    "SEVERITIES",
    "SORTS",
    "TRIAGE_STATUSES",
    "facet_counts",
    "query_issues",
]
