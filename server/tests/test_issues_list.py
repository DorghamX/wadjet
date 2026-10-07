"""Issues list and its HTMX partials (phase 4, T4.3).

Rendered from ``seed-demo`` data, so the assertions double as a contract on
the design: severity with a colored edge *and* a word, filters with counts on
the left, one row per issue - and a search box whose caret must survive every
keystroke, which is why one route answers three ways (full page, sidebar +
table, table alone), told apart by the ``HX-Target`` header htmx sends.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.issues import BadIssueFilter, IssueFilters
from app.security import hash_password
from app.seed import seed_demo

HTML = {"Accept": "text/html"}

#: What htmx sends with a partial request; the route branches on HX-Target.
HX_BODY = {"HX-Request": "true", "HX-Target": "issues-body"}
HX_TABLE = {"HX-Request": "true", "HX-Target": "issues-table"}

#: The seeded project with 16 issues, one blocker, one assignment.
ISSUES = "/projects/payments/issues"
API_ISSUES = "/api/v1/projects/payments/issues"


def _signup(engine: Engine, username: str, *, is_admin: bool = False) -> str:
    """Create a user with a known password and return that password."""
    password = f"pw-{username}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES (:u, :e, :h, :admin, TRUE)"
            ),
            {
                "u": username,
                "e": f"{username}@example.test",
                "h": hash_password(password),
                "admin": is_admin,
            },
        )
    return password


def _login(client: TestClient, username: str, password: str, next_url: str = "/") -> Any:
    """Log in the way the browser form does (html Accept + hidden csrf)."""
    if "wadjet_csrf" not in client.cookies:
        client.get("/login")
    return client.post(
        f"/session?next={next_url}",
        data={
            "username": username,
            "password": password,
            "csrf_token": client.cookies.get("wadjet_csrf"),
        },
        headers=HTML,
        follow_redirects=False,
    )


def _api_headers(client: TestClient) -> dict[str, str]:
    """Session cookies plus the CSRF header an HTMX/API client sends."""
    return {"X-CSRF-Token": client.cookies.get("wadjet_csrf", "")}


def _rows_of(body: str) -> list[str]:
    """The issue rows out of a rendered table (the header row is not one)."""
    table = body.split('<table class="t">', 1)[1].split("</table>", 1)[0]
    return table.split("<tr>")[2:]


def _row_count(body: str) -> int:
    """One location cell per issue row; the empty state has no table."""
    return body.count('<td class="m">')


def _count(engine: Engine, sql: str, **params: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


def _signed_in_admin(client: TestClient, engine: Engine, username: str) -> None:
    seed_demo(engine)
    password = _signup(engine, username, is_admin=True)
    _login(client, username, password)


# --- the page --------------------------------------------------------------


def test_anonymous_issues_page_redirects_to_login(client: TestClient) -> None:
    response = client.get(ISSUES, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_issues_page_is_the_design_table(client: TestClient, engine: Engine) -> None:
    _signed_in_admin(client, engine, "issuesadmin")
    body = client.get(ISSUES).text

    # Page head, the search box from the design, and the sort menu beside it.
    assert "<h1>Issues</h1>" in body
    assert 'placeholder="Search by title, file or rule"' in body
    assert 'id="issue-search-sort"' in body

    # The design's five columns, in order.
    heads = [f">{name}</th>" for name in ("Severity", "Issue", "Location", "Status", "Assignee")]
    positions = [body.index(head) for head in heads]
    assert positions == sorted(positions)

    # Facet counts over the whole project (payments: 11 open, 1 blocker,
    # 9 ruff findings, 15 still present).
    for facet in (
        ">Open</a><span>11</span>",
        ">Blocker</a><span>1</span>",
        ">Ruff</a><span>9</span>",
        ">Present</a><span>15</span>",
    ):
        assert facet in body

    # Every status is a word, not only a color (design copy).
    for word in ("Confirmed", "False positive", "Accepted risk", "Won&#39;t fix"):
        assert f">{word}</a>" in body

    rows = _rows_of(body)
    assert len(rows) == 16
    # Worst severity first: the blocker row the design shows at the top,
    # with its rule on the muted second line and path:line in the middle.
    first = rows[0]
    assert '<span class="sv s1">Blocker</span>' in first
    # The title now links to the issue's own page (T4.4); the muted rule line
    # and path:line keep their place below and beside it.
    assert 'href="/projects/payments/issues/' in first
    assert "Private Key</a><br>" in first
    assert '<span class="mu">detect-secrets Private Key</span>' in first
    assert '<td class="m">src/config/deploy_key.pem:1</td>' in first
    assert '<span class="c nt">Open</span>' in first
    # Assignment is a name, and unassigned says so with a word.
    assert "Bob Okafor" in body
    assert "Unassigned" in body
    # The list ends in the severities that do not burn the page.
    assert '<span class="sv">Low</span>' in rows[-1]
    assert "Page 1 of 1 &middot; 16 issues" in body


def test_table_partial_leaves_the_search_box_alone(client: TestClient, engine: Engine) -> None:
    """Typing swaps only the table: no input, no sidebar, no page chrome.

    The input lives outside this fragment, so the caret and everything typed
    so far survive every keystroke.
    """
    _signed_in_admin(client, engine, "issuespartial")
    body = client.get(ISSUES, headers=HX_TABLE).text

    assert "<html" not in body
    assert 'class="topbar"' not in body
    assert 'id="issue-search-text"' not in body
    assert "<h3>Status</h3>" not in body
    assert '<table class="t">' in body
    assert _row_count(body) == 16


def test_body_partial_swaps_mirrors_sidebar_and_table_together(
    client: TestClient, engine: Engine
) -> None:
    _signed_in_admin(client, engine, "issuesbody")
    body = client.get(f"{ISSUES}?status=open", headers=HX_BODY).text

    assert 'class="topbar"' not in body
    assert 'id="issue-search-text"' in body
    assert "<h3>Status</h3>" in body
    # The filter state travels as a hidden field, re-rendered with the click.
    assert '<input type="hidden" name="status" value="open">' in body
    assert _row_count(body) == 11
    # No confirmed row survived - but the sidebar still lists Confirmed,
    # which is why the row check looks at the chip, not at the word.
    assert '<span class="c ok">Confirmed</span>' not in body


def test_filters_narrow_the_list(client: TestClient, engine: Engine) -> None:
    _signed_in_admin(client, engine, "issuesfilters")

    def rows(query: str) -> int:
        return _row_count(client.get(f"{ISSUES}{query}", headers=HX_TABLE).text)

    assert rows("?status=open") == 11
    assert rows("?status=confirmed") == 2
    assert rows("?severity=high") == 3
    assert rows("?tool=ruff") == 9
    assert rows("?tool=pip_audit") == 1
    assert rows("?category=secret") == 1
    assert rows("?presence=present") == 15
    # Two filters intersect instead of replacing each other.
    assert rows("?severity=high&tool=bandit") == 2
    assert rows("?text=hardcoded") == 2
    assert rows("?text=webhooks") == 2


def test_presence_filter_marks_the_leavers_without_hiding_them(
    client: TestClient, engine: Engine
) -> None:
    _signed_in_admin(client, engine, "issuespresence")
    body = client.get(f"{ISSUES}?presence=resolved").text

    rows = _rows_of(body)
    assert len(rows) == 1
    # An issue can be resolved while still open: both words are shown.
    assert "W605: invalid escape sequence" in rows[0]
    assert '<span class="c nt">Open</span>' in rows[0]
    assert ">Resolved</span>" in rows[0]


def test_the_search_box_reflects_its_text_escaped(client: TestClient, engine: Engine) -> None:
    _signed_in_admin(client, engine, "issuesescape")
    response = client.get(ISSUES, params={"text": "<script>alert(1)</script>"}, headers=HX_BODY)
    body = response.text
    assert 'value="&lt;script&gt;alert(1)&lt;/script&gt;"' in body
    assert "<script>alert(1)</script>" not in body
    assert "No issues match" in body


def test_a_percent_in_the_search_is_a_character_not_a_wildcard(
    client: TestClient, engine: Engine
) -> None:
    _signed_in_admin(client, engine, "issuespercent")
    body = client.get(f"{ISSUES}?text=%25", headers=HX_TABLE).text
    # Unescaped, LIKE would have matched every issue.
    assert _row_count(body) == 0
    assert "No issues match" in body


def test_pagination_keeps_the_size_and_says_where_the_end_is(
    client: TestClient, engine: Engine
) -> None:
    _signed_in_admin(client, engine, "issuespaging")
    page_two = client.get(f"{ISSUES}?per_page=5&page=2", headers=HX_TABLE).text
    assert _row_count(page_two) == 5
    assert "Page 2 of 4 &middot; 16 issues" in page_two
    # Previous drops the page it would land on; next keeps the page size.
    assert 'href="?per_page=5"' in page_two
    assert 'href="?page=3&amp;per_page=5"' in page_two

    # Past the end is explained, not mistaken for an empty project.
    past = client.get(f"{ISSUES}?page=99").text
    assert "That page is past the end" in past
    assert "<h3>No issues yet</h3>" not in past
    assert 'href="?"' in past


def test_facet_links_keep_every_filter_but_never_a_stale_search(
    client: TestClient, engine: Engine
) -> None:
    _signed_in_admin(client, engine, "issuesfacets")
    body = client.get(f"{ISSUES}?severity=high&text=B105", headers=HX_BODY).text

    # The mirrors re-state the active filter for the search box...
    assert '<input type="hidden" name="severity" value="high">' in body
    # ...the active facet wears the accent and links to switching itself off...
    assert 'href="?" hx-get="?" class="on" aria-current="true">High</a>' in body
    # ...another facet keeps the severity, and carries no text= at all: the
    # typed search rides along with the form on the next keystroke instead of
    # being frozen into a link rendered before you finished typing.
    assert 'href="?status=open&amp;severity=high"' in body
    # Clear filters drops the search you just typed, and it sits outside the
    # facet include so nothing can re-add the text it just cleared.
    assert '<a href="?" hx-get="?">Clear filters</a>' in body
    assert '<div hx-include="#issue-search-text, #issue-search-sort">' in body
    included = body.split('<div hx-include="#issue-search-text, #issue-search-sort">', 1)[1]
    assert "Clear filters" not in included.split("</div>", 1)[0]


def test_unknown_filters_are_refused_with_a_reason(client: TestClient, engine: Engine) -> None:
    _signed_in_admin(client, engine, "issuesbadfilter")
    for query, needle in (
        ("?status=bogus", "unknown status"),
        ("?severity=nope", "unknown severity"),
        ("?sort=nope", "unknown sort"),
        ("?page=0", "starts at 1"),
        ("?per_page=abc", "must be a whole number"),
        ("?assignee=me", "assignee must be a user id"),
    ):
        response = client.get(f"{ISSUES}{query}")
        assert response.status_code == 400, query
        assert needle in response.text


def test_unknown_and_ungranted_projects_answer_the_same_404(
    client: TestClient, engine: Engine
) -> None:
    seed_demo(engine)
    password = _signup(engine, "issuesoutsider")
    _login(client, "issuesoutsider", password)

    stranger = client.get(ISSUES)
    unknown = client.get("/projects/no-such-project/issues")
    assert stranger.status_code == 404
    assert unknown.status_code == 404
    # Same page, same wording: no hint about which of the two happened.
    assert "Project not found" in stranger.text
    assert "Project not found" in unknown.text


# --- the JSON API (section 12) ----------------------------------------------


def test_api_issues_list_is_sorted_and_shaped(client: TestClient, engine: Engine) -> None:
    _signed_in_admin(client, engine, "issuesapi")
    response = client.get(API_ISSUES, headers=_api_headers(client))
    assert response.status_code == 200
    payload = response.json()
    assert (payload["total"], payload["page"], payload["per_page"]) == (16, 1, 50)

    issues = payload["issues"]
    assert len(issues) == 16
    # Default sort: worst severity first.
    assert [item["severity"] for item in issues[:4]] == ["blocker", "high", "high", "high"]
    assert issues[0]["title"] == "Private Key"
    assert issues[0]["assignee"] is None
    # The one seeded assignment carries the person, not just an id.
    assigned = [item for item in issues if item["assignee"]]
    assert len(assigned) == 1
    assert assigned[0]["assignee"]["username"] == "demo-bob"
    assert assigned[0]["assignee"]["display_name"] == "Bob Okafor"
    # Section 12's shape: identity, place, state - no snippets, no fixes.
    assert set(issues[0]) == {
        "id",
        "title",
        "tool",
        "rule_id",
        "severity",
        "category",
        "file_path",
        "line_start",
        "line_end",
        "triage_status",
        "presence",
        "package",
        "vuln_id",
        "assignee",
        "first_seen_analysis_id",
        "last_seen_analysis_id",
    }


def test_api_filters_sort_and_pagination(client: TestClient, engine: Engine) -> None:
    _signed_in_admin(client, engine, "issuesapifilters")

    def total(query: str) -> tuple[int, list[dict[str, Any]]]:
        payload = client.get(f"{API_ISSUES}{query}", headers=_api_headers(client)).json()
        return payload["total"], payload["issues"]

    assert total("?status=open")[0] == 11
    assert total("?severity=high&tool=bandit")[0] == 2
    assert total("?presence=resolved")[0] == 1
    assert total("?category=secret")[0] == 1
    assert total("?text=hardcoded")[0] == 2
    assert total("?file=src/payments/webhooks.py")[0] == 1
    # Assignment: the one seeded row, and everyone else.
    assert total("?assignee=none")[0] == 15
    bob = _count(engine, "SELECT id FROM users WHERE username = 'demo-bob'")
    assert total(f"?assignee={bob}")[0] == 1

    # Sorting is real: alphabetical under whichever collation the database
    # speaks (some order case-blind, some case-first), not the default
    # severity order, which is what an ignored sort= would have returned.
    _, by_title = total("?sort=title")
    titles = [item["title"] for item in by_title]
    assert titles in (sorted(titles), sorted(titles, key=str.lower))

    # Paging past the end is an empty page, not an error: total is how a
    # client learns where the end is. An absurd page size is capped.
    past = client.get(f"{API_ISSUES}?page=99", headers=_api_headers(client)).json()
    assert past["issues"] == [] and past["total"] == 16
    capped = client.get(f"{API_ISSUES}?per_page=9999", headers=_api_headers(client)).json()
    assert capped["per_page"] == 200


def test_api_refuses_unknown_filter_values(client: TestClient, engine: Engine) -> None:
    _signed_in_admin(client, engine, "issuesapi422")
    response = client.get(f"{API_ISSUES}?status=bogus", headers=_api_headers(client))
    assert response.status_code == 422
    assert "unknown status" in response.json()["detail"]


def test_api_issues_needs_a_session_and_a_grant(client: TestClient, engine: Engine) -> None:
    assert client.get(API_ISSUES).status_code == 401

    seed_demo(engine)
    password = _signup(engine, "issuesapoutsider")
    _login(client, "issuesapoutsider", password)
    # No grants: a project you may not browse is indistinguishable from one
    # that does not exist (section 7).
    assert client.get(API_ISSUES, headers=_api_headers(client)).status_code == 404
    unknown = client.get("/api/v1/projects/nope/issues", headers=_api_headers(client))
    assert unknown.status_code == 404


# --- the parser behind both (no database needed) ---------------------------


def test_issue_filters_parse_validate_and_build_links() -> None:
    filters = IssueFilters.from_query(
        [("status", "open"), ("text", "hardcoded"), ("sort", "title"), ("page", "3")]
    )
    # Dropping one filter keeps the rest; unset values are omitted so links
    # and the address bar stay short.
    assert filters.params(status=None) == {"text": "hardcoded", "sort": "title", "page": "3"}
    assert IssueFilters.from_query([("sort", "severity")]).params() == {}
    # The first occurrence wins: a link's own value beats a stale mirror.
    assert IssueFilters.from_query([("status", "open"), ("status", "confirmed")]).status == "open"
    # A big page size is clamped; a nonsense one is refused.
    assert IssueFilters.from_query([("per_page", "1000000")]).per_page == 200
    with pytest.raises(BadIssueFilter, match="starts at 1"):
        IssueFilters.from_query([("page", "0")])
    with pytest.raises(BadIssueFilter, match="unknown status"):
        IssueFilters.from_query([("status", "bogus")])
    with pytest.raises(BadIssueFilter, match="whole number"):
        IssueFilters.from_query([("per_page", "lots")])
    with pytest.raises(BadIssueFilter, match="assignee must be"):
        IssueFilters.from_query([("assignee", "me")])
    # A typo in a link builder is a bug, not an empty page.
    with pytest.raises(ValueError, match="not a filter"):
        filters.params(bogus="1")
