"""Unit tests for matching and lifecycle (sections 5.3-5.4, T2.2).

The six scenarios the guide calls out: line shift, file move, edited flagged
line, duplicate identical lines, resolved then reappearing, and an incomplete
analysis resolving nothing.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.fingerprint import compute_fingerprints
from app.lifecycle import (
    RULE_EXACT,
    RULE_MOVED,
    RULE_NEW,
    RULE_SAME_LINES,
    ExistingIssue,
    LifecyclePlan,
    plan_lifecycle,
)
from wadjet_schema import Category, Finding, Severity

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)

SNIPPET = "\n".join(
    [
        "import os",
        "import sys",
        "value = 1",
        "assert value",  # flagged (line 10)
        "print(value)",
        "print('a')",
        "print('b')",
    ]
)


def make_finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "tool": "bandit",
        "rule_id": "B101",
        "severity": Severity.medium,
        "category": Category.bug,
        "title": "assert used",
        "message": "assert statement",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 10,
        "snippet": SNIPPET,
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def computed(findings: list[Finding], project_key: str = "demo"):
    """Fingerprints for one analysis, as ingest would compute them."""
    return compute_fingerprints(project_key, findings)


def issue_from(computed_finding, **overrides: object) -> ExistingIssue:
    """A stored issue built from an incoming finding (as if ingested before)."""
    f = computed_finding.finding
    values: dict[str, object] = {
        "id": 1,
        "fingerprint": computed_finding.fingerprint,
        "tool": f.tool,
        "rule_id": f.rule_id,
        "category": f.category.value,
        "file_path": f.file_path,
        "snippet": f.snippet,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "triage_status": "open",
        "presence": "present",
        "first_seen_analysis_id": 1,
    }
    values.update(overrides)
    return ExistingIssue(**values)  # type: ignore[arg-type]


def plan_for(
    existing: list[ExistingIssue],
    findings: list[Finding],
    status: str = "complete",
    analysis_id: int = 2,
) -> LifecyclePlan:
    return plan_lifecycle(
        existing,
        computed(findings),
        analysis_id=analysis_id,
        analysis_status=status,
        now=NOW,
        extra_issue_fields={"last_seen_analysis_id": analysis_id},
    )


# --- 1. line shift ----------------------------------------------------------


def test_line_shift_preserves_the_flag() -> None:
    """Inserting lines at the top: exact match, line numbers updated."""
    (first,) = computed([make_finding()])
    stored = issue_from(first, triage_status="false_positive")

    shifted = make_finding(line_start=25, line_end=25)
    plan = plan_for([stored], [shifted])

    assert plan.creations == []
    assert len(plan.updates) == 1
    update = plan.updates[0]
    assert update.issue_id == 1
    assert update.fields["line_start"] == 25
    assert update.fields["line_end"] == 25
    assert "presence" not in update.fields  # still present, nothing to flip
    # triage untouched; the carried flag is announced
    assert "triage_status" not in update.fields
    assert [e.type for e in update.events] == ["flag_carried_over"]
    assert plan.resolutions == []


def test_line_shift_near_file_top_matches_with_rule_2() -> None:
    """When the leading context grows, the context half changes: rule 2."""
    short = "top = 1\nassert top"
    (first,) = computed([make_finding(snippet=short, line_start=2, line_end=2)])
    stored = issue_from(first)

    shifted_snippet = "new = 0\ntop = 1\nassert top"
    shifted = make_finding(snippet=shifted_snippet, line_start=3, line_end=3)
    plan = plan_for([stored], [shifted])

    assert plan.outcomes[0].rule == RULE_SAME_LINES
    assert plan.outcomes[0].existing is not None
    update = plan.updates[0]
    assert update.fields["line_start"] == 3
    assert update.fields["snippet"] == shifted_snippet
    # the stored issue adopts the new fingerprint so rule 1 hits next time
    assert update.fields["fingerprint"] == plan.outcomes[0].computed.fingerprint


# --- 2. file move -----------------------------------------------------------


def test_file_move_is_preserved() -> None:
    """Same code, new path, old path gone from the analysis: rule 3."""
    (first,) = computed([make_finding()])
    stored = issue_from(first, triage_status="confirmed")

    moved = make_finding(file_path="src/moved/app.py")
    plan = plan_for([stored], [moved])

    assert plan.outcomes[0].rule == RULE_MOVED
    assert plan.creations == []
    update = plan.updates[0]
    assert update.fields["file_path"] == "src/moved/app.py"
    assert update.fields["fingerprint"] == plan.outcomes[0].computed.fingerprint
    assert "triage_status" not in update.fields
    assert plan.resolutions == []


def test_old_path_still_scanned_is_not_a_move() -> None:
    """Rule 3 only fires when the old path has no findings in this analysis."""
    (first,) = computed([make_finding()])
    stored = issue_from(first)

    still_there = make_finding()
    moved = make_finding(file_path="src/other/app.py")
    plan = plan_for([stored], [still_there, moved])

    # The old path still reports: the moved copy is a new issue, and the
    # stored one stays exactly where it is.
    rules = [o.rule for o in plan.outcomes]
    assert rules == [RULE_EXACT, RULE_NEW]
    assert len(plan.creations) == 1
    assert "file_path" not in plan.updates[0].fields
    assert plan.resolutions == []


# --- 3. edited flagged line -------------------------------------------------


def test_edited_flagged_line_resolves_old_and_opens_new() -> None:
    """The flag belongs to the exact snippet: edit it and a new issue appears."""
    (first,) = computed([make_finding()])
    stored = issue_from(first, triage_status="confirmed")

    edited_snippet = SNIPPET.replace("assert value", "assert value is not None")
    edited = make_finding(snippet=edited_snippet)
    plan = plan_for([stored], [edited])

    assert plan.outcomes[0].rule == RULE_NEW
    assert len(plan.creations) == 1
    created = plan.creations[0]
    assert created.fields["triage_status"] == "open"
    assert created.fields["presence"] == "present"
    assert created.fields["fingerprint"] != stored.fingerprint
    assert [e.type for e in created.events] == ["created"]
    # the old issue is resolved by this complete analysis
    assert len(plan.resolutions) == 1
    assert plan.resolutions[0].issue_id == 1
    assert plan.resolutions[0].fields["presence"] == "resolved"
    assert plan.resolutions[0].fields["resolved_at"] == NOW
    assert [e.type for e in plan.resolutions[0].events] == ["resolved_by_scan"]


# --- 4. duplicate identical lines -------------------------------------------


def test_duplicate_identical_lines_stay_two_issues() -> None:
    """Two identical flagged lines match their own occurrence, not each other."""
    low = make_finding(line_start=10, line_end=10)
    high = make_finding(line_start=40, line_end=40)
    incoming = computed([low, high])

    stored_low = issue_from(incoming[0], id=1)
    stored_high = issue_from(incoming[1], id=2)

    plan = plan_lifecycle(
        [stored_high, stored_low],
        incoming,
        analysis_id=2,
        analysis_status="complete",
        now=NOW,
    )

    assert [o.rule for o in plan.outcomes] == [RULE_EXACT, RULE_EXACT]
    assert plan.creations == []
    assert {u.issue_id for u in plan.updates} == {1, 2}
    assert plan.resolutions == []


def test_duplicate_lines_in_one_upload_create_two_issues() -> None:
    """First upload: both duplicates are created, distinct fingerprints."""
    low = make_finding(line_start=10, line_end=10)
    high = make_finding(line_start=40, line_end=40)
    plan = plan_lifecycle(
        [], computed([low, high]), analysis_id=1, analysis_status="complete", now=NOW
    )
    assert len(plan.creations) == 2
    fingerprints = {c.fields["fingerprint"] for c in plan.creations}
    assert len(fingerprints) == 2


# --- 5. resolved then reappearing --------------------------------------------


def test_resolved_issue_reappears_with_triage_preserved() -> None:
    """Seen again: presence=present, reopened_by_scan, triage intact."""
    (first,) = computed([make_finding()])
    stored = issue_from(
        first,
        presence="resolved",
        triage_status="accepted_risk",
        first_seen_analysis_id=7,
    )

    plan = plan_for([stored], [make_finding()], analysis_id=9)

    assert plan.outcomes[0].rule == RULE_EXACT
    update = plan.updates[0]
    assert update.fields["presence"] == "present"
    assert update.fields["resolved_at"] is None
    assert "triage_status" not in update.fields
    event_types = [e.type for e in update.events]
    assert "reopened_by_scan" in event_types
    assert "flag_carried_over" in event_types
    carried = next(e for e in update.events if e.type == "flag_carried_over")
    assert carried.payload["first_seen_analysis"] == 7
    assert plan.resolutions == []


def test_already_resolved_issue_stays_resolved_when_absent() -> None:
    """No repeated resolution events for an issue that is already resolved."""
    (first,) = computed([make_finding()])
    stored = issue_from(first, presence="resolved")

    plan = plan_for([stored], [], status="complete")

    assert plan.resolutions == []
    assert plan.updates == []
    assert plan.creations == []


# --- 6. incomplete analysis resolves nothing ---------------------------------


def test_incomplete_analysis_resolves_nothing() -> None:
    """An incomplete analysis never resolves an unseen issue (section 5.4)."""
    (first,) = computed([make_finding()])
    stored = issue_from(first, presence="present")

    plan = plan_for([stored], [], status="incomplete")

    assert plan.resolutions == []
    assert plan.updates == []
    assert plan.creations == []


def test_incomplete_analysis_still_matches_and_creates() -> None:
    """Partial results still feed the dashboard: matches and sightings land."""
    (first,) = computed([make_finding()])
    stored = issue_from(first, presence="resolved")

    seen_again = make_finding()
    brand_new = make_finding(
        file_path="src/other.py",
        rule_id="B102",
        snippet=SNIPPET.replace("assert value", "subprocess.call(x)"),
    )
    plan = plan_for([stored], [seen_again, brand_new], status="incomplete")

    assert plan.outcomes[0].rule == RULE_EXACT
    assert plan.outcomes[1].rule == RULE_NEW
    assert plan.updates[0].fields["presence"] == "present"
    assert len(plan.creations) == 1
    # nothing unseen is resolved by an incomplete analysis
    assert plan.resolutions == []


# --- carried flags -----------------------------------------------------------


def test_carrying_a_flag_logs_flag_carried_over_every_analysis() -> None:
    """Non-open triage survives and is announced on every match (5.3)."""
    (first,) = computed([make_finding()])
    stored = issue_from(first, triage_status="wont_fix", first_seen_analysis_id=3)

    plan = plan_for([stored], [make_finding()], analysis_id=11)

    carried = [e for e in plan.updates[0].events if e.type == "flag_carried_over"]
    assert len(carried) == 1
    assert carried[0].payload["status"] == "wont_fix"
    assert carried[0].payload["analysis"] == 11
