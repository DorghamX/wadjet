"""Matching an upload to existing issues, and issue lifecycle (sections 5.3, 5.4).

Pure functions: sequences in, a plan out. No database, no clock (``now`` is a
parameter), no I/O. The ingest endpoint (T2.4) is the only thing that applies a
plan to the database, inside the same transaction as the analysis row.

Matching, each existing issue at most once, in order (section 5.3):

1. Exact fingerprint.
2. Same tool, rule_id, file_path and identical norm(flagged), but different
   context (nearby code changed): match, update context hash and line numbers.
3. File moved: same tool, rule_id, norm(flagged) and context hash, different
   file_path, and the old path has no findings in this analysis: match,
   update path.
4. Otherwise create a new issue (``triage_status=open``).

Lifecycle (section 5.4):

- Not seen in a *complete* analysis: ``presence=resolved``, event
  ``resolved_by_scan``. An incomplete analysis never resolves anything.
- Seen again: ``presence=present``, event ``reopened_by_scan``; triage is
  preserved.
- A match carrying a non-open triage status keeps it and logs
  ``flag_carried_over``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from app.fingerprint import (
    DEPENDENCY_CATEGORY,
    ComputedFinding,
    context_norm_hash,
    normalize_text,
    sha256_hex,
    split_snippet,
)

#: Match rules, in the order the guide tries them.
RULE_EXACT = "exact"
RULE_SAME_LINES = "same_lines"
RULE_MOVED = "moved"
RULE_NEW = "new"


@dataclass(frozen=True)
class ExistingIssue:
    """The stored state of one persistent issue, as the matcher sees it."""

    id: int
    fingerprint: str
    tool: str
    rule_id: str
    category: str
    file_path: str | None
    snippet: str | None
    line_start: int | None
    line_end: int | None
    triage_status: str
    presence: str
    first_seen_analysis_id: int | None = None


@dataclass(frozen=True)
class MatchOutcome:
    """One incoming finding and the issue it was matched to (or ``None``)."""

    computed: ComputedFinding
    existing: ExistingIssue | None
    rule: str


@dataclass(frozen=True)
class Event:
    """An issue timeline entry to append (section 4: issue_events)."""

    type: str
    payload: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class IssueUpdate:
    """An existing issue to update, with the events that go with it."""

    issue_id: int
    fields: dict[str, object]
    events: list[Event]


@dataclass(frozen=True)
class IssueCreation:
    """A brand new issue to insert (triage_status defaults to open)."""

    computed: ComputedFinding
    fields: dict[str, object]
    events: list[Event]


@dataclass(frozen=True)
class LifecyclePlan:
    """Everything one analysis does to the issue table."""

    creations: list[IssueCreation]
    updates: list[IssueUpdate]
    resolutions: list[IssueUpdate]
    outcomes: list[MatchOutcome]

    @property
    def created_count(self) -> int:
        return len(self.creations)


def _existing_flagged_and_context(issue: ExistingIssue) -> tuple[str, str]:
    """Re-derive ``norm(flagged)`` and the context hash of a stored issue."""
    flagged, context = split_snippet(issue.snippet, issue.line_start, issue.line_end)
    return normalize_text(flagged), context_norm_hash(context)


def match_findings(
    existing: Sequence[ExistingIssue],
    incoming: Sequence[ComputedFinding],
) -> list[MatchOutcome]:
    """Pair every incoming finding with an existing issue, or ``None``.

    Rules are applied in order across the whole upload: first every exact
    fingerprint hit, then same-lines, then moves.  Each existing issue is
    matched at most once.
    """
    free = {issue.id: issue for issue in existing}
    outcomes: dict[int, MatchOutcome] = {}

    def take(issue: ExistingIssue, index: int, rule: str) -> bool:
        if issue.id not in free:
            return False
        del free[issue.id]
        outcomes[index] = MatchOutcome(computed=incoming[index], existing=issue, rule=rule)
        return True

    # Rule 1: exact fingerprint.
    by_fingerprint: dict[str, list[ExistingIssue]] = {}
    for issue in existing:
        by_fingerprint.setdefault(issue.fingerprint, []).append(issue)
    for index, computed in enumerate(incoming):
        for candidate in by_fingerprint.get(computed.fingerprint, []):
            if take(candidate, index, RULE_EXACT):
                break

    # Rule 2: same tool, rule, path and flagged lines, different context.
    by_lines: dict[tuple[str, str, str | None, str], list[ExistingIssue]] = {}
    for issue in free.values():
        if issue.category == DEPENDENCY_CATEGORY or not issue.snippet:
            continue
        flagged_norm, _ = _existing_flagged_and_context(issue)
        key = (issue.tool, issue.rule_id, issue.file_path, flagged_norm)
        by_lines.setdefault(key, []).append(issue)
    for index, computed in enumerate(incoming):
        if index in outcomes or computed.is_dependency:
            continue
        candidates = by_lines.get(
            (
                computed.finding.tool,
                computed.finding.rule_id,
                computed.finding.file_path,
                computed.flagged_norm,
            )
        )
        if candidates:
            for candidate in sorted(candidates, key=lambda i: i.id):
                if take(candidate, index, RULE_SAME_LINES):
                    break

    # Rule 3: the file moved, and the old path has no findings this time.
    paths_this_analysis = {c.finding.file_path for c in incoming if c.finding.file_path}
    by_move: dict[tuple[str, str, str], list[ExistingIssue]] = {}
    for issue in free.values():
        if issue.category == DEPENDENCY_CATEGORY or not issue.snippet:
            continue
        flagged_norm, context_hash = _existing_flagged_and_context(issue)
        move_key = (issue.tool, issue.rule_id, flagged_norm)
        by_move.setdefault(move_key, []).append(issue)
    for index, computed in enumerate(incoming):
        if index in outcomes or computed.is_dependency:
            continue
        finding = computed.finding
        if not finding.file_path:
            continue
        for candidate in sorted(
            by_move.get((finding.tool, finding.rule_id, computed.flagged_norm), []),
            key=lambda i: i.id,
        ):
            if not candidate.file_path:
                continue
            if candidate.file_path == finding.file_path:
                continue  # same path was rule 2's business
            if candidate.file_path in paths_this_analysis:
                continue  # the old path still has findings: not a move
            if _existing_flagged_and_context(candidate)[1] != computed.context_hash:
                continue
            if take(candidate, index, RULE_MOVED):
                break

    # Rule 4: everything left is a new issue.
    return [
        outcomes.get(
            index,
            MatchOutcome(computed=computed, existing=None, rule=RULE_NEW),
        )
        for index, computed in enumerate(incoming)
    ]


def plan_lifecycle(
    existing: Sequence[ExistingIssue],
    incoming: Sequence[ComputedFinding],
    *,
    analysis_id: int,
    analysis_status: str,
    now: datetime,
    extra_issue_fields: dict[str, object] | None = None,
) -> LifecyclePlan:
    """Turn one upload into creations, updates and resolutions.

    ``analysis_status`` is ``complete`` or ``incomplete``: only a complete
    analysis may resolve an issue that was not seen (section 5.4).
    ``extra_issue_fields`` lets the caller add columns the pure layer does not
    know about (project_id, last_seen_analysis_id and so on).
    """
    extra = dict(extra_issue_fields or {})
    outcomes = match_findings(existing, incoming)
    matched_ids = {o.existing.id for o in outcomes if o.existing is not None}

    creations: list[IssueCreation] = []
    updates: list[IssueUpdate] = []

    for outcome in outcomes:
        computed = outcome.computed
        finding = computed.finding
        if outcome.existing is None:
            fields: dict[str, object] = {
                "fingerprint": computed.fingerprint,
                "tool": finding.tool,
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "category": finding.category.value,
                "title": finding.title,
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
                "snippet": finding.snippet,
                "snippet_norm_hash": (
                    sha256_hex(computed.flagged_norm) if computed.flagged_norm else None
                ),
                "package": finding.package,
                "vuln_id": finding.vuln_id,
                "installed_version": finding.installed_version,
                "fixed_versions": list(finding.fixed_versions),
                "cwe": finding.cwe,
                "description": finding.message,
                "triage_status": "open",
                "presence": "present",
                "first_seen_analysis_id": analysis_id,
                "last_seen_analysis_id": analysis_id,
            }
            fields.update(extra)
            creations.append(
                IssueCreation(
                    computed=computed,
                    fields=fields,
                    events=[Event("created", {"analysis": analysis_id})],
                )
            )
            continue

        issue = outcome.existing
        fields = {}
        events: list[Event] = []

        # Rules 2 and 3: the stored issue adopts the new identity pieces.
        if computed.fingerprint != issue.fingerprint:
            fields["fingerprint"] = computed.fingerprint
        if finding.file_path != issue.file_path:
            fields["file_path"] = finding.file_path
        if finding.line_start != issue.line_start:
            fields["line_start"] = finding.line_start
        if finding.line_end != issue.line_end:
            fields["line_end"] = finding.line_end
        if finding.snippet != issue.snippet:
            fields["snippet"] = finding.snippet
            fields["snippet_norm_hash"] = (
                sha256_hex(computed.flagged_norm) if computed.flagged_norm else None
            )
        fields["last_seen_analysis_id"] = analysis_id

        # Seen again: back to present, triage preserved (section 5.4).
        if issue.presence == "resolved":
            fields["presence"] = "present"
            fields["resolved_at"] = None
            events.append(Event("reopened_by_scan", {"analysis": analysis_id}))

        # A carried flag stays carried, and the timeline says so.
        if issue.triage_status != "open":
            events.append(
                Event(
                    "flag_carried_over",
                    {
                        "analysis": analysis_id,
                        "status": issue.triage_status,
                        "first_seen_analysis": issue.first_seen_analysis_id,
                    },
                )
            )

        fields.update(extra)
        updates.append(IssueUpdate(issue_id=issue.id, fields=fields, events=events))

    # Resolution: only a complete analysis, only issues still present.
    resolutions: list[IssueUpdate] = []
    if analysis_status == "complete":
        for issue in existing:
            if issue.id in matched_ids or issue.presence != "present":
                continue
            resolutions.append(
                IssueUpdate(
                    issue_id=issue.id,
                    fields={"presence": "resolved", "resolved_at": now},
                    events=[Event("resolved_by_scan", {"analysis": analysis_id})],
                )
            )

    return LifecyclePlan(
        creations=creations,
        updates=updates,
        resolutions=resolutions,
        outcomes=outcomes,
    )


def matched_pairs(outcomes: Iterable[MatchOutcome]) -> list[tuple[int, int]]:
    """(incoming index, issue id) pairs - a compact view for tests and logs."""
    return [
        (index, outcome.existing.id)
        for index, outcome in enumerate(outcomes)
        if outcome.existing is not None
    ]
