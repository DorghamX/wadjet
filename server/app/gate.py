"""Quality gate evaluation (section 9).

A gate is a named list of conditions written as "fail when": ``metric
operator threshold``. Metrics are computed over the whole scope: issues with
``presence=present`` and ``triage_status`` in (``open``, ``confirmed``) -
false positive, accepted risk and won't fix are excluded.

Result: ``passed`` only if no condition triggered and the analysis is
complete. Store per condition: actual value, threshold, triggered.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Connection, text

#: Triage statuses that still count towards the gate (section 9).
COUNTED_STATUSES = ("open", "confirmed")

#: The metric names of section 9 that are computed from the issue table.
ISSUE_METRICS = (
    "issues_total",
    "issues_blocker",
    "issues_critical",
    "issues_high",
    "issues_medium",
    "issues_low",
    "vulnerabilities",
    "secrets",
    "dependency_vulns",
    "dependency_vulns_with_fix",
    "bugs",
    "code_smells",
)

#: Every metric a condition may name (section 9); coverage comes from the upload.
ALL_METRICS = ISSUE_METRICS + ("coverage_line_percent",)

#: The operators section 9 accepts.
OPERATORS = (">", ">=", "<", "<=", "==")

METRIC_SQL = """
SELECT
    COUNT(*)::int AS issues_total,
    COUNT(*) FILTER (WHERE severity = 'blocker')::int AS issues_blocker,
    COUNT(*) FILTER (WHERE severity = 'critical')::int AS issues_critical,
    COUNT(*) FILTER (WHERE severity = 'high')::int AS issues_high,
    COUNT(*) FILTER (WHERE severity = 'medium')::int AS issues_medium,
    COUNT(*) FILTER (WHERE severity = 'low')::int AS issues_low,
    COUNT(*) FILTER (WHERE category = 'vulnerability')::int AS vulnerabilities,
    COUNT(*) FILTER (WHERE category = 'secret')::int AS secrets,
    COUNT(*) FILTER (WHERE category = 'dependency')::int AS dependency_vulns,
    COUNT(*) FILTER (
        WHERE category = 'dependency'
          AND fixed_versions IS NOT NULL
          AND jsonb_array_length(fixed_versions) > 0
    )::int AS dependency_vulns_with_fix,
    COUNT(*) FILTER (WHERE category = 'bug')::int AS bugs,
    COUNT(*) FILTER (WHERE category = 'code_smell')::int AS code_smells
FROM issues
WHERE project_id = :pid
  AND presence = 'present'
  AND triage_status IN ('open', 'confirmed')
"""


def compute_issue_metrics(conn: Connection, project_id: int) -> dict[str, float]:
    """Every section-9 metric that comes from the issue table.

    Scoped to one project: a gate never sees another project's issues.
    """
    row = conn.execute(text(METRIC_SQL), {"pid": project_id}).mappings().one()
    return {name: float(row[name]) for name in ISSUE_METRICS}


def _compare(actual: float, operator: str, threshold: float) -> bool:
    """Whether a condition triggers for a known actual value."""
    if operator == ">":
        return actual > threshold
    if operator == ">=":
        return actual >= threshold
    if operator == "<":
        return actual < threshold
    if operator == "<=":
        return actual <= threshold
    if operator == "==":
        return actual == threshold
    # Unknown operator: fail closed rather than pass silently.
    return True


def evaluate_conditions(
    conditions: list[dict[str, Any]], metrics: dict[str, float]
) -> list[dict[str, Any]]:
    """Evaluate every condition, one detail row each (section 9).

    Two special cases, both fail-closed:

    - ``coverage_line_percent`` with no report in the upload triggers with
      ``reason: "no coverage report"`` (section 6 coverage row) - a gate that
      asks for coverage must see a report, otherwise \"no data\" would read as
      green.
    - Any other metric this analysis does not produce shows as null and does
      not trigger (the UI gate builder only offers the section 9 list, so an
      absent name is a stale copy, not a promise to enforce).
    """
    details: list[dict[str, Any]] = []
    for condition in conditions:
        metric = str(condition["metric"])
        operator = str(condition["operator"])
        threshold = float(condition["threshold"])
        actual = metrics.get(metric)
        if actual is None:
            triggered = metric == "coverage_line_percent"
        else:
            triggered = _compare(actual, operator, threshold)
        detail: dict[str, Any] = {
            "metric": metric,
            "operator": operator,
            "threshold": threshold,
            "actual": actual,
            "triggered": triggered,
        }
        if triggered and actual is None:
            detail["reason"] = "no coverage report"
        details.append(detail)
    return details


def load_gate_conditions(conn: Connection, project_id: int) -> list[dict[str, Any]]:
    """The conditions of the gate the project uses (section 9: exactly one).

    A project that has never chosen a gate falls back to the built-in
    default (migration 0008), so every analysis is judged by something.
    """
    rows = conn.execute(
        text(
            "SELECT gc.metric, gc.operator, gc.threshold "
            "FROM gate_conditions gc "
            "JOIN projects p ON gc.gate_id = COALESCE("
            "    p.gate_id,"
            "    (SELECT id FROM quality_gates WHERE is_default ORDER BY id LIMIT 1)"
            ") "
            "WHERE p.id = :pid "
            "ORDER BY gc.id"
        ),
        {"pid": project_id},
    ).fetchall()
    return [{"metric": row[0], "operator": row[1], "threshold": float(row[2])} for row in rows]


def scanner_errors_fail_gate(settings: dict[str, Any]) -> bool:
    """The section 6 failure policy flag: default true, fail closed.

    Anything but an explicit ``false`` in the stored settings means a
    scanner error fails the gate.
    """
    value = settings.get("fail_on_scanner_error", True)
    return value if isinstance(value, bool) else True


def evaluate_gate(
    conn: Connection,
    project_id: int,
    *,
    analysis_status: str,
    uploaded_metrics: dict[str, Any],
    fail_on_scanner_error: bool = True,
    issue_metrics: dict[str, float] | None = None,
) -> tuple[str, list[dict[str, Any]], dict[str, float]]:
    """Evaluate the project's gate for a freshly ingested analysis.

    Returns ``(gate_status, condition_details, metrics)`` where ``metrics``
    merges the computed issue metrics with the uploaded ones (coverage line
    percent comes from the agent's coverage step).

    An incomplete analysis always gets the synthetic
    ``all_scanners_completed`` row; the ``fail_on_scanner_error`` setting
    (section 6, default true) decides whether that row *fails* the gate -
    with the default, incomplete never passes, which is section 9's
    "passed only if ... the analysis is complete". A project may opt out;
    the analysis stays ``incomplete`` and never resolves issues either way.

    ``issue_metrics`` overrides the computed metrics: ``seed-demo`` passes
    each historical analysis' own counts, so past gate results stay honest
    instead of being recomputed from today's issues.
    """
    metrics = (
        dict(issue_metrics)
        if issue_metrics is not None
        else compute_issue_metrics(conn, project_id)
    )
    coverage = uploaded_metrics.get("coverage_line_percent")
    if isinstance(coverage, (int, float)):
        metrics["coverage_line_percent"] = float(coverage)

    details = evaluate_conditions(load_gate_conditions(conn, project_id), metrics)
    if analysis_status != "complete":
        details.insert(
            0,
            {
                "metric": "all_scanners_completed",
                "operator": "==",
                "threshold": 1,
                "actual": 0,
                "triggered": fail_on_scanner_error,
            },
        )
    triggered = any(detail["triggered"] for detail in details)
    status = "passed" if not triggered else "failed"
    return status, details, metrics
