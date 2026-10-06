"""Summary table, gate verdict with failing conditions, and the report file
(section 11, steps 8)."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from wadjet_schema import AnalysisResult, AnalysisUpload

#: Display order for the summary table (section 9 severities plus info).
SEVERITY_ORDER = ("blocker", "critical", "high", "medium", "low", "info")


def failing_conditions(result: AnalysisResult) -> list[dict[str, Any]]:
    """The conditions that triggered, worst structure preserved (section 9)."""
    conditions = result.gate_details.get("conditions") or []
    return [item for item in conditions if isinstance(item, dict) and item.get("triggered")]


def dashboard_url(base_url: str, project_key: str) -> str:
    """Where humans look at this analysis (built agent-side: the frozen
    AnalysisResult contract carries no URL)."""
    return f"{base_url.rstrip('/')}/projects/{project_key}"


def print_summary(
    upload: AnalysisUpload,
    result: AnalysisResult,
    base_url: str,
    out: Callable[[str], None] = print,
) -> None:
    """Print the table, the verdict with failing conditions, and the link."""
    severity_counts: Counter[str] = Counter(finding.severity.value for finding in upload.findings)
    tool_counts: Counter[str] = Counter(finding.tool for finding in upload.findings)

    out("")
    out(f"Analysis {result.analysis_id} for {upload.project_key}")
    out("")
    out("  severity   findings")
    for severity in SEVERITY_ORDER:
        if severity_counts.get(severity):
            out(f"  {severity:<9} {severity_counts[severity]:>9}")
    if not severity_counts:
        out("  (no findings)")
    out("")
    out("  tool        findings")
    for tool in sorted(tool_counts):
        out(f"  {tool:<10} {tool_counts[tool]:>9}")
    out("")
    coverage = upload.metrics.get("coverage_line_percent")
    if isinstance(coverage, (int, float)):
        out(f"  coverage: {coverage:.1f}%")
        out("")
    out(f"  created {result.issues_created} new issue(s), resolved {result.issues_resolved}")
    out("")

    if result.gate_status == "passed":
        out("  GATE: PASSED")
    else:
        out("  GATE: FAILED - failing conditions:")
        failing = failing_conditions(result)
        if not failing:
            out("    (no condition triggered; the analysis itself is incomplete)")
        for condition in failing:
            metric = condition.get("metric")
            operator = condition.get("operator")
            threshold = condition.get("threshold")
            actual = condition.get("actual")
            reason = condition.get("reason")
            if reason:
                out(f"    fail when {metric} {operator} {threshold} ({reason})")
            else:
                out(f"    fail when {metric} {operator} {threshold} (actual: {actual})")
    out("")
    out(f"  {dashboard_url(base_url, upload.project_key)}")
    out("")


def write_report(path: Path, upload: AnalysisUpload, result: AnalysisResult, base_url: str) -> None:
    """Write ``wadjet-report.json``-style output for CI artifacts."""
    payload = {
        "project_key": upload.project_key,
        "commit_sha": upload.commit_sha,
        "ci_url": upload.ci_url,
        "analysis": result.model_dump(),
        "scanner_runs": upload.scanner_runs,
        "metrics": upload.metrics,
        "dashboard_url": dashboard_url(base_url, upload.project_key),
        "findings": [finding.model_dump(mode="json") for finding in upload.findings],
    }
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
