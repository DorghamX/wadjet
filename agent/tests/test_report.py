"""Summary table, gate verdict and the report file (section 11, step 8)."""

from __future__ import annotations

import json
from pathlib import Path

from wadjet_agent.report import dashboard_url, failing_conditions, print_summary, write_report
from wadjet_schema import AnalysisResult, AnalysisUpload, Finding, Severity


def make_upload() -> AnalysisUpload:
    findings = [
        Finding(
            tool="bandit",
            rule_id="B602",
            severity=Severity.critical,
            category="bug",
            title="shell=True",
            message="subprocess call with shell=True",
            file_path="app.py",
            line_start=3,
            line_end=3,
            snippet="subprocess.run(x, shell=True)",
        ),
        Finding(
            tool="bandit",
            rule_id="B101",
            severity=Severity.low,
            category="bug",
            title="Assert used",
            message="assert statement found",
            file_path="app.py",
            line_start=9,
            line_end=9,
            snippet="assert x",
        ),
        Finding(
            tool="pip_audit",
            rule_id="CVE-2018-18074",
            severity=Severity.high,
            category="dependency",
            title="requests 2.19.0: CVE-2018-18074",
            message="Authorization header leak",
            file_path=None,
            line_start=0,
            line_end=0,
            snippet="",
        ),
    ]
    return AnalysisUpload(
        project_key="demo",
        commit_sha="abc",
        ci_url=None,
        findings=findings,
        metrics={},
        scanner_runs={},
    )


def make_result(status: str) -> AnalysisResult:
    return AnalysisResult(
        analysis_id="7",
        gate_status=status,
        gate_details={
            "conditions": [
                {
                    "metric": "coverage_line_percent",
                    "operator": "<",
                    "threshold": 70.0,
                    "actual": 42.5,
                    "triggered": status != "passed",
                },
                {
                    "metric": "secrets",
                    "operator": ">",
                    "threshold": 0.0,
                    "actual": 0.0,
                    "triggered": False,
                },
            ]
        },
        issues_resolved=2,
        issues_created=5,
    )


def test_failing_conditions_are_only_the_triggered_ones() -> None:
    failing = failing_conditions(make_result("failed"))
    assert len(failing) == 1
    assert failing[0]["metric"] == "coverage_line_percent"
    assert failing_conditions(make_result("passed")) == []


def test_dashboard_url() -> None:
    assert dashboard_url("https://wadjet.example/", "demo") == (
        "https://wadjet.example/projects/demo"
    )


def test_print_summary_shows_table_verdict_and_link() -> None:
    lines: list[str] = []
    print_summary(make_upload(), make_result("failed"), "https://wadjet.example", out=lines.append)
    text = "\n".join(lines)
    assert "Analysis 7 for demo" in text
    assert "critical" in text and "low" in text and "high" in text
    assert "bandit" in text and "pip_audit" in text
    assert "created 5 new issue(s), resolved 2" in text
    assert "GATE: FAILED - failing conditions:" in text
    assert "fail when coverage_line_percent < 70.0 (actual: 42.5)" in text
    assert "https://wadjet.example/projects/demo" in text
    # A passing gate shows no failing conditions.
    passed: list[str] = []
    print_summary(make_upload(), make_result("passed"), "https://x", out=passed.append)
    assert "GATE: PASSED" in "\n".join(passed)


def test_write_report_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "wadjet-report.json"
    write_report(path, make_upload(), make_result("failed"), "https://wadjet.example")
    payload = json.loads(path.read_text())
    assert payload["project_key"] == "demo"
    assert payload["analysis"]["gate_status"] == "failed"
    assert payload["dashboard_url"] == "https://wadjet.example/projects/demo"
    assert len(payload["findings"]) == 3
    assert payload["findings"][0]["severity"] == "critical"


def test_print_summary_shows_coverage_and_condition_reason() -> None:
    """T3.1: the coverage metric line, and the gate's "no coverage report"
    reason instead of a bare (actual: None)."""
    upload = make_upload().model_copy(update={"metrics": {"coverage_line_percent": 91.4}})
    result = AnalysisResult(
        analysis_id="9",
        gate_status="failed",
        gate_details={
            "conditions": [
                {
                    "metric": "coverage_line_percent",
                    "operator": "<",
                    "threshold": 70.0,
                    "actual": None,
                    "triggered": True,
                    "reason": "no coverage report",
                }
            ]
        },
        issues_resolved=0,
        issues_created=0,
    )
    lines: list[str] = []
    print_summary(upload, result, "https://x", out=lines.append)
    text = "\n".join(lines)
    assert "coverage: 91.4%" in text
    assert "fail when coverage_line_percent < 70.0 (no coverage report)" in text
    assert "actual: None" not in text
