"""Coverage report parsing: metrics only, warnings never failures (T3.1)."""

from __future__ import annotations

import json
from pathlib import Path

from wadjet_agent.adapters.base import RunContext
from wadjet_agent.coverage_report import (
    FILE_PREFIX,
    OVERALL_KEY,
    collect_coverage_metrics,
    configured_report,
)

#: Trimmed from a real `coverage json` run (coverage 7.16.2).
JSON_REPORT = {
    "meta": {"format": 3, "version": "7.16.2"},
    "files": {
        "app.py": {"summary": {"percent_covered": 33.333333333333336}},
        "src/lib.py": {"summary": {"percent_covered": 100.0}},
    },
    "totals": {"covered_lines": 2, "num_statements": 6, "percent_covered": 50.0},
}

#: Trimmed from a real `coverage xml` run (coverage 7.16.2): two of six
#: lines hit, one class, line elements carry the truth.
XML_REPORT = """<?xml version="1.0" ?>
<coverage version="7.16.2" timestamp="1" lines-valid="6" lines-covered="2"
          line-rate="0.3333" branches-covered="0" branches-valid="0"
          branch-rate="0" complexity="0">
	<sources>
		<source>/repo</source>
	</sources>
	<packages>
		<package name="." line-rate="0.3333" branch-rate="0" complexity="0">
			<classes>
				<class name="app.py" filename="app.py" line-rate="0.3333" branch-rate="0">
					<methods/>
					<lines>
						<line number="1" hits="1"/>
						<line number="2" hits="0"/>
						<line number="3" hits="0"/>
						<line number="4" hits="0"/>
						<line number="7" hits="1"/>
						<line number="8" hits="0"/>
					</lines>
				</class>
			</classes>
		</package>
	</packages>
</coverage>
"""


def make_ctx(tmp_path: Path, settings: dict | None = None) -> RunContext:
    return RunContext(
        repo_root=tmp_path,
        include_paths=["."],
        exclusion_globs=[],
        python_executable="python3",
        settings=settings or {},
    )


def coverage_settings(report_path: str) -> dict:
    return {"scanners": {"coverage": {"report_path": report_path}}}


def test_not_configured_produces_no_metrics_and_no_warning(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    assert configured_report(ctx) is None
    assert collect_coverage_metrics(ctx) == ({}, None)


def test_disabled_scanner_is_treated_as_not_configured(tmp_path: Path) -> None:
    settings = {"scanners": {"coverage": {"enabled": False, "report_path": "coverage.json"}}}
    ctx = make_ctx(tmp_path, settings)
    assert configured_report(ctx) is None
    assert collect_coverage_metrics(ctx) == ({}, None)


def test_coverage_json_overall_and_per_file(tmp_path: Path) -> None:
    (tmp_path / "coverage.json").write_text(json.dumps(JSON_REPORT))
    ctx = make_ctx(tmp_path, coverage_settings("coverage.json"))

    metrics, warning = collect_coverage_metrics(ctx)
    assert warning is None
    assert metrics[OVERALL_KEY] == 50.0
    assert metrics[FILE_PREFIX + "app.py"] == 33.333333333333336
    assert metrics[FILE_PREFIX + "src/lib.py"] == 100.0
    # The gate metric is the only one section 9 knows; the rest are display.
    assert set(metrics) == {
        OVERALL_KEY,
        FILE_PREFIX + "app.py",
        FILE_PREFIX + "src/lib.py",
    }


def test_coverage_xml_overall_and_per_file(tmp_path: Path) -> None:
    (tmp_path / "coverage.xml").write_text(XML_REPORT)
    ctx = make_ctx(tmp_path, coverage_settings("coverage.xml"))

    metrics, warning = collect_coverage_metrics(ctx)
    assert warning is None
    # Exact line counts beat the rounded line-rate attribute.
    assert metrics[OVERALL_KEY] == 2 / 6 * 100.0
    assert metrics[FILE_PREFIX + "app.py"] == 2 / 6 * 100.0


def test_missing_report_warns_but_never_fails(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, coverage_settings("coverage.json"))
    metrics, warning = collect_coverage_metrics(ctx)
    assert metrics == {}
    assert warning == "coverage report not found: coverage.json"


def test_unsupported_and_malformed_reports_warn(tmp_path: Path) -> None:
    (tmp_path / "coverage.txt").write_text("nonsense")
    ctx = make_ctx(tmp_path, coverage_settings("coverage.txt"))
    warning = collect_coverage_metrics(ctx)[1]
    assert warning is not None and "unsupported coverage report format" in warning

    (tmp_path / "coverage.json").write_text("{not json")
    ctx = make_ctx(tmp_path, coverage_settings("coverage.json"))
    assert collect_coverage_metrics(ctx)[1] == "coverage report could not be parsed: coverage.json"

    (tmp_path / "coverage.json").write_text('{"files": {}}')  # no totals
    assert "could not be parsed" in (collect_coverage_metrics(ctx)[1] or "")
