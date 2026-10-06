"""Contract tests for the Bandit adapter against recorded output (section 6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wadjet_agent.adapters import bandit
from wadjet_agent.adapters.base import RawOutput, RunContext
from wadjet_schema import Category, Severity

FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "bandit" / "1.9.4"
SAMPLE_ROOT = FIXTURE_ROOT / "sample"


def load_raw() -> RawOutput:
    data = json.loads((FIXTURE_ROOT / "bandit.json").read_text())
    return RawOutput(data, duration=1.0)


def make_ctx(**settings: object) -> RunContext:
    return RunContext(
        repo_root=SAMPLE_ROOT,
        include_paths=["."],
        exclusion_globs=[],
        python_executable="python3",
        settings={"scanners": {"bandit": dict(**settings)}},  # type: ignore[arg-type]
    )


def test_fixture_parses_into_contract_findings() -> None:
    findings = bandit.BanditAdapter().normalize(load_raw(), make_ctx())
    assert len(findings) == 8
    assert {f.rule_id for f in findings} == {
        "B101",
        "B105",
        "B301",
        "B311",
        "B324",
        "B403",
        "B404",
        "B602",
    }
    for finding in findings:
        assert finding.tool == "bandit"
        assert finding.category is Category.vulnerability
        assert finding.file_path == "app.py"  # relative, ready for the server
        assert finding.message  # the scanner text survives for unknown KB rules
        assert finding.raw and finding.raw["test_id"] == finding.rule_id


def test_severity_mapping_matches_section_6() -> None:
    findings = {f.rule_id: f for f in bandit.BanditAdapter().normalize(load_raw(), make_ctx())}
    # HIGH severity + HIGH confidence = critical.
    assert findings["B602"].severity is Severity.critical
    assert findings["B324"].severity is Severity.critical
    # MEDIUM = medium, LOW = low.
    assert findings["B301"].severity is Severity.medium
    assert findings["B101"].severity is Severity.low
    assert findings["B105"].severity is Severity.low


@pytest.mark.parametrize(
    ("severity", "confidence", "expected"),
    [
        ("HIGH", "HIGH", Severity.critical),
        ("HIGH", "MEDIUM", Severity.high),
        ("HIGH", "LOW", Severity.high),
        ("MEDIUM", "HIGH", Severity.medium),
        ("LOW", "HIGH", Severity.low),
        ("", "", Severity.low),
    ],
)
def test_map_severity_branches(severity: str, confidence: str, expected: Severity) -> None:
    assert bandit._map_severity(severity, confidence) is expected


def test_cwe_is_kept() -> None:
    findings = {f.rule_id: f for f in bandit.BanditAdapter().normalize(load_raw(), make_ctx())}
    assert findings["B301"].cwe == "CWE-502"
    assert findings["B324"].cwe == "CWE-327"
    assert findings["B101"].cwe == "CWE-703"


def test_lines_and_snippet_follow_the_context_convention() -> None:
    findings = {f.rule_id: f for f in bandit.BanditAdapter().normalize(load_raw(), make_ctx())}
    finding = findings["B101"]
    assert finding.line_start == 10
    assert finding.line_end == 10
    lines = finding.snippet.split("\n")
    assert len(lines) == 7  # 3 above, flagged, 3 below
    assert lines[3] == "    assert value > 0"  # the flagged line sits at index 3


def test_skipped_test_ids_are_dropped_by_the_agent_too() -> None:
    findings = bandit.BanditAdapter().normalize(load_raw(), make_ctx(skipped_test_ids=["B101"]))
    assert "B101" not in {f.rule_id for f in findings}
    assert len(findings) == 7


def test_run_parses_recorded_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    """The recorded output parses exactly as ``run`` parses live output."""
    stdout = (FIXTURE_ROOT / "bandit.json").read_text()

    def fake_run_command(argv: list[str], ctx: RunContext) -> tuple[int, str, str]:
        return 1, stdout, ""  # bandit exits 1 when it finds issues

    monkeypatch.setattr(bandit, "run_command", fake_run_command)
    raw = bandit.BanditAdapter().run(make_ctx())
    assert raw.error is None
    assert isinstance(raw.data, dict)
    assert len(raw.data["results"]) == 8


def test_run_records_missing_or_broken_output(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = bandit.BanditAdapter()

    monkeypatch.setattr(
        bandit,
        "run_command",
        lambda argv, ctx: (_ for _ in ()).throw(FileNotFoundError()),
    )
    assert "not installed" in (adapter.run(make_ctx()).error or "")

    monkeypatch.setattr(bandit, "run_command", lambda argv, ctx: (2, "", "boom"))
    error = adapter.run(make_ctx()).error or ""
    assert "no JSON" in error and "boom" in error


def test_normalize_ignores_broken_runs() -> None:
    raw = RawOutput(None, 0.0, error="bandit is not installed")
    assert bandit.BanditAdapter().normalize(raw, make_ctx()) == []
    assert bandit.BanditAdapter().normalize(RawOutput({"results": None}, 1.0), make_ctx()) == []
