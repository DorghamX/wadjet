"""Contract tests for the pip-audit adapter against recorded output (section 6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wadjet_agent.adapters import pip_audit
from wadjet_agent.adapters.base import RawOutput, RunContext
from wadjet_schema import Category, Severity

FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "pip-audit" / "2.10.1"


def load_raw() -> RawOutput:
    """The recorded stdout as ``run`` hands it to ``normalize`` (unwrapped)."""
    data = json.loads((FIXTURE_ROOT / "pip-audit.json").read_text())
    dependencies = data["dependencies"] if isinstance(data, dict) else data
    return RawOutput(dependencies, duration=1.0)


def make_ctx(**settings: object) -> RunContext:
    return RunContext(
        repo_root=FIXTURE_ROOT,
        include_paths=["."],
        exclusion_globs=[],
        python_executable="python3",
        settings={"scanners": {"pip_audit": dict(settings)}},
    )


def test_fixture_parses_into_dependency_findings() -> None:
    findings = pip_audit.PipAuditAdapter().normalize(load_raw(), make_ctx())
    assert findings  # the recorded run found vulnerabilities
    for finding in findings:
        assert finding.tool == "pip_audit"
        assert finding.category is Category.dependency
        assert finding.package == "requests"
        assert finding.installed_version == "2.19.0"
        assert finding.vuln_id
        assert finding.file_path is None  # dependency findings carry no path
        assert finding.snippet == ""
        assert finding.message  # the advisory text becomes the description


def test_ids_aliases_and_fix_versions_survive() -> None:
    findings = pip_audit.PipAuditAdapter().normalize(load_raw(), make_ctx())
    by_id = {finding.vuln_id: finding for finding in findings}
    assert "PYSEC-2018-28" in by_id
    entry = by_id["PYSEC-2018-28"]
    assert entry.rule_id == "PYSEC-2018-28"
    assert "CVE-2018-18074" in entry.aliases
    assert entry.fixed_versions == ["2.20.0"]  # the server builds the fix text
    assert entry.title == "requests 2.19.0: PYSEC-2018-28"


def test_severity_comes_from_the_project_setting() -> None:
    default = pip_audit.PipAuditAdapter().normalize(load_raw(), make_ctx())
    assert all(f.severity is Severity.high for f in default)  # default high

    strict = pip_audit.PipAuditAdapter().normalize(
        load_raw(), make_ctx(dependency_default_severity="critical")
    )
    assert all(f.severity is Severity.critical for f in strict)

    nonsense = pip_audit.PipAuditAdapter().normalize(
        load_raw(), make_ctx(dependency_default_severity="purple")
    )
    assert all(f.severity is Severity.high for f in nonsense)  # falls back


def test_duplicate_advisories_normalize_to_duplicate_findings() -> None:
    """pip-audit repeats an advisory per source; the server dedupes by
    fingerprint, so the agent passes them through untouched (section 11)."""
    findings = pip_audit.PipAuditAdapter().normalize(load_raw(), make_ctx())
    unique_ids = {finding.vuln_id for finding in findings}
    assert len(findings) > len(unique_ids)
    assert len(unique_ids) >= 5


def test_run_accepts_the_wrapped_and_legacy_shapes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    adapter = pip_audit.PipAuditAdapter()
    stdout = (FIXTURE_ROOT / "pip-audit.json").read_text()

    monkeypatch.setattr(
        pip_audit,
        "run_command",
        lambda argv, ctx: (1, stdout, ""),  # vulns found
    )
    raw = adapter.run(make_ctx())
    assert raw.error is None
    assert isinstance(raw.data, list) and len(raw.data) == 1  # dependencies unwrapped

    monkeypatch.setattr(pip_audit, "run_command", lambda argv, ctx: (0, '[{"name": "x"}]', ""))
    legacy = adapter.run(make_ctx())
    assert legacy.error is None and legacy.data == [{"name": "x"}]

    monkeypatch.setattr(pip_audit, "run_command", lambda argv, ctx: (2, "", "no deps"))
    error = adapter.run(make_ctx()).error or ""
    assert "no JSON" in error and "no deps" in error


def test_normalize_ignores_broken_runs() -> None:
    raw = RawOutput(None, 0.0, error="pip-audit is not installed")
    assert pip_audit.PipAuditAdapter().normalize(raw, make_ctx()) == []
