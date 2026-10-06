"""Contract tests for the Ruff adapter against recorded output (section 6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wadjet_agent.adapters import enabled_adapters, ruff
from wadjet_agent.adapters.base import RawOutput, RunContext
from wadjet_schema import Category, Severity

FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "ruff" / "0.16.10"
SAMPLE_ROOT = FIXTURE_ROOT / "sample"


def load_raw() -> RawOutput:
    """Exactly what ``run`` builds: diagnostics plus fetched explanations."""
    diagnostics = json.loads((FIXTURE_ROOT / "ruff-check.json").read_text())
    rules = json.loads((FIXTURE_ROOT / "ruff-rules.json").read_text())
    explanations = {code: meta["explanation"] for code, meta in rules.items()}
    return RawOutput({"diagnostics": diagnostics, "explanations": explanations}, duration=1.0)


def make_ctx(**settings: object) -> RunContext:
    return RunContext(
        repo_root=SAMPLE_ROOT,
        include_paths=["."],
        exclusion_globs=[],
        python_executable="python3",
        settings={"scanners": {"ruff": dict(**settings)}},  # type: ignore[arg-type]
    )


def test_fixture_parses_into_contract_findings() -> None:
    findings = ruff.RuffAdapter().normalize(load_raw(), make_ctx())
    assert len(findings) == 8
    assert {f.rule_id for f in findings} == {"B006", "C901", "F401", "F841", "PLE1307"}
    for finding in findings:
        assert finding.tool == "ruff"
        assert finding.file_path == "messy.py"  # relative, ready for the server
        assert finding.message  # the scanner text survives for the KB fallback
        assert finding.title.startswith(f"{finding.rule_id}:")
        # Section 6: the fetched explanation travels in raw.explanation.
        assert finding.raw and finding.raw["explanation"].startswith("## What it does")


def test_severity_mapping_stays_within_the_section_6_cap() -> None:
    findings = {f.rule_id: f for f in ruff.RuffAdapter().normalize(load_raw(), make_ctx())}
    # Defect families (F, B, PLE): medium bugs.
    assert findings["F401"].severity is Severity.medium
    assert findings["F401"].category is Category.bug
    assert findings["F841"].category is Category.bug
    assert findings["B006"].severity is Severity.medium
    assert findings["PLE1307"].category is Category.bug
    # Complexity: a smell at low.
    assert findings["C901"].severity is Severity.low
    assert findings["C901"].category is Category.code_smell
    # Nothing from Ruff ever rises above medium.
    for finding in findings.values():
        assert finding.severity in (Severity.medium, Severity.low)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("F401", (Severity.medium, Category.bug)),
        ("B006", (Severity.medium, Category.bug)),
        ("PLE1307", (Severity.medium, Category.bug)),
        ("E999", (Severity.medium, Category.bug)),  # syntax errors are defects
        ("C901", (Severity.low, Category.code_smell)),
        ("E501", (Severity.low, Category.code_smell)),
        ("W291", (Severity.low, Category.code_smell)),
        ("TRY300", (Severity.low, Category.code_smell)),
        ("RUF001", (Severity.low, Category.code_smell)),
    ],
)
def test_classify_branches(code: str, expected: tuple[Severity, Category]) -> None:
    assert ruff._classify(code) == expected


def test_lines_and_snippet_follow_the_context_convention() -> None:
    findings = {f.rule_id: f for f in ruff.RuffAdapter().normalize(load_raw(), make_ctx())}
    finding = findings["B006"]
    assert finding.line_start == 9
    assert finding.line_end == 9
    lines = finding.snippet.split("\n")
    assert len(lines) == 7  # 3 above, flagged, 3 below
    assert lines[3] == "def process(items, cache=[]):"


def test_families_configuration() -> None:
    assert ruff._families({}) == ["F", "B", "C90", "PLE"]
    assert ruff._families({"families": "F, E, W"}) == ["F", "E", "W"]
    assert ruff._families({"families": ["RUF"]}) == ["RUF"]
    # S is Bandit's territory, and a selection never ends up empty.
    assert ruff._families({"families": ["F", "S", ""]}) == ["F"]
    assert ruff._families({"families": ["S"]}) == ["F", "B", "C90", "PLE"]


def test_run_selects_families_and_exclusions(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []

    def fake_run_command(argv: list[str], ctx: RunContext) -> tuple[int, str, str]:
        captured.append(argv)
        return 1, "[]", ""

    monkeypatch.setattr(ruff, "run_command", fake_run_command)
    ctx = RunContext(
        repo_root=SAMPLE_ROOT,
        include_paths=["src", "."],
        exclusion_globs=[".venv/", "/build/"],
        python_executable="python3",
        settings={"scanners": {"ruff": {"families": "F,E"}}},
    )
    raw = ruff.RuffAdapter().run(ctx)
    assert raw.error is None
    assert captured == [
        [
            "ruff",
            "check",
            "--output-format",
            "json",
            "--select",
            "F,E",
            "--exclude",
            ".venv",
            "--exclude",
            "build",
            "src",
            ".",
        ]
    ]


def test_run_fetches_one_explanation_per_unique_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = (FIXTURE_ROOT / "ruff-check.json").read_text()
    rules = json.loads((FIXTURE_ROOT / "ruff-rules.json").read_text())
    fetched: list[str] = []

    def fake_run_command(argv: list[str], ctx: RunContext) -> tuple[int, str, str]:
        if "rule" in argv:
            fetched.append(argv[2])
            return 0, json.dumps(rules[argv[2]]), ""
        return 1, stdout, ""

    monkeypatch.setattr(ruff, "run_command", fake_run_command)
    raw = ruff.RuffAdapter().run(make_ctx())
    assert raw.error is None
    assert sorted(fetched) == sorted(rules)  # once per unique code, not per finding
    assert set(raw.data["explanations"]) == set(rules)


def test_run_tolerates_missing_explanations(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed rule fetch never fails the run; the message stands in."""
    stdout = (FIXTURE_ROOT / "ruff-check.json").read_text()

    def fake_run_command(argv: list[str], ctx: RunContext) -> tuple[int, str, str]:
        if "rule" in argv:
            return 2, "", "unknown rule"
        return 1, stdout, ""

    monkeypatch.setattr(ruff, "run_command", fake_run_command)
    raw = ruff.RuffAdapter().run(make_ctx())
    assert raw.error is None
    assert raw.data["explanations"] == {}
    findings = ruff.RuffAdapter().normalize(raw, make_ctx())
    assert len(findings) == 8
    assert findings[0].raw and "explanation" not in findings[0].raw


def test_run_parses_recorded_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    """The recorded output parses exactly as ``run`` parses live output."""
    stdout = (FIXTURE_ROOT / "ruff-check.json").read_text()

    def fake_run_command(argv: list[str], ctx: RunContext) -> tuple[int, str, str]:
        if "rule" in argv:
            return 0, '{"summary": "s", "explanation": "e"}', ""
        return 1, stdout, ""  # ruff exits 1 when it finds issues

    monkeypatch.setattr(ruff, "run_command", fake_run_command)
    raw = ruff.RuffAdapter().run(make_ctx())
    assert raw.error is None
    assert len(raw.data["diagnostics"]) == 8


def test_run_records_missing_or_broken_output(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = ruff.RuffAdapter()

    monkeypatch.setattr(
        ruff,
        "run_command",
        lambda argv, ctx: (_ for _ in ()).throw(FileNotFoundError()),
    )
    assert "not installed" in (adapter.run(make_ctx()).error or "")

    monkeypatch.setattr(ruff, "run_command", lambda argv, ctx: (2, "", "boom"))
    error = adapter.run(make_ctx()).error or ""
    assert "no JSON" in error and "boom" in error

    monkeypatch.setattr(ruff, "run_command", lambda argv, ctx: (0, '{"not": "an array"}', ""))
    assert "not an array" in (adapter.run(make_ctx()).error or "")


def test_normalize_ignores_broken_runs() -> None:
    raw = RawOutput(None, 0.0, error="ruff is not installed")
    assert ruff.RuffAdapter().normalize(raw, make_ctx()) == []
    assert ruff.RuffAdapter().normalize(RawOutput({"diagnostics": None}, 1.0), make_ctx()) == []


def test_disabled_ruff_is_not_run() -> None:
    ctx = RunContext(
        repo_root=SAMPLE_ROOT,
        include_paths=["."],
        exclusion_globs=[],
        python_executable="python3",
        settings={"scanners": {"ruff": {"enabled": False}}},
    )
    assert "ruff" not in [adapter.name for adapter in enabled_adapters(ctx)]
