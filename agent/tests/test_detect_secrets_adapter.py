"""Contract tests for the detect-secrets adapter against recorded output (6)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from wadjet_agent.adapters import detect_secrets, enabled_adapters
from wadjet_agent.adapters.base import RawOutput, RunContext
from wadjet_schema import Category, Severity

FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "detect-secrets" / "1.5.0"
SAMPLE_ROOT = FIXTURE_ROOT / "sample"

#: The planted values in ``sample/`` - none of them may ever be uploaded.
PLANTED_VALUES = ("hunter2-not-real", "AKIA1234567890ABCD", "user:pass@")


def load_raw() -> RawOutput:
    data = json.loads((FIXTURE_ROOT / "detect-secrets.json").read_text())
    return RawOutput(data, duration=1.0)


def make_ctx(**settings: object) -> RunContext:
    return RunContext(
        repo_root=SAMPLE_ROOT,
        include_paths=["."],
        exclusion_globs=[],
        python_executable="python3",
        settings={"scanners": {"detect_secrets": dict(**settings)}},  # type: ignore[arg-type]
    )


def test_fixture_parses_into_contract_findings() -> None:
    findings = detect_secrets.DetectSecretsAdapter().normalize(load_raw(), make_ctx())
    assert len(findings) == 4
    assert {(f.file_path, f.line_start, f.rule_id) for f in findings} == {
        ("key.pem", 1, "Private Key"),
        ("settings.py", 3, "Secret Keyword"),
        ("settings.py", 4, "Secret Keyword"),
        ("settings.py", 5, "Basic Auth Credentials"),
    }
    for finding in findings:
        assert finding.tool == "detect_secrets"
        assert finding.severity is Severity.blocker
        assert finding.category is Category.secret
        assert finding.title == finding.rule_id  # the detector type
        assert finding.message and finding.line_start == finding.line_end
        # The keep list: hash only, in raw, and never the source line.
        assert set(finding.raw) == {"hashed_secret"}
        assert finding.raw["hashed_secret"]
        assert finding.snippet == ""


def test_no_planted_value_can_reach_the_upload() -> None:
    findings = detect_secrets.DetectSecretsAdapter().normalize(load_raw(), make_ctx())
    payload = json.dumps([f.model_dump() for f in findings])
    for value in PLANTED_VALUES:
        assert value not in payload


def test_run_parses_recorded_stdout(monkeypatch) -> None:
    stdout = (FIXTURE_ROOT / "detect-secrets.json").read_text()
    captured: list[list[str]] = []

    def fake_run_command(argv, ctx):
        captured.append(argv)
        return 0, stdout, "fatal: not a git repository"  # harmless outside git

    monkeypatch.setattr(detect_secrets, "run_command", fake_run_command)
    raw = detect_secrets.DetectSecretsAdapter().run(make_ctx())
    assert raw.error is None
    assert captured == [["detect-secrets", "scan", "."]]
    assert len(raw.data["results"]) == 2


def test_run_records_missing_or_broken_output(monkeypatch) -> None:
    adapter = detect_secrets.DetectSecretsAdapter()

    monkeypatch.setattr(
        detect_secrets,
        "run_command",
        lambda argv, ctx: (_ for _ in ()).throw(FileNotFoundError()),
    )
    assert "not installed" in (adapter.run(make_ctx()).error or "")

    monkeypatch.setattr(
        detect_secrets,
        "run_command",
        lambda argv, ctx: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="detect-secrets", timeout=5)
        ),
    )
    assert "timed out" in (adapter.run(make_ctx()).error or "")

    monkeypatch.setattr(detect_secrets, "run_command", lambda argv, ctx: (1, "", "boom"))
    error = adapter.run(make_ctx()).error or ""
    assert "no JSON" in error and "boom" in error

    monkeypatch.setattr(detect_secrets, "run_command", lambda argv, ctx: (0, "[1, 2]", ""))
    assert "not an object" in (adapter.run(make_ctx()).error or "")


def test_normalize_tolerates_broken_runs() -> None:
    adapter = detect_secrets.DetectSecretsAdapter()
    raw = RawOutput(None, 0.0, error="detect-secrets is not installed")
    assert adapter.normalize(raw, make_ctx()) == []
    assert adapter.normalize(RawOutput({"no_results": {}}, 1.0), make_ctx()) == []
    assert adapter.normalize(RawOutput({"results": "weird"}, 1.0), make_ctx()) == []


def test_disabled_detect_secrets_is_not_run() -> None:
    ctx = RunContext(
        repo_root=SAMPLE_ROOT,
        include_paths=["."],
        exclusion_globs=[],
        python_executable="python3",
        settings={"scanners": {"detect_secrets": {"enabled": False}}},
    )
    assert "detect_secrets" not in [adapter.name for adapter in enabled_adapters(ctx)]
