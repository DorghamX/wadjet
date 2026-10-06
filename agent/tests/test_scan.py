"""The scan flow: exit codes, upload, dry-run, doctor (section 11, T2.6)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from wadjet_agent import scan as scan_module
from wadjet_agent.adapters.base import AdapterInfo, RawOutput, RunContext
from wadjet_agent.client import AgentError
from wadjet_agent.scan import (
    EXIT_CONFIG,
    EXIT_GATE_FAILED,
    EXIT_INCOMPLETE,
    EXIT_OK,
    build_context,
    doctor,
    read_env,
    run_scan,
)
from wadjet_schema import AgentConfig, AnalysisResult, AnalysisUpload, Finding, Severity

ENV = {"WADJET_URL": "https://wadjet.example", "WADJET_TOKEN": "tok"}


def make_config(**overrides: Any) -> AgentConfig:
    payload: dict[str, Any] = {
        "project_key": "demo",
        "settings": {},
        "gate_conditions": {"conditions": []},
        "exclusion_globs": [".venv/"],
    }
    payload.update(overrides)
    return AgentConfig(**payload)


def make_finding(path: str = "app.py") -> Finding:
    return Finding(
        tool="bandit",
        rule_id="B101",
        severity=Severity.medium,
        category="bug",
        title="Assert used",
        message="assert statement found",
        file_path=path,
        line_start=1,
        line_end=1,
        snippet="assert x",
    )


def make_result(status: str = "passed", **overrides: Any) -> AnalysisResult:
    payload: dict[str, Any] = {
        "analysis_id": "12",
        "gate_status": status,
        "gate_details": {
            "conditions": [
                {
                    "metric": "issues_total",
                    "operator": ">",
                    "threshold": 0.0,
                    "actual": 1.0,
                    "triggered": status != "passed",
                }
            ]
        },
        "issues_resolved": 0,
        "issues_created": 1,
    }
    payload.update(overrides)
    return AnalysisResult(**payload)


class StubAdapter:
    """A recorded adapter: no subprocess, deterministic output."""

    name = "stub"

    def __init__(
        self,
        *,
        raw: RawOutput | None = None,
        findings: list[Finding] | None = None,
        crash: bool = False,
    ) -> None:
        self._raw = raw or RawOutput({"ok": True}, duration=0.5)
        self._findings = findings or []
        self._crash = crash

    def info(self) -> AdapterInfo:
        return AdapterInfo(installed=True, version="1.2.3", supported=True, detail="stub 1.2.3")

    def run(self, ctx: RunContext) -> RawOutput:
        if self._crash:
            raise RuntimeError("adapter exploded")
        return self._raw

    def normalize(self, raw: RawOutput, ctx: RunContext) -> list[Finding]:
        return [] if raw.error else list(self._findings)


@pytest.fixture()
def uploads(monkeypatch: pytest.MonkeyPatch) -> list[AnalysisUpload]:
    """Capture every upload and answer with a passing result."""
    captured: list[AnalysisUpload] = []

    def fake_upload(base_url: str, token: str, upload: Any) -> AnalysisResult:
        captured.append(upload)
        return make_result("passed")

    monkeypatch.setattr(scan_module, "upload_analysis", fake_upload)
    return captured  # type: ignore[return-value]


def patch_config(monkeypatch: pytest.MonkeyPatch, config: AgentConfig | None = None) -> None:
    monkeypatch.setattr(scan_module, "fetch_config", lambda url, token: config or make_config())


def patch_adapters(monkeypatch: pytest.MonkeyPatch, *adapters: Any) -> None:
    monkeypatch.setattr(scan_module, "enabled_adapters", lambda ctx: list(adapters))


# --- environment ------------------------------------------------------------


def test_read_env_requires_both_values() -> None:
    assert read_env(ENV) == ("https://wadjet.example", "tok")
    with pytest.raises(AgentError, match="WADJET_URL and WADJET_TOKEN"):
        read_env({})
    with pytest.raises(AgentError):
        read_env({"WADJET_URL": "https://x"})


def test_scan_without_environment_is_an_agent_error(tmp_path: Path) -> None:
    with pytest.raises(AgentError):
        run_scan(tmp_path, env={})


def test_build_context_uses_scope_and_timeout() -> None:
    config = make_config(settings={"scope": {"include": ["src", "lib"]}, "timeout_seconds": 42})
    ctx = build_context(config, Path("/repo"))
    assert ctx.include_paths == ["src", "lib"]
    assert ctx.exclusion_globs == [".venv/"]
    assert ctx.timeout == 42.0
    assert build_context(make_config(), Path("/repo")).include_paths == ["."]


# --- dry run ----------------------------------------------------------------


def test_dry_run_prints_the_plan_and_never_uploads(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_config(monkeypatch)
    patch_adapters(monkeypatch, StubAdapter())

    def fail_upload(*args: Any) -> Any:
        raise AssertionError("dry run must not upload")

    monkeypatch.setattr(scan_module, "upload_analysis", fail_upload)

    code = run_scan(Path("/nowhere"), dry_run=True, env=ENV)
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "Would scan project 'demo'" in out
    assert "stub" in out
    assert "exclusions" in out


# --- full run ---------------------------------------------------------------


def test_happy_path_uploads_and_returns_zero(
    monkeypatch: pytest.MonkeyPatch,
    uploads: list[Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    patch_config(monkeypatch)
    patch_adapters(monkeypatch, StubAdapter(findings=[make_finding()]))

    env = {**ENV, "GITHUB_SHA": "abc123", "GITHUB_RUN_ID": "1"}
    code = run_scan(Path("/nowhere"), env=env)

    assert code == EXIT_OK
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload.project_key == "demo"
    assert upload.commit_sha == "abc123"
    assert len(upload.findings) == 1
    assert upload.scanner_runs["stub"]["status"] == "ok"
    assert upload.scanner_runs["stub"]["version"] == "1.2.3"

    out = capsys.readouterr().out
    assert "GATE: PASSED" in out
    assert "https://wadjet.example/projects/demo" in out


def test_gate_failure_returns_one(monkeypatch: pytest.MonkeyPatch, uploads: list[Any]) -> None:
    patch_config(monkeypatch)
    patch_adapters(monkeypatch, StubAdapter())

    monkeypatch.setattr(
        scan_module, "upload_analysis", lambda url, token, upload: make_result("failed")
    )
    assert run_scan(Path("/nowhere"), env=ENV) == EXIT_GATE_FAILED


def test_scanner_error_makes_the_analysis_incomplete(
    monkeypatch: pytest.MonkeyPatch, uploads: list[Any]
) -> None:
    patch_config(monkeypatch)
    patch_adapters(
        monkeypatch, StubAdapter(raw=RawOutput(None, 0.0, error="bandit is not installed"))
    )
    assert run_scan(Path("/nowhere"), env=ENV) == EXIT_INCOMPLETE
    assert uploads[0].scanner_runs["stub"]["status"] == "error"


def test_adapter_crash_is_recorded_not_fatal(
    monkeypatch: pytest.MonkeyPatch, uploads: list[Any]
) -> None:
    patch_config(monkeypatch)
    patch_adapters(monkeypatch, StubAdapter(crash=True))
    code = run_scan(Path("/nowhere"), env=ENV)
    assert code == EXIT_INCOMPLETE
    record = uploads[0].scanner_runs["stub"]
    assert record["status"] == "error"
    assert "adapter exploded" in record["error"]


def test_network_error_propagates_as_agent_error(
    monkeypatch: pytest.MonkeyPatch, uploads: list[Any]
) -> None:
    patch_config(monkeypatch)
    patch_adapters(monkeypatch, StubAdapter())

    def fail(url: str, token: str, upload: Any) -> AnalysisResult:
        raise AgentError("upload failed: HTTP 413")

    monkeypatch.setattr(scan_module, "upload_analysis", fail)
    with pytest.raises(AgentError, match="413"):
        run_scan(Path("/nowhere"), env=ENV)


def test_excluded_paths_are_post_filtered_before_upload(
    monkeypatch: pytest.MonkeyPatch, uploads: list[Any]
) -> None:
    patch_config(monkeypatch)
    patch_adapters(
        monkeypatch,
        StubAdapter(findings=[make_finding(".venv/lib/site.py"), make_finding("app.py")]),
    )
    assert run_scan(Path("/nowhere"), env=ENV) == EXIT_OK
    paths = [finding.file_path for finding in uploads[0].findings]
    assert paths == ["app.py"]  # dependency findings without a path would survive


def test_report_file_is_written(
    monkeypatch: pytest.MonkeyPatch, uploads: list[Any], tmp_path: Path
) -> None:
    patch_config(monkeypatch)
    patch_adapters(monkeypatch, StubAdapter(findings=[make_finding()]))
    report = tmp_path / "wadjet-report.json"

    run_scan(Path("/nowhere"), env=ENV, report_path=report)

    payload = json.loads(report.read_text())
    assert payload["project_key"] == "demo"
    assert payload["analysis"]["gate_status"] == "passed"
    assert payload["analysis"]["analysis_id"] == "12"
    assert len(payload["findings"]) == 1
    assert payload["scanner_runs"]["stub"]["status"] == "ok"


# --- doctor -----------------------------------------------------------------


def test_doctor_without_environment_checks_tools_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    good = StubAdapter()
    monkeypatch.setattr(scan_module, "ADAPTERS", {"stub": good})
    assert doctor(env={}, out=print) == EXIT_OK
    out = capsys.readouterr().out
    assert "server: skipped" in out
    assert "stub" in out


def test_doctor_fails_when_a_tool_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    missing = StubAdapter()
    missing.info = lambda: AdapterInfo(  # type: ignore[method-assign]
        installed=False, version=None, supported=False, detail="stub is not installed"
    )
    monkeypatch.setattr(scan_module, "ADAPTERS", {"stub": missing})
    assert doctor(env={}, out=lambda _line: None) == EXIT_GATE_FAILED


def test_doctor_reports_a_server_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_module, "ADAPTERS", {"stub": StubAdapter()})

    def fail(url: str, token: str) -> AgentConfig:
        raise AgentError("token rejected")

    monkeypatch.setattr(scan_module, "fetch_config", fail)
    assert doctor(env=dict(ENV), out=lambda _line: None) == EXIT_CONFIG
