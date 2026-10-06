"""CLI wiring: exit codes and option handling (section 11)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from wadjet_agent import cli as cli_module
from wadjet_agent.cli import app
from wadjet_agent.scan import EXIT_CONFIG, EXIT_GATE_FAILED, EXIT_OK

runner = CliRunner()


@pytest.fixture(autouse=True)
def no_server_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WADJET_URL", raising=False)
    monkeypatch.delenv("WADJET_TOKEN", raising=False)


def test_scan_without_environment_exits_2() -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == EXIT_CONFIG


def test_scan_passes_options_through(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_run_scan(repo_root: Path, *, dry_run: bool, report_path: Path | None) -> int:
        seen.update(root=repo_root, dry_run=dry_run, report_path=report_path)
        return EXIT_GATE_FAILED

    monkeypatch.setattr(cli_module, "run_scan", fake_run_scan)
    result = runner.invoke(
        app,
        ["scan", "--path", "/repo", "--dry-run", "--report-json", "out.json"],
    )
    assert result.exit_code == EXIT_GATE_FAILED  # 1 bubbles up for CI
    assert seen["dry_run"] is True
    assert seen["report_path"] == Path("out.json")
    assert seen["root"] == Path("/repo").resolve()


def test_scan_report_flag_is_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "run_scan", lambda repo_root, *, dry_run, report_path: EXIT_OK)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0


def test_doctor_uses_the_doctor_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "run_doctor", lambda: EXIT_CONFIG)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == EXIT_CONFIG

    monkeypatch.setattr(cli_module, "run_doctor", lambda: EXIT_OK)
    assert runner.invoke(app, ["doctor"]).exit_code == EXIT_OK
