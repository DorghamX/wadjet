"""Shared adapter helpers: version ranges, probe, snippet building (section 6)."""

from __future__ import annotations

import sys
from pathlib import Path

from wadjet_agent.adapters.base import (
    RunContext,
    build_snippet,
    local_executable,
    probe,
    trim_snippet,
    version_in_range,
)


def test_local_executable_resolution() -> None:
    # Bare names prefer the interpreter's directory (the agent's own tools).
    name = Path(sys.executable).name
    resolved = local_executable(name)
    assert resolved is not None and Path(resolved).is_file()
    # Unknown commands and absolute paths (e.g. WADJET_PYTHON) are left alone.
    assert local_executable("wadjet-no-such-command") is None
    assert local_executable(sys.executable) is None


def test_version_in_range() -> None:
    assert version_in_range("1.7.8", "1.7.8", "2")
    assert version_in_range("1.9.4", "1.7.8", "2")
    assert not version_in_range("1.7.7", "1.7.8", "2")
    assert not version_in_range("2.0.0", "1.7.8", "2")
    assert version_in_range("2.10.1", "2.7", "3")
    assert not version_in_range("3.0.0", "2.7", "3")


def test_probe_reports_missing_and_known_distributions() -> None:
    missing = probe("wadjet-no-such-distribution", "1.0", "2")
    assert missing.installed is False
    assert missing.version is None
    assert "not installed" in missing.detail

    installed = probe("wadjet-schema", "0.1", "999")
    assert installed.installed is True
    assert installed.supported is True
    assert installed.version is not None

    outside = probe("wadjet-schema", "998", "999")
    assert outside.installed is True
    assert outside.supported is False
    assert "outside the supported range" in outside.detail


def test_run_context_reads_structured_tool_settings() -> None:
    ctx = RunContext(
        repo_root=Path(),
        include_paths=["src"],
        exclusion_globs=[],
        python_executable="python3",
        settings={
            "scanners": {"bandit": {"enabled": False, "minimum_confidence": "high"}},
        },
    )
    assert ctx.tool_enabled("bandit") is False
    assert ctx.tool_enabled("pip_audit") is True  # absent means enabled
    assert ctx.tool_settings("bandit")["minimum_confidence"] == "high"
    assert ctx.tool_settings("nothing") == {}


def test_build_snippet_matches_the_server_split_convention(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("\n".join(f"line {number}" for number in range(1, 21)) + "\n")

    snippet = build_snippet(tmp_path, "app.py", 10, 10)
    lines = snippet.split("\n")
    assert len(lines) == 7
    assert lines[:3] == ["line 7", "line 8", "line 9"]
    assert lines[3] == "line 10"  # flagged line sits where split_snippet expects it
    assert lines[4:] == ["line 11", "line 12", "line 13"]


def test_build_snippet_edge_cases(tmp_path: Path) -> None:
    source = tmp_path / "short.py"
    source.write_text("only one line\n")

    assert build_snippet(tmp_path, "missing.py", 1, 1) == ""  # unreadable
    assert build_snippet(tmp_path, "short.py", 0, 0) == ""  # no line info
    assert build_snippet(tmp_path, "short.py", 5, 5) == ""  # past the end
    assert build_snippet(tmp_path, "short.py", 3, 4) == ""  # line_end < line_start
    # Near the top of a file: no context above.
    assert build_snippet(tmp_path, "short.py", 1, 1) == "only one line"


def test_trim_snippet_caps_length() -> None:
    small = "x" * 100
    assert trim_snippet(small) == small
    big = "y" * 10_000
    assert len(trim_snippet(big)) == 4000
