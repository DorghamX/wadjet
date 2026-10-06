"""Bandit adapter (section 6): ``bandit -r <paths> -f json -x <excludes>``.

Severity mapping: HIGH severity + HIGH confidence = critical; HIGH = high;
MEDIUM = medium; LOW = low.  Category ``vulnerability``.  The issue CWE is
kept for the server's knowledge base.
"""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from wadjet_schema import Category, Finding, Severity

from .base import (
    AdapterInfo,
    RawOutput,
    RunContext,
    build_snippet,
    probe,
    relative_path,
    run_command,
)

#: Supported range, pinned in SUPPORTED.md.
MINIMUM, MAXIMUM = "1.7.8", "2"

NAME = "bandit"


def _map_severity(severity: str, confidence: str) -> Severity:
    level = severity.upper()
    if level == "HIGH":
        return Severity.critical if confidence.upper() == "HIGH" else Severity.high
    if level == "MEDIUM":
        return Severity.medium
    return Severity.low


def _cwe(entry: dict[str, Any]) -> str | None:
    cwe = entry.get("issue_cwe")
    if isinstance(cwe, dict) and cwe.get("id") is not None:
        return f"CWE-{cwe['id']}"
    return None


class BanditAdapter:
    """Runs Bandit over the included paths and normalizes its JSON."""

    name = NAME

    def info(self) -> AdapterInfo:
        return probe("bandit", MINIMUM, MAXIMUM)

    def run(self, ctx: RunContext) -> RawOutput:
        options = ctx.tool_settings(NAME)
        argv = ["bandit", "-f", "json"]
        for glob in ctx.exclusion_globs:
            argv += ["-x", glob.strip("/")]
        skipped = options.get("skipped_test_ids")
        if isinstance(skipped, list) and skipped:
            argv += ["-s", ",".join(str(test_id) for test_id in skipped)]
        minimum_confidence = options.get("minimum_confidence")
        if minimum_confidence:
            argv += ["--confidence", str(minimum_confidence)]
        argv += ["-r", *ctx.include_paths]

        started = time.monotonic()
        try:
            returncode, stdout, stderr = run_command(argv, ctx)
        except subprocess.TimeoutExpired:
            return RawOutput(None, ctx.timeout, f"bandit timed out after {ctx.timeout}s")
        except FileNotFoundError:
            return RawOutput(None, 0.0, "bandit is not installed")
        except OSError as exc:
            return RawOutput(None, 0.0, f"bandit failed to start: {exc}")
        duration = time.monotonic() - started

        # Bandit exits non-zero when it finds issues: parseable JSON is success.
        try:
            data = json.loads(stdout)
        except ValueError:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return RawOutput(None, duration, f"bandit produced no JSON: {detail[:500]}")
        if not isinstance(data, dict):
            return RawOutput(None, duration, "bandit JSON was not an object")
        return RawOutput(data, duration)

    def normalize(self, raw: RawOutput, ctx: RunContext) -> list[Finding]:
        if raw.error or not isinstance(raw.data, dict):
            return []
        skipped = {
            str(test_id) for test_id in ctx.tool_settings(NAME).get("skipped_test_ids") or []
        }
        findings: list[Finding] = []
        for entry in raw.data.get("results") or []:
            rule_id = entry.get("test_id")
            if not isinstance(rule_id, str) or not rule_id or rule_id in skipped:
                continue
            line_range = entry.get("line_range") or []
            line_start = int(entry.get("line_number") or 0)
            line_end = int(line_range[-1]) if line_range else line_start
            path = relative_path(str(entry.get("filename") or ""), ctx)
            message = str(entry.get("issue_text") or rule_id)
            findings.append(
                Finding(
                    tool=NAME,
                    rule_id=rule_id,
                    severity=_map_severity(
                        str(entry.get("issue_severity") or ""),
                        str(entry.get("issue_confidence") or ""),
                    ),
                    category=Category.vulnerability,
                    title=message,
                    message=message,
                    file_path=path,
                    line_start=line_start,
                    line_end=line_end,
                    snippet=build_snippet(ctx.repo_root, path, line_start, line_end),
                    cwe=_cwe(entry),
                    raw=dict(entry),
                )
            )
        return findings
