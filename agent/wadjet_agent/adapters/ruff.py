"""Ruff adapter (section 6): ``ruff check --output-format json --select
<families> --exclude <globs>``.

Default families ``F,B,C90,PLE`` - never ``S``, which would duplicate
Bandit's findings, so ``S`` is filtered out even if configured. Severity:
the defect families (``F``, ``B``, ``PLE``, ``E9``) are ``bug`` at medium,
every other family is a ``code_smell`` at low; nothing from Ruff ever rises
above medium (section 6). Each unique rule's
``ruff rule <CODE> --output-format json`` explanation is fetched once per
run and uploaded in ``raw.explanation`` - the server's knowledge base prints
it as the issue description, with family-level impact/fix text from
``ruff.yml``.
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
MINIMUM, MAXIMUM = "0.6", "1"

NAME = "ruff"

#: Families selected when the project does not say otherwise (section 6).
DEFAULT_FAMILIES = ("F", "B", "C90", "PLE")

#: Families whose findings are defects rather than style. Checked against the
#: leading letters of the code, plus the E9 syntax-error family.
BUG_FAMILIES = frozenset({"F", "B", "PLE"})


def _family(rule_id: str) -> str:
    """The leading letters of a code: ``PLE1307`` -> ``PLE``, ``E501`` -> ``E``."""
    return "".join(character for character in rule_id if not character.isdigit())


def _classify(rule_id: str) -> tuple[Severity, Category]:
    """Bugs: medium. Smells: low. Never above medium (section 6)."""
    if _family(rule_id) in BUG_FAMILIES or rule_id.startswith("E9"):
        return Severity.medium, Category.bug
    return Severity.low, Category.code_smell


def _families(options: dict[str, Any]) -> list[str]:
    """The configured families (settings ``scanners.ruff.families``).

    Accepts a list or a comma-separated string; ``S`` is dropped because
    Bandit owns security rules, and an empty selection falls back to the
    section 6 defaults rather than running Ruff with nothing selected.
    """
    raw = options.get("families")
    if isinstance(raw, str):
        selected = [part.strip() for part in raw.split(",")]
    elif isinstance(raw, (list, tuple)):
        selected = [str(family).strip() for family in raw]
    else:
        selected = list(DEFAULT_FAMILIES)
    families = [family for family in selected if family and family != "S"]
    return families or list(DEFAULT_FAMILIES)


def _fetch_explanation(code: str, ctx: RunContext) -> str | None:
    """``ruff rule <CODE>`` markdown for ``raw.explanation`` (section 6).

    Never fatal: the run still counts when an explanation cannot be fetched;
    the server then describes the finding with the scanner's message.
    """
    try:
        _returncode, stdout, _stderr = run_command(
            ["ruff", "rule", code, "--output-format", "json"], ctx
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    try:
        metadata = json.loads(stdout)
    except ValueError:
        return None
    if not isinstance(metadata, dict):
        return None
    text = str(metadata.get("explanation") or "").strip()
    if text:
        return text
    summary = str(metadata.get("summary") or "").strip()
    return summary or None


class RuffAdapter:
    """Runs Ruff over the included paths and normalizes its JSON."""

    name = NAME

    def info(self) -> AdapterInfo:
        return probe("ruff", MINIMUM, MAXIMUM)

    def run(self, ctx: RunContext) -> RawOutput:
        options = ctx.tool_settings(NAME)
        argv = ["ruff", "check", "--output-format", "json", "--select"]
        argv.append(",".join(_families(options)))
        for glob in ctx.exclusion_globs:
            argv += ["--exclude", glob.strip("/")]
        argv += ctx.include_paths

        started = time.monotonic()
        try:
            returncode, stdout, stderr = run_command(argv, ctx)
        except subprocess.TimeoutExpired:
            return RawOutput(None, ctx.timeout, f"ruff timed out after {ctx.timeout}s")
        except FileNotFoundError:
            return RawOutput(None, 0.0, "ruff is not installed")
        except OSError as exc:
            return RawOutput(None, 0.0, f"ruff failed to start: {exc}")
        duration = time.monotonic() - started

        # Ruff exits 1 when it finds issues: parseable JSON is success.
        try:
            diagnostics = json.loads(stdout)
        except ValueError:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return RawOutput(None, duration, f"ruff produced no JSON: {detail[:500]}")
        if not isinstance(diagnostics, list):
            return RawOutput(None, duration, "ruff JSON was not an array")

        codes = sorted(
            {
                str(entry.get("code") or "")
                for entry in diagnostics
                if isinstance(entry, dict) and entry.get("code")
            }
        )
        explanations: dict[str, str] = {}
        for code in codes:
            explanation = _fetch_explanation(code, ctx)
            if explanation:
                explanations[code] = explanation
        # The rule fetches are part of this run: count them in the duration
        # the server stores in ``scanner_runs``.
        duration = time.monotonic() - started
        return RawOutput({"diagnostics": diagnostics, "explanations": explanations}, duration)

    def normalize(self, raw: RawOutput, ctx: RunContext) -> list[Finding]:
        if raw.error or not isinstance(raw.data, dict):
            return []
        diagnostics = raw.data.get("diagnostics")
        explanations = raw.data.get("explanations")
        if not isinstance(diagnostics, list):
            return []
        findings: list[Finding] = []
        for entry in diagnostics:
            if not isinstance(entry, dict):
                continue
            code = str(entry.get("code") or "")
            if not code:
                continue
            location = entry.get("location")
            ending = entry.get("end_location")
            location = location if isinstance(location, dict) else {}
            ending = ending if isinstance(ending, dict) else {}
            line_start = int(location.get("row") or 0)
            line_end = int(ending.get("row") or line_start) or line_start
            if line_end < line_start:
                line_end = line_start
            path = relative_path(str(entry.get("filename") or ""), ctx)
            message = str(entry.get("message") or code)
            severity, category = _classify(code)
            payload = dict(entry)
            if isinstance(explanations, dict):
                explanation = explanations.get(code)
                if isinstance(explanation, str) and explanation:
                    payload["explanation"] = explanation
            findings.append(
                Finding(
                    tool=NAME,
                    rule_id=code,
                    severity=severity,
                    category=category,
                    title=f"{code}: {message}",
                    message=message,
                    file_path=path,
                    line_start=line_start,
                    line_end=line_end,
                    snippet=build_snippet(ctx.repo_root, path, line_start, line_end),
                    raw=payload,
                )
            )
        return findings
