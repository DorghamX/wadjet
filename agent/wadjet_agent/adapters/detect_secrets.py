"""detect-secrets adapter (section 6): ``detect-secrets scan`` JSON.

Severity ``blocker``, category ``secret``. The keep list is exactly
file, line, type and hash (section 6 / guide row): the finding carries
``rule_id`` = detector type, the path and line, ``raw = {"hashed_secret"}``
and an empty ``snippet`` - the source line IS the secret, so it never
leaves the machine, and no other raw field is passed through. The scan
flow redacts the lines detect-secrets flagged from *other* tools' snippets
(``scan.mask_secret_lines``, step 6).
"""

from __future__ import annotations

import json
import subprocess
import time

from wadjet_schema import Category, Finding, Severity

from .base import (
    AdapterInfo,
    RawOutput,
    RunContext,
    probe,
    relative_path,
    run_command,
)

#: Supported range, pinned in SUPPORTED.md.
MINIMUM, MAXIMUM = "1.4", "2"

NAME = "detect_secrets"


class DetectSecretsAdapter:
    """Runs detect-secrets over the included paths and normalizes its JSON."""

    name = NAME

    def info(self) -> AdapterInfo:
        return probe("detect-secrets", MINIMUM, MAXIMUM)

    def run(self, ctx: RunContext) -> RawOutput:
        argv = ["detect-secrets", "scan", *ctx.include_paths]

        started = time.monotonic()
        try:
            returncode, stdout, stderr = run_command(argv, ctx)
        except subprocess.TimeoutExpired:
            return RawOutput(None, ctx.timeout, f"detect-secrets timed out after {ctx.timeout}s")
        except FileNotFoundError:
            return RawOutput(None, 0.0, "detect-secrets is not installed")
        except OSError as exc:
            return RawOutput(None, 0.0, f"detect-secrets failed to start: {exc}")
        duration = time.monotonic() - started

        # detect-secrets exits 0 whether or not it found anything; JSON is
        # the contract (it may still warn on stderr outside a git checkout).
        try:
            data = json.loads(stdout)
        except ValueError:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return RawOutput(None, duration, f"detect-secrets produced no JSON: {detail[:500]}")
        if not isinstance(data, dict):
            return RawOutput(None, duration, "detect-secrets JSON was not an object")
        return RawOutput(data, duration)

    def normalize(self, raw: RawOutput, ctx: RunContext) -> list[Finding]:
        if raw.error or not isinstance(raw.data, dict):
            return []
        results = raw.data.get("results")
        if not isinstance(results, dict):
            return []
        findings: list[Finding] = []
        for filename, entries in results.items():
            if not isinstance(entries, list):
                continue
            path = relative_path(str(filename), ctx)
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                kind = str(entry.get("type") or "Secret")
                line = int(entry.get("line_number") or 0)
                findings.append(
                    Finding(
                        tool=NAME,
                        rule_id=kind,
                        severity=Severity.blocker,
                        category=Category.secret,
                        title=kind,
                        message=(
                            f"{kind} detected on line {line}; the value is never "
                            "uploaded (file, line, type and hash only)"
                        ),
                        file_path=path,
                        line_start=line,
                        line_end=line,
                        # The line itself carries the value: never the source
                        # text, only the metadata above (section 6).
                        snippet="",
                        raw={"hashed_secret": str(entry.get("hashed_secret") or "")},
                    )
                )
        return findings
