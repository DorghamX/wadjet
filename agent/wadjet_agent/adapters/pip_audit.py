"""pip-audit adapter (section 6): ``pip-audit -f json`` against the active
environment, or ``-r <file>`` per configured dependency file.

The JSON carries no severity: it comes from the project setting
``dependency_default_severity`` (default ``high``).  Category
``dependency``; fix text is rebuilt server-side from ``fix_versions``.
"""

from __future__ import annotations

import json
import subprocess
import time

from wadjet_schema import Category, Finding, Severity

from .base import AdapterInfo, RawOutput, RunContext, probe, run_command

#: Supported range, pinned in SUPPORTED.md.
MINIMUM, MAXIMUM = "2.7", "3"

NAME = "pip_audit"


class PipAuditAdapter:
    """Runs pip-audit and normalizes its JSON into dependency findings."""

    name = NAME

    def info(self) -> AdapterInfo:
        return probe("pip-audit", MINIMUM, MAXIMUM)

    def run(self, ctx: RunContext) -> RawOutput:
        options = ctx.tool_settings(NAME)
        argv = [ctx.python_executable, "-m", "pip_audit", "-f", "json"]
        files = options.get("dependency_files")
        if isinstance(files, list):
            for file in files:
                argv += ["-r", str(file)]

        started = time.monotonic()
        try:
            returncode, stdout, stderr = run_command(argv, ctx)
        except subprocess.TimeoutExpired:
            return RawOutput(None, ctx.timeout, f"pip-audit timed out after {ctx.timeout}s")
        except FileNotFoundError:
            return RawOutput(None, 0.0, f"{ctx.python_executable} is not runnable")
        except OSError as exc:
            return RawOutput(None, 0.0, f"pip-audit failed to start: {exc}")
        duration = time.monotonic() - started

        # pip-audit exits non-zero when it finds vulnerabilities: parseable
        # JSON is success, no matter the exit code.
        try:
            data = json.loads(stdout)
        except ValueError:
            detail = stderr.strip() or stdout.strip() or f"exit code {returncode}"
            return RawOutput(None, duration, f"pip-audit produced no JSON: {detail[:500]}")
        # Current pip-audit wraps the list in an object; older ones emit it bare.
        if isinstance(data, dict):
            dependencies = data.get("dependencies")
            data = dependencies if isinstance(dependencies, list) else None
        if not isinstance(data, list):
            return RawOutput(None, duration, "pip-audit JSON had no dependency list")
        return RawOutput(data, duration)

    def normalize(self, raw: RawOutput, ctx: RunContext) -> list[Finding]:
        if raw.error or not isinstance(raw.data, list):
            return []
        options = ctx.tool_settings(NAME)
        default_severity = str(options.get("dependency_default_severity") or "high")
        try:
            severity = Severity(default_severity)
        except ValueError:
            severity = Severity.high

        findings: list[Finding] = []
        for dependency in raw.data:
            if not isinstance(dependency, dict):
                continue
            package = str(dependency.get("name") or "")
            version = str(dependency.get("version") or "")
            for vuln in dependency.get("vulns") or []:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id") or "")
                if not package or not vuln_id:
                    continue
                description = str(
                    vuln.get("description") or f"{package} {version} is affected by {vuln_id}"
                )
                findings.append(
                    Finding(
                        tool=NAME,
                        rule_id=vuln_id,
                        severity=severity,
                        category=Category.dependency,
                        title=f"{package} {version}: {vuln_id}",
                        message=description,
                        file_path=None,
                        line_start=0,
                        line_end=0,
                        snippet="",
                        package=package,
                        installed_version=version,
                        vuln_id=vuln_id,
                        aliases=[str(alias) for alias in vuln.get("aliases") or []],
                        fixed_versions=[str(fixed) for fixed in vuln.get("fix_versions") or []],
                        raw=dict(vuln),
                    )
                )
        return findings
