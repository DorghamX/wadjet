"""The ``wadjet scan`` flow (section 11).

Exit codes: 0 gate passed, 1 gate failed, 2 config/auth/network error,
3 analysis incomplete (scanner error).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from wadjet_schema import AgentConfig, AnalysisUpload, Finding, filter_findings

from .adapters import ADAPTERS, Adapter, RunContext, enabled_adapters
from .ci import collect_ci_info, git_commit
from .client import AgentError, fetch_config, upload_analysis
from .coverage_report import collect_coverage_metrics, configured_report
from .report import print_summary, write_report

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_CONFIG = 2
EXIT_INCOMPLETE = 3


def read_env(env: Mapping[str, str]) -> tuple[str, str]:
    """``WADJET_URL`` and ``WADJET_TOKEN`` (section 11, step 1)."""
    base_url = (env.get("WADJET_URL") or "").strip()
    token = (env.get("WADJET_TOKEN") or "").strip()
    if not base_url or not token:
        raise AgentError("WADJET_URL and WADJET_TOKEN must both be set")
    return base_url, token


def build_context(config: AgentConfig, repo_root: Path) -> RunContext:
    """Turn the fetched config into a run context (section 11, step 2)."""
    scope = config.settings.get("scope")
    include_paths = ["."]
    if isinstance(scope, dict):
        include = scope.get("include")
        if isinstance(include, list) and include:
            include_paths = [str(path) for path in include]
    timeout = config.settings.get("timeout_seconds")
    return RunContext(
        repo_root=repo_root,
        include_paths=include_paths,
        exclusion_globs=list(config.exclusion_globs),
        python_executable=os.environ.get("WADJET_PYTHON") or _default_python(),
        settings=config.settings,
        timeout=float(timeout) if isinstance(timeout, (int, float)) else 300.0,
    )


def _default_python() -> str:
    return sys.executable or "python3"


def run_one_adapter(adapter: Adapter, ctx: RunContext) -> tuple[dict[str, Any], list[Finding]]:
    """Run one adapter and record its scanner_runs entry (section 6)."""
    info = adapter.info()
    record: dict[str, Any] = {"version": info.version}
    try:
        raw = adapter.run(ctx)
    except Exception as exc:  # noqa: BLE001 - a crash must not kill the scan
        record.update(status="error", duration=0.0, error=f"{adapter.name} crashed: {exc}")
        return record, []
    record["duration"] = round(raw.duration, 3)
    if raw.error:
        record.update(status="error", error=raw.error)
        return record, []
    try:
        findings = adapter.normalize(raw, ctx)
    except Exception as exc:  # noqa: BLE001 - malformed output must not kill the scan
        record.update(status="error", error=f"{adapter.name} output could not be parsed: {exc}")
        return record, []
    record["status"] = "ok"
    return record, findings


def print_plan(
    config: AgentConfig,
    ctx: RunContext,
    adapters: list[Adapter],
    out: Callable[[str], None] = print,
) -> None:
    """``scan --dry-run``: what would run, without running it (section 11)."""
    out("")
    out(f"Would scan project {config.project_key!r} at {ctx.repo_root}")
    out(f"  include paths : {', '.join(ctx.include_paths)}")
    out(f"  exclusions    : {', '.join(ctx.exclusion_globs) or '(none)'}")
    conditions = config.gate_conditions.get("conditions") or []
    if conditions:
        out(
            "  gate          : "
            + ", ".join(
                f"fail when {c['metric']} {c['operator']} {c['threshold']}" for c in conditions
            )
        )
    else:
        out("  gate          : (no conditions)")
    coverage_report = configured_report(ctx)
    out(f"  coverage      : {coverage_report or '(not configured)'}")
    out("")
    for adapter in adapters:
        info = adapter.info()
        state = info.detail if info.installed else f"NOT AVAILABLE - {info.detail}"
        out(f"  {adapter.name:<12} {state}")
    out("")


def run_scan(
    repo_root: Path,
    *,
    dry_run: bool = False,
    report_path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    """Execute one scan; returns the process exit code (section 11)."""
    environ: Mapping[str, str] = os.environ if env is None else env
    base_url, token = read_env(environ)
    config = fetch_config(base_url, token)
    ctx = build_context(config, repo_root)
    adapters = enabled_adapters(ctx)

    if dry_run:
        print_plan(config, ctx, adapters)
        return EXIT_OK

    runs: dict[str, dict[str, Any]] = {}
    findings: list[Finding] = []
    for adapter in adapters:
        record, produced = run_one_adapter(adapter, ctx)
        runs[adapter.name] = record
        findings.extend(produced)

    # Defense in depth: post-filter exclusions before the server's own pass.
    kept, _excluded = filter_findings(findings, ctx.exclusion_globs)

    # The coverage report is produced by the project's own test step: metrics
    # only, and a broken report warns instead of failing the run (the gate's
    # coverage condition carries the verdict - section 6 coverage row).
    coverage_metrics, coverage_warning = collect_coverage_metrics(ctx)
    if coverage_warning:
        print(f"warning: {coverage_warning}")

    commit_sha, ci_url = collect_ci_info(environ)
    if commit_sha is None:
        commit_sha = git_commit(repo_root)

    upload = AnalysisUpload(
        project_key=config.project_key,
        commit_sha=commit_sha,
        ci_url=ci_url,
        findings=kept,
        metrics=coverage_metrics,
        scanner_runs=runs,
    )
    result = upload_analysis(base_url, token, upload)

    print_summary(upload, result, base_url)
    if report_path is not None:
        write_report(report_path, upload, result, base_url)

    if any(run.get("status") == "error" for run in runs.values()):
        return EXIT_INCOMPLETE
    return EXIT_OK if result.gate_status == "passed" else EXIT_GATE_FAILED


def doctor(env: Mapping[str, str] | None = None, out: Callable[[str], None] = print) -> int:
    """``wadjet doctor``: check tools, versions and the server (section 11)."""
    environ: Mapping[str, str] = os.environ if env is None else env
    out("")
    out("Wadjet agent doctor")
    out("")
    out(f"  WADJET_URL    : {'set' if environ.get('WADJET_URL') else 'NOT SET'}")
    out(f"  WADJET_TOKEN  : {'set' if environ.get('WADJET_TOKEN') else 'NOT SET'}")
    out("")
    tools_ok = True
    for adapter in ADAPTERS.values():
        info = adapter.info()
        if not info.installed or not info.supported:
            tools_ok = False
        out(f"  {adapter.name:<12} {info.detail}")
    out("")

    config_ok = True
    if environ.get("WADJET_URL") and environ.get("WADJET_TOKEN"):
        base_url, token = read_env(environ)
        try:
            config = fetch_config(base_url, token)
        except AgentError as exc:
            config_ok = False
            out(f"  server: ERROR - {exc}")
        else:
            out(f"  server: OK - project {config.project_key!r} at {base_url}")
            # The coverage report belongs to the project's test step, so this
            # line is informational: it never changes the exit code.
            ctx = build_context(config, Path.cwd())
            report_path = configured_report(ctx)
            if report_path is None:
                out("  coverage      : report not configured")
            else:
                coverage_metrics, warning = collect_coverage_metrics(ctx)
                if warning is not None:
                    out(f"  coverage      : WARNING - {warning}")
                else:
                    percent = coverage_metrics["coverage_line_percent"]
                    out(f"  coverage      : {report_path} -> {percent:.1f}%")
    else:
        out("  server: skipped (WADJET_URL/WADJET_TOKEN not set)")
    out("")

    if not config_ok:
        return EXIT_CONFIG
    return EXIT_OK if tools_ok else EXIT_GATE_FAILED
