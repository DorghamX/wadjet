"""Command line interface of the Wadjet agent (section 11).

``wadjet scan`` runs the flow, ``wadjet doctor`` checks tools and versions.
Exit codes: 0 gate passed, 1 gate failed, 2 config/auth/network error,
3 analysis incomplete (scanner error).
"""

from __future__ import annotations

from pathlib import Path

import typer

from .client import AgentError
from .scan import EXIT_CONFIG, run_scan
from .scan import doctor as run_doctor

app = typer.Typer(
    help="Run Wadjet scanners and upload findings to a Wadjet server.", no_args_is_help=True
)


@app.callback()
def root() -> None:
    """Wadjet analysis agent."""


@app.command()
def scan(
    path: Path | None = typer.Option(
        None, "--path", help="Repository root to scan (default: current directory)"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would run, without running it"
    ),
    report_json: Path | None = typer.Option(
        None,
        "--report-json",
        help="Write a machine-readable report (e.g. wadjet-report.json)",
    ),
) -> None:
    """Run the enabled scanners and upload the findings (section 11)."""
    repo_root = (path or Path.cwd()).resolve()
    try:
        code = run_scan(repo_root, dry_run=dry_run, report_path=report_json)
    except AgentError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_CONFIG) from None
    if code:
        raise typer.Exit(code)


@app.command()
def doctor() -> None:
    """Check tools, versions and server connectivity (section 11)."""
    raise typer.Exit(run_doctor())


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()
