"""Adapter protocol and shared run types (section 6).

Each adapter is one file (aim under 150 lines) with recorded output under
``fixtures/<tool>/<version>/`` and contract tests that parse the fixtures.
Supported version ranges are pinned in ``SUPPORTED.md``.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from wadjet_schema import Finding

#: Per-scanner timeout in seconds (settings may override; T3.4 formalises it).
DEFAULT_TIMEOUT = 300.0

#: Snippets are trimmed to this many characters before upload (section 11, step 6).
MAX_SNIPPET_CHARS = 4000

#: Context lines above and below the flagged lines (matches the server split).
CONTEXT_LINES = 3


@dataclass(frozen=True)
class AdapterInfo:
    """What ``doctor`` and ``scanner_runs`` need to know about one tool."""

    installed: bool
    version: str | None
    supported: bool
    detail: str


@dataclass(frozen=True)
class RawOutput:
    """One scanner invocation's result."""

    data: Any
    duration: float
    error: str | None = None  # None means the run succeeded


@dataclass
class RunContext:
    """Everything an adapter may look at while running (section 6)."""

    repo_root: Path
    include_paths: list[str]
    exclusion_globs: list[str]
    python_executable: str
    settings: dict[str, Any]
    timeout: float = DEFAULT_TIMEOUT

    def tool_settings(self, name: str) -> dict[str, Any]:
        """Structured options for one scanner (no free-form CLI args)."""
        scanners = self.settings.get("scanners")
        if isinstance(scanners, dict):
            options = scanners.get(name)
            if isinstance(options, dict):
                return options
        return {}

    def tool_enabled(self, name: str) -> bool:
        options = self.tool_settings(name)
        enabled = options.get("enabled", True)
        return bool(enabled)


@runtime_checkable
class Adapter(Protocol):
    """One scanner integration (section 6)."""

    name: str

    def info(self) -> AdapterInfo:
        """Installed? version? within the supported range?"""
        ...

    def run(self, ctx: RunContext) -> RawOutput:
        """Invoke the tool once and return its parsed output."""
        ...

    def normalize(self, raw: RawOutput, ctx: RunContext) -> list[Finding]:
        """Turn raw output into contract findings."""
        ...


def version_in_range(version: str, minimum: str, maximum: str) -> bool:
    """``minimum <= version < maximum`` over the numeric dotted prefixes."""

    def parts(value: str) -> tuple[int, ...]:
        numbers = re.findall(r"\d+", value)
        return tuple(int(number) for number in numbers[:3]) or (0,)

    return parts(minimum) <= parts(version) < parts(maximum)


def probe(distribution: str, minimum: str, maximum: str) -> AdapterInfo:
    """Describe an installed distribution without importing it."""
    try:
        version = metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return AdapterInfo(
            installed=False,
            version=None,
            supported=False,
            detail=f"{distribution} is not installed",
        )
    supported = version_in_range(version, minimum, maximum)
    detail = (
        f"{distribution} {version} (supported: >={minimum}, <{maximum})"
        if supported
        else f"{distribution} {version} is outside the supported range >={minimum}, <{maximum}"
    )
    return AdapterInfo(installed=True, version=version, supported=supported, detail=detail)


def local_executable(name: str) -> str | None:
    """Where a bare command name resolves next to the running interpreter.

    The agent scans with the tools from *its own* environment (``pip install
    wadjet-agent[scanners]``), but the subprocess inherits whatever ``PATH``
    the caller happened to have - in CI or a make target that often does not
    include ``.venv/bin``. Prefer the interpreter's directory so the binary
    ``probe`` reported as installed is the one we actually run.
    """
    if os.sep in name or (os.altsep and os.altsep in name):
        return None
    candidate = Path(sys.executable).parent / name
    return str(candidate) if candidate.is_file() else None


def run_command(argv: list[str], ctx: RunContext) -> tuple[int, str, str]:
    """Run one scanner; returns ``(returncode, stdout, stderr)``.

    Raises ``subprocess.TimeoutExpired`` past ``ctx.timeout`` and
    ``OSError`` when the executable is missing - adapters translate both
    into a recorded ``status=error`` run.
    """
    argv = list(argv)
    resolved = local_executable(argv[0])
    if resolved is not None:
        argv[0] = resolved
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=ctx.timeout,
        cwd=ctx.repo_root,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def build_snippet(
    repo_root: Path, path: str, line_start: int, line_end: int, context: int = CONTEXT_LINES
) -> str:
    """Read up to ``context`` lines around the flagged lines (section 5.2).

    The snippet contains exactly ``min(context, line_start - 1)`` lines above
    the flagged region - the same formula the server's ``split_snippet``
    uses to re-derive the split, so flagged lines and context agree at ingest.
    """
    if line_start < 1 or line_end < line_start:
        return ""
    try:
        lines = (repo_root / path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    flagged_index = line_start - 1
    if flagged_index >= len(lines):
        return ""
    start = flagged_index - min(context, flagged_index)
    stop = min(len(lines), line_end + context)
    if stop <= start:
        return ""
    return trim_snippet("\n".join(lines[start:stop]))


def trim_snippet(text: str) -> str:
    """Cap a snippet so one finding cannot bloat the upload (step 6)."""
    if len(text) <= MAX_SNIPPET_CHARS:
        return text
    return text[:MAX_SNIPPET_CHARS]
