"""Shared exclusion matching (section 10, defense in depth).

The agent post-filters findings by path and the server drops any finding
whose path matches, so both sides must agree exactly: one implementation in
the shared contract package, never two.

Globs are gitignore-style. The plain-name case (``.venv/``) matches a path
segment at any depth; patterns with wildcards or slashes match the whole
relative path, where ``fnmatch``'s ``*`` crosses ``/`` just like gitignore's
does for simple patterns. Dependency findings have no path and are never
excluded.
"""

from __future__ import annotations

from collections.abc import Sequence
from fnmatch import fnmatch

from .models import Finding

#: The editable defaults the UI shows (section 10).
DEFAULT_EXCLUSION_GLOBS: tuple[str, ...] = (
    ".venv/",
    "venv/",
    "node_modules/",
    ".git/",
    "build/",
    "dist/",
    "__pycache__/",
    "site-packages/",
)


def path_is_excluded(path: str, globs: Sequence[str]) -> bool:
    """Whether a POSIX-relative path matches any exclusion glob."""
    normalized = path.removeprefix("./").strip("/")
    if not normalized:
        return False
    parts = [part for part in normalized.split("/") if part]
    for raw in globs:
        glob = str(raw).strip().strip("/")
        if not glob:
            continue
        if "/" not in glob and not any(ch in glob for ch in "*?["):
            # Plain directory or file name: matches at any depth.
            if any(fnmatch(part, glob) for part in parts):
                return True
            continue
        if fnmatch(normalized, glob) or fnmatch(normalized, glob + "/*"):
            return True
        if glob.startswith("**/") and fnmatch(normalized, glob.removeprefix("**/")):
            return True
    return False


def filter_findings(findings: Sequence[Finding], globs: Sequence[str]) -> tuple[list[Finding], int]:
    """Split findings into ``(kept, excluded_count)``.

    Dependency findings (no path) are never excluded (section 10).
    """
    kept: list[Finding] = []
    excluded = 0
    for finding in findings:
        if finding.file_path and path_is_excluded(finding.file_path, globs):
            excluded += 1
        else:
            kept.append(finding)
    return kept, excluded
