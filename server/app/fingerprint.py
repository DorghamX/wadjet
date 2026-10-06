"""Fingerprints: the identity of a finding (section 5.2).

Pure functions only - no database, no clock, no I/O - so the algorithm can be
unit tested in isolation and reused by the server ingest and the agent.

Normalization: split a snippet into lines, strip each line, drop empty lines,
join with ``\\n``.

- Code: ``sha256("code|" + project_key + "|" + tool + "|" + rule_id + "|"
  + file_path + "|" + norm(flagged) + "|" + sha256(norm(context)) + "|" + n)``
  where ``n`` is the occurrence index among findings with identical
  (tool, rule_id, file_path, norm(flagged)) in the same analysis, ordered by
  line.  Line numbers deliberately do not take part: inserting lines at the
  top of a file keeps the fingerprint, so a carried-over flag survives a
  line shift.
- Dependency: ``sha256("dep|" + project_key + "|" + vuln_id + "|"
  + pep503_name(package))`` - version independent, so a flag survives an
  upgrade while the package stays vulnerable.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass

from wadjet_schema import Finding

#: Lines of context kept on each side of a snippet (section 5.1).
CONTEXT_LINES = 3

#: How a finding's identity is decided: dependency findings use the version
#: independent dependency fingerprint, everything else the code fingerprint.
DEPENDENCY_CATEGORY = "dependency"


def normalize_text(text: str) -> str:
    """Split into lines, strip each, drop empty lines, join with ``\\n``."""
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def pep503_name(name: str) -> str:
    """Normalize a Python package name per PEP 503 (section 5.2)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_hex(text: str) -> str:
    """Hex SHA-256 of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def split_snippet(
    snippet: str | None, line_start: int | None, line_end: int | None
) -> tuple[str, str]:
    """Split a stored snippet into ``(flagged_text, context_text)``.

    The agent builds a snippet as up to :data:`CONTEXT_LINES` context lines
    above the flagged lines, the flagged lines themselves (``line_start`` to
    ``line_end``), then up to :data:`CONTEXT_LINES` below, so the split is
    derivable from the line numbers.  A snippet that does not follow the
    convention (trimmed by a scanner, dependency findings) is treated as
    entirely flagged with no context.
    """
    if not snippet:
        return "", ""
    lines = snippet.splitlines()
    if line_start is None or line_end is None:
        return snippet, ""
    n_flagged = max(1, line_end - line_start + 1)
    above = min(CONTEXT_LINES, max(0, line_start - 1))
    above = min(above, max(0, len(lines) - 1))
    flagged_lines = lines[above : above + n_flagged]
    if not flagged_lines:
        return snippet, ""
    context_lines = lines[:above] + lines[above + n_flagged :]
    return "\n".join(flagged_lines), "\n".join(context_lines)


def flagged_norm_hash(flagged: str) -> str:
    """``sha256(norm(flagged_lines))`` - the half of the identity that survives
    a nearby-code edit."""
    return sha256_hex(normalize_text(flagged))


def context_norm_hash(context: str) -> str:
    """``sha256(norm(context))`` - the half that pins the surrounding code."""
    return sha256_hex(normalize_text(context))


def code_fingerprint(
    project_key: str,
    tool: str,
    rule_id: str,
    file_path: str,
    flagged_norm: str,
    context_hash: str,
    occurrence: int,
) -> str:
    """The code finding fingerprint from section 5.2."""
    payload = "|".join(
        (
            "code",
            project_key,
            tool,
            rule_id,
            file_path,
            flagged_norm,
            context_hash,
            str(occurrence),
        )
    )
    return sha256_hex(payload)


def dep_fingerprint(project_key: str, vuln_id: str, package: str) -> str:
    """The dependency finding fingerprint from section 5.2 (version free)."""
    payload = "|".join(("dep", project_key, vuln_id, pep503_name(package)))
    return sha256_hex(payload)


@dataclass(frozen=True)
class ComputedFinding:
    """A finding with its identity pieces already derived."""

    finding: Finding
    fingerprint: str
    flagged_norm: str
    context_hash: str
    occurrence: int

    @property
    def is_dependency(self) -> bool:
        return self.finding.category == DEPENDENCY_CATEGORY

    @property
    def group_key(self) -> tuple[str, str, str | None, str]:
        """(tool, rule_id, file_path, flagged_norm) for occurrence indexing."""
        f = self.finding
        return (f.tool, f.rule_id, f.file_path, self.flagged_norm)


def compute_fingerprints(project_key: str, findings: Sequence[Finding]) -> list[ComputedFinding]:
    """Compute the fingerprint of every finding in one analysis.

    Occurrence indices are assigned per group of identical
    (tool, rule_id, file_path, norm(flagged)) ordered by line, so duplicate
    identical lines in one file stay two distinct issues.
    """
    # Pass 1: derive the flagged/context pieces for code findings.
    pieces: list[tuple[str, str]] = []
    for f in findings:
        if f.category == DEPENDENCY_CATEGORY:
            pieces.append(("", ""))
        else:
            flagged, context = split_snippet(f.snippet, f.line_start, f.line_end)
            pieces.append((normalize_text(flagged), context_norm_hash(context)))

    # Pass 2: occurrence index per group, ordered by line then input order.
    groups: dict[tuple[str, str, str | None, str], list[int]] = {}
    for index, f in enumerate(findings):
        flagged_norm, _ = pieces[index]
        if f.category == DEPENDENCY_CATEGORY:
            continue
        key = (f.tool, f.rule_id, f.file_path, flagged_norm)
        groups.setdefault(key, []).append(index)
    occurrence_of: dict[int, int] = {}
    for members in groups.values():
        ordered = sorted(members, key=lambda i: (findings[i].line_start or 0, i))
        for position, index in enumerate(ordered):
            occurrence_of[index] = position

    # Pass 3: the fingerprint itself.
    computed: list[ComputedFinding] = []
    for index, f in enumerate(findings):
        flagged_norm, context_hash = pieces[index]
        if f.category == DEPENDENCY_CATEGORY:
            fingerprint = dep_fingerprint(project_key, f.vuln_id or "", f.package or "")
            computed.append(
                ComputedFinding(
                    finding=f,
                    fingerprint=fingerprint,
                    flagged_norm="",
                    context_hash="",
                    occurrence=0,
                )
            )
        else:
            occurrence = occurrence_of[index]
            fingerprint = code_fingerprint(
                project_key,
                f.tool,
                f.rule_id,
                f.file_path or "",
                flagged_norm,
                context_hash,
                occurrence,
            )
            computed.append(
                ComputedFinding(
                    finding=f,
                    fingerprint=fingerprint,
                    flagged_norm=flagged_norm,
                    context_hash=context_hash,
                    occurrence=occurrence,
                )
            )
    return computed
