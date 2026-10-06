"""Enrichment knowledge base (section 6).

``server/app/kb/<tool>.yml`` maps ``rule_id`` to
``{title, description, impact, fix, references, cwe}``.  The server enriches
findings at ingest so text can improve without agent updates.

Rules of the section, implemented here:

- Bandit: full table in ``bandit.yml``, one entry per test ID.
- Ruff: description from ``raw.explanation``; impact and fix from a
  family-level fallback in ``ruff.yml``.
- pip-audit: description from the advisory, impact generic by vulnerability,
  fix text built from ``fixed_versions``.
- ``_fallback.yml`` for unknown rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from wadjet_schema import Category, Finding

KB_DIR = Path(__file__).resolve().parent

#: Tools that have their own YAML table; anything else uses the fallback.
TOOL_FILES = {
    "bandit": "bandit.yml",
    "ruff": "ruff.yml",
}
FALLBACK_FILE = "_fallback.yml"

#: Ruff families checked in longest-first order (C90 before C).
RUFF_FAMILIES = ("C90", "PLE", "PLW", "PLC", "E", "W", "F", "B")


@dataclass(frozen=True)
class Entry:
    """One row of a knowledge base file."""

    title: str
    description: str
    impact: str
    fix: str
    references: list[str] = field(default_factory=list)
    cwe: str | None = None


@dataclass(frozen=True)
class Enrichment:
    """The text the ingest writes onto the issue."""

    title: str
    description: str
    impact: str
    fix: str
    references: list[str]
    cwe: str | None


def _read_yaml(name: str) -> dict[str, Any]:
    path = KB_DIR / name
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a mapping of rule ids to entries")
    return data


@cache
def load_table(filename: str) -> dict[str, Entry]:
    """Load one YAML file into ``rule_id -> Entry`` (cached)."""
    table: dict[str, Entry] = {}
    for rule_id, raw in _read_yaml(filename).items():
        raw = raw or {}
        table[str(rule_id)] = Entry(
            title=str(raw.get("title") or ""),
            description=str(raw.get("description") or ""),
            impact=str(raw.get("impact") or ""),
            fix=str(raw.get("fix") or ""),
            references=[str(r) for r in (raw.get("references") or [])],
            cwe=str(raw["cwe"]) if raw.get("cwe") else None,
        )
    return table


@cache
def fallback_entry() -> Entry:
    """The ``_fallback.yml`` entry for unknown rules."""
    table = load_table(FALLBACK_FILE)
    return table["default"]


def get_entry(tool: str, rule_id: str) -> Entry:
    """The KB entry for a rule, falling back to ``_fallback.yml``."""
    filename = TOOL_FILES.get(tool)
    if filename is not None:
        entry = load_table(filename).get(rule_id)
        if entry is not None:
            return entry
    return fallback_entry()


def _ruff_family(rule_id: str) -> str | None:
    for family in RUFF_FAMILIES:
        if rule_id.startswith(family):
            return family
    return None


def _nvd_reference(vuln_id: str | None) -> list[str]:
    if vuln_id and vuln_id.upper().startswith("CVE-"):
        return [f"https://nvd.nist.gov/vuln/detail/{vuln_id.upper()}"]
    return []


def _dependency_enrichment(finding: Finding) -> Enrichment:
    """pip-audit: advisory text in, upgrade instruction out (section 6)."""
    package = finding.package or "this package"
    fixed = [str(v) for v in finding.fixed_versions]
    if fixed:
        fix = f"Upgrade `{package}` to `{', '.join(fixed)}`"
    else:
        fix = "No fixed version published yet; consider mitigation or replacement"
    raw = finding.raw or {}
    advisory_refs = [
        str(r) for r in (raw.get("references") or []) if isinstance(r, str) and r.startswith("http")
    ]
    return Enrichment(
        title=finding.title,
        description=finding.message,
        impact=(
            f"A known vulnerability in `{package}` is reachable through your "
            "dependencies: anything this package does on behalf of your "
            "application - parsing input, handling crypto, talking to the "
            "network - can be abused the way the advisory describes."
        ),
        fix=fix,
        references=[*_nvd_reference(finding.vuln_id), *advisory_refs],
        cwe=finding.cwe,
    )


def _ruff_enrichment(finding: Finding) -> Enrichment:
    """Ruff: description from the fetched explanation, family fallback text."""
    raw = finding.raw or {}
    explanation = str(raw.get("explanation") or "").strip()
    family = _ruff_family(finding.rule_id)
    entry = load_table(TOOL_FILES["ruff"]).get(family) if family else None
    if entry is None:
        entry = get_entry("ruff", finding.rule_id)  # exact rule, else fallback
    return Enrichment(
        title=finding.title,
        description=explanation or finding.message,
        impact=entry.impact,
        fix=entry.fix,
        references=list(entry.references),
        cwe=finding.cwe or entry.cwe,
    )


def enrich_finding(finding: Finding) -> Enrichment:
    """Produce the issue text for one finding (called at ingest)."""
    if finding.category == Category.dependency:
        return _dependency_enrichment(finding)
    if finding.tool == "ruff":
        return _ruff_enrichment(finding)

    entry = get_entry(finding.tool, finding.rule_id)
    return Enrichment(
        title=entry.title or finding.title,
        description=entry.description or finding.message,
        impact=entry.impact,
        fix=entry.fix,
        references=list(entry.references),
        cwe=entry.cwe or finding.cwe,
    )


__all__ = [
    "Enrichment",
    "Entry",
    "enrich_finding",
    "fallback_entry",
    "get_entry",
    "load_table",
]
