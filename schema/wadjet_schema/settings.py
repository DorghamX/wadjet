"""Validated project settings (section 10).

Structured options only: no free-form CLI arguments anywhere. The server
validates this schema on write, so the stored ``projects.settings`` JSON is
always well-formed; reads (the agent's ``AgentConfig.settings`` and the
ingest exclusion pass) consume the same keys through plain dicts, because
the agent contract is frozen since T0.4.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .exclusions import DEFAULT_EXCLUSION_GLOBS

#: Scanners that may carry their own section (the agent's adapter keys).
SCANNER_NAMES = ("bandit", "pip_audit", "ruff", "detect_secrets", "coverage")

#: Global default for one scan, in seconds (the agent's DEFAULT_TIMEOUT).
DEFAULT_TIMEOUT_SECONDS = 300.0

#: What ``pip-audit``'s ``dependency_default_severity`` may name.
SeverityName = Literal["blocker", "critical", "high", "medium", "low", "info"]


class ScannerSettings(BaseModel):
    """One scanner's section: enable flag, timeout, structured options."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    #: Seconds for this scanner only; overrides ``timeout_seconds``.
    timeout: float | None = Field(default=None, gt=0)
    # -- bandit ----------------------------------------------------------
    skipped_test_ids: list[str] = Field(default_factory=list)
    minimum_confidence: Literal["low", "medium", "high"] | None = None
    # -- pip-audit -------------------------------------------------------
    dependency_files: list[str] = Field(default_factory=list)
    dependency_default_severity: SeverityName | None = None
    # -- ruff: empty falls back to the section 6 defaults (F,B,C90,PLE) --
    families: list[str] = Field(default_factory=list)
    # -- coverage: repo-relative report path -----------------------------
    report_path: str | None = None

    @field_validator("families")
    @classmethod
    def _family_codes(cls, value: list[str]) -> list[str]:
        for family in value:
            if not family or family != family.upper():
                raise ValueError(
                    f"invalid ruff family {family!r}: expected an uppercase code such as F or C90"
                )
        if "S" in value:
            raise ValueError("the S family duplicates Bandit; leave it out")
        return value


class ScopeSettings(BaseModel):
    """Where to scan: include paths and gitignore-style exclusion globs."""

    model_config = ConfigDict(extra="forbid")

    include: list[str] = Field(default_factory=lambda: ["."])
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUSION_GLOBS))

    @field_validator("include")
    @classmethod
    def _non_empty_include(cls, value: list[str]) -> list[str]:
        if not value or any(not str(path).strip() for path in value):
            raise ValueError("include needs at least one non-empty path")
        return value


class ScannersSettings(BaseModel):
    """One subsection per scanner; unknown keys are rejected (section 10)."""

    model_config = ConfigDict(extra="forbid")

    bandit: ScannerSettings = Field(default_factory=ScannerSettings)
    pip_audit: ScannerSettings = Field(default_factory=ScannerSettings)
    ruff: ScannerSettings = Field(default_factory=ScannerSettings)
    detect_secrets: ScannerSettings = Field(default_factory=ScannerSettings)
    coverage: ScannerSettings = Field(default_factory=ScannerSettings)


class ProjectSettings(BaseModel):
    """Everything ``projects.settings`` may hold (section 10).

    Quality gate choice, general fields, tokens and members live on the
    project row and their own tables, not here.
    """

    model_config = ConfigDict(extra="forbid")

    scanners: ScannersSettings = Field(default_factory=ScannersSettings)
    scope: ScopeSettings = Field(default_factory=ScopeSettings)
    #: Failure policy (section 6): default true, a scanner error fails the
    #: gate with the synthetic "All enabled scanners completed" condition.
    fail_on_scanner_error: bool = True
    timeout_seconds: float = Field(default=DEFAULT_TIMEOUT_SECONDS, gt=0)
