"""Shared Pydantic models between the Wadjet server and the Wadjet agent.

See section 5.1 of the build guide for the Finding contract.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    blocker = "blocker"
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Category(str, Enum):
    vulnerability = "vulnerability"
    dependency = "dependency"
    secret = "secret"
    bug = "bug"
    code_smell = "code_smell"


class Finding(BaseModel):
    """A normalized finding (section 5.1)."""

    tool: str
    rule_id: str
    severity: Severity
    category: Category
    title: str
    message: str
    file_path: str | None = Field(
        default=None, description="posix, relative to repo root; null for dependency findings"
    )
    line_start: int
    line_end: int
    snippet: str
    package: str | None = Field(default=None, description="package name, null for code findings")
    installed_version: str | None = Field(default=None)
    vuln_id: str | None = Field(default=None, description="e.g. CVE-2023-12345")
    aliases: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    cwe: str | None = Field(default=None, description="e.g. CWE-79")
    raw: dict[str, Any] | None = Field(default=None, description="scanner-specific extra data")


class AnalysisUpload(BaseModel):
    """Payload sent from the agent to the server (section 11)."""

    project_key: str
    commit_sha: str | None = Field(default=None)
    ci_url: str | None = Field(default=None)
    findings: list[Finding]
    metrics: dict[str, Any]
    scanner_runs: dict[str, Any]


class AnalysisResult(BaseModel):
    """Gate result returned to the agent after upload (section 9)."""

    analysis_id: str
    gate_status: str  # passed | failed
    gate_details: dict[str, Any]  # per-condition actual, threshold, triggered
    issues_resolved: int
    issues_created: int


class AgentConfig(BaseModel):
    """Configuration fetched by the agent from the server (section 11)."""

    project_key: str
    settings: dict[str, Any]  # scanner options, exclusions, gate id, etc.
    gate_conditions: dict[str, Any]
    exclusion_globs: list[str]


#: Human-readable fingerprint algorithm (section 5.2)
FINGERPRINT_CODE = (
    'sha256("code|" + project_key + "|" + tool + "|" + rule_id + "|" + file_path + '
    '"|" + norm_flagged_lines + "|" + sha256(norm(context)) + "|" + n)'
)
FINGERPRINT_DEP = 'sha256("dep|" + project_key + "|" + vuln_id + "|" + pep503_name(package))'
