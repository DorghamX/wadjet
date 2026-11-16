"""Validated project settings (section 10, T3.4).

The schema is what makes "structured options only, no free-form CLI
args" a test: anything the guide does not name must fail validation.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from wadjet_schema import (
    DEFAULT_EXCLUSION_GLOBS,
    DEFAULT_TIMEOUT_SECONDS,
    ProjectSettings,
)


def test_defaults_match_section_10() -> None:
    settings = ProjectSettings()
    # Failure policy default (section 6: fail_on_scanner_error default true).
    assert settings.fail_on_scanner_error is True
    assert settings.timeout_seconds == DEFAULT_TIMEOUT_SECONDS == 300.0
    assert settings.scope.include == ["."]
    assert settings.scope.exclude == list(DEFAULT_EXCLUSION_GLOBS)
    for name in ("bandit", "pip_audit", "ruff", "detect_secrets", "coverage"):
        scanner = getattr(settings.scanners, name)
        assert scanner.enabled is True
        assert scanner.timeout is None


def test_round_trips_through_json() -> None:
    settings = ProjectSettings.model_validate(
        {
            "scanners": {"ruff": {"families": ["F"], "timeout": 30}},
            "scope": {"include": ["src"], "exclude": ["tests/fixtures/"]},
        }
    )
    assert ProjectSettings.model_validate_json(settings.model_dump_json()) == settings


def test_named_structured_options_are_accepted() -> None:
    settings = ProjectSettings.model_validate(
        {
            "scanners": {
                "bandit": {
                    "skipped_test_ids": ["B101"],
                    "minimum_confidence": "medium",
                    "timeout": 60,
                },
                "pip_audit": {
                    "dependency_files": ["requirements.txt"],
                    "dependency_default_severity": "critical",
                },
                "ruff": {"families": ["F", "B", "C90", "PLE"]},
                "coverage": {"report_path": "coverage.xml"},
                "detect_secrets": {"enabled": False},
            },
            "scope": {"include": ["src", "tests"], "exclude": ["tests/fixtures/"]},
            "timeout_seconds": 60.0,
        }
    )
    assert settings.scanners.bandit.minimum_confidence == "medium"
    assert settings.scanners.pip_audit.dependency_default_severity == "critical"
    assert settings.scanners.ruff.families == ["F", "B", "C90", "PLE"]
    assert settings.scanners.coverage.report_path == "coverage.xml"
    assert settings.scanners.detect_secrets.enabled is False
    assert settings.scope.include == ["src", "tests"]


@pytest.mark.parametrize(
    "body",
    [
        {"extra_args": ["--fix"]},  # free-form CLI args, anywhere
        {"unknown": {}},
        {"scanners": {"semgrep": {"enabled": True}}},  # unknown scanner
        {"scanners": {"bandit": {"args": "-x"}}},  # free-form per scanner
        {"scanners": {"ruff": {"families": ["S"]}}},  # S duplicates Bandit
        {"scanners": {"ruff": {"families": ["f"]}}},  # lowercase typo
        {"scanners": {"bandit": {"minimum_confidence": "ultra"}}},
        {"scanners": {"pip_audit": {"dependency_default_severity": "zomg"}}},
        {"scanners": {"bandit": {"timeout": 0}}},  # must be positive
        {"scanners": {"bandit": {"timeout": -5}}},
        {"scope": {"include": []}},  # must name at least one path
        {"scope": {"include": ["  "]}},
        {"scope": {"unknown": []}},
        {"timeout_seconds": -1},
        {"fail_on_scanner_error": "maybe"},
    ],
)
def test_unsupported_shapes_are_rejected(body: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ProjectSettings.model_validate(body)
