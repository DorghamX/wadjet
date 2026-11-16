"""Unit tests for the fingerprint algorithm (section 5.2, T2.2)."""

from __future__ import annotations

from app.fingerprint import (
    code_fingerprint,
    compute_fingerprints,
    context_norm_hash,
    dep_fingerprint,
    flagged_norm_hash,
    normalize_text,
    pep503_name,
    split_snippet,
)
from wadjet_schema import Category, Finding, Severity

SNIPPET = "\n".join(
    [
        "import os",  # context
        "import sys",  # context
        "value = 1",  # context
        "assert value",  # flagged (line 10)
        "print(value)",  # context
        "print('a')",  # context
        "print('b')",  # context
    ]
)


def make_finding(**overrides: object) -> Finding:
    """A code finding whose snippet matches line_start=10 convention."""
    values: dict[str, object] = {
        "tool": "bandit",
        "rule_id": "B101",
        "severity": Severity.medium,
        "category": Category.bug,
        "title": "assert used",
        "message": "assert statement",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 10,
        "snippet": SNIPPET,
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


# --- normalization ---------------------------------------------------------


def test_normalize_text_strips_and_drops_empty_lines() -> None:
    assert normalize_text("  a  \n\n\tb\t\n   \n") == "a\nb"


def test_pep503_name_normalizes_separators_and_case() -> None:
    assert pep503_name("Django.Rest_Framework") == "django-rest-framework"
    assert pep503_name("zope.interface") == "zope-interface"
    assert pep503_name("already-normalized") == "already-normalized"


def test_split_snippet_follows_the_context_convention() -> None:
    flagged, context = split_snippet(SNIPPET, 10, 10)
    assert flagged == "assert value"
    assert context.splitlines() == [
        "import os",
        "import sys",
        "value = 1",
        "print(value)",
        "print('a')",
        "print('b')",
    ]


def test_split_snippet_flags_everything_when_near_the_top() -> None:
    snippet = "top = 1\nassert top"
    flagged, context = split_snippet(snippet, 2, 2)
    assert flagged == "assert top"
    assert context == "top = 1"


def test_split_snippet_of_unconventional_snippet_is_all_flagged() -> None:
    flagged, context = split_snippet("one line only", 42, 44)
    assert flagged == "one line only"
    assert context == ""


def test_hashes_of_flagged_and_context() -> None:
    assert flagged_norm_hash(SNIPPET)  # present, stable shape
    assert context_norm_hash("a\nb") == context_norm_hash(" a \n\n b ")
    assert context_norm_hash("a") != context_norm_hash("b")


# --- the code fingerprint ---------------------------------------------------


def _fp(**overrides: object) -> str:
    values: dict[str, object] = {
        "project_key": "demo",
        "tool": "bandit",
        "rule_id": "B101",
        "file_path": "src/app.py",
        "flagged_norm": "assert value",
        "context_hash": context_norm_hash("ctx"),
        "occurrence": 0,
    }
    values.update(overrides)
    return code_fingerprint(**values)  # type: ignore[arg-type]


def test_code_fingerprint_is_deterministic() -> None:
    assert _fp() == _fp()


def test_code_fingerprint_reacts_to_every_component() -> None:
    base = _fp()
    assert _fp(project_key="other") != base
    assert _fp(tool="ruff") != base
    assert _fp(rule_id="E501") != base
    assert _fp(file_path="src/other.py") != base
    assert _fp(flagged_norm="other") != base
    assert _fp(context_hash=context_norm_hash("other")) != base
    assert _fp(occurrence=1) != base


def test_dep_fingerprint_is_version_independent() -> None:
    """A flag survives an upgrade while the package stays vulnerable."""
    first = dep_fingerprint("demo", "CVE-2023-12345", "django")
    second = dep_fingerprint("demo", "CVE-2023-12345", "Django")
    assert first == second  # no version anywhere in the formula


def test_dep_fingerprint_reacts_to_identity_parts() -> None:
    base = dep_fingerprint("demo", "CVE-1", "django")
    assert dep_fingerprint("other", "CVE-1", "django") != base
    assert dep_fingerprint("demo", "CVE-2", "django") != base
    assert dep_fingerprint("demo", "CVE-1", "flask") != base
    # PEP 503: separators do not change identity
    assert dep_fingerprint("demo", "CVE-1", "zope.interface") == dep_fingerprint(
        "demo", "CVE-1", "zope-interface"
    )


# --- occurrence indexing ----------------------------------------------------


def test_line_shift_keeps_the_fingerprint() -> None:
    """Inserting lines at the top moves the code, not the identity."""
    before = make_finding()
    after = make_finding(line_start=25, line_end=25)
    (first,) = compute_fingerprints("demo", [before])
    (second,) = compute_fingerprints("demo", [after])
    assert first.fingerprint == second.fingerprint


def test_duplicate_identical_lines_get_distinct_fingerprints() -> None:
    """Two identical flagged lines are two issues (occurrence index n)."""
    first = make_finding(line_start=10, line_end=10)
    second = make_finding(line_start=40, line_end=40)
    computed = compute_fingerprints("demo", [first, second])
    assert computed[0].fingerprint != computed[1].fingerprint
    assert computed[0].occurrence == 0
    assert computed[1].occurrence == 1


def test_occurrence_is_ordered_by_line_not_by_input_order() -> None:
    low = make_finding(line_start=40, line_end=40)
    high = make_finding(line_start=10, line_end=10)
    computed = compute_fingerprints("demo", [low, high])
    by_line = {c.finding.line_start: c.occurrence for c in computed}
    assert by_line[10] == 0
    assert by_line[40] == 1


def test_different_rule_or_path_breaks_the_group() -> None:
    a = make_finding()
    b = make_finding(rule_id="B102")
    computed = compute_fingerprints("demo", [a, b])
    assert computed[0].occurrence == 0
    assert computed[1].occurrence == 0


def test_edited_flagged_line_changes_the_fingerprint() -> None:
    """A flag belongs to that exact snippet (section 5.4)."""
    before = make_finding()
    after = make_finding(snippet=SNIPPET.replace("assert value", "assert value > 0"))
    (first,) = compute_fingerprints("demo", [before])
    (second,) = compute_fingerprints("demo", [after])
    assert first.fingerprint != second.fingerprint


def test_dependency_finding_dispatch() -> None:
    dep = make_finding(
        tool="pip-audit",
        rule_id="CVE-2023-12345",
        category=Category.dependency,
        file_path=None,
        package="django",
        vuln_id="CVE-2023-12345",
        installed_version="4.2.0",
    )
    (computed,) = compute_fingerprints("demo", [dep])
    assert computed.is_dependency
    assert computed.fingerprint == dep_fingerprint("demo", "CVE-2023-12345", "django")


def test_fingerprint_differs_between_projects() -> None:
    finding = make_finding()
    (one,) = compute_fingerprints("project-a", [finding])
    (two,) = compute_fingerprints("project-b", [finding])
    assert one.fingerprint != two.fingerprint
