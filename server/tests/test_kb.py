"""Knowledge base completeness and enrichment tests (section 6, T2.3)."""

from __future__ import annotations

import importlib.util
import re

from app.kb import enrich_finding, fallback_entry, get_entry, load_table
from wadjet_schema import Category, Finding, Severity

# The complete Bandit test registry (bandit 1.9.4), frozen here so the
# completeness test runs even where bandit itself is not installed. The
# cross-check below fails if an installed bandit knows IDs we do not.
BANDIT_TEST_IDS = [
    "B101",
    "B102",
    "B103",
    "B104",
    "B105",
    "B106",
    "B107",
    "B108",
    "B110",
    "B112",
    "B113",
    "B201",
    "B202",
    "B301",
    "B302",
    "B303",
    "B304",
    "B305",
    "B306",
    "B307",
    "B308",
    "B310",
    "B311",
    "B312",
    "B313",
    "B314",
    "B315",
    "B316",
    "B317",
    "B318",
    "B319",
    "B321",
    "B323",
    "B324",
    "B401",
    "B402",
    "B403",
    "B404",
    "B405",
    "B406",
    "B407",
    "B408",
    "B409",
    "B411",
    "B412",
    "B413",
    "B415",
    "B501",
    "B502",
    "B503",
    "B504",
    "B505",
    "B506",
    "B507",
    "B508",
    "B509",
    "B601",
    "B602",
    "B603",
    "B604",
    "B605",
    "B606",
    "B607",
    "B608",
    "B609",
    "B610",
    "B611",
    "B612",
    "B613",
    "B614",
    "B615",
    "B701",
    "B702",
    "B703",
    "B704",
]


def make_finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "tool": "bandit",
        "rule_id": "B101",
        "severity": Severity.medium,
        "category": Category.bug,
        "title": "Assert used",
        "message": "assert statement found",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 10,
        "snippet": "assert value",
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


# --- completeness -----------------------------------------------------------


def test_bandit_kb_has_every_test_id() -> None:
    """A test must fail if any Bandit test ID is missing from the KB."""
    table = load_table("bandit.yml")
    missing = [tid for tid in BANDIT_TEST_IDS if tid not in table]
    assert missing == [], f"bandit.yml is missing entries for: {missing}"


def test_bandit_kb_has_no_stale_ids() -> None:
    """Nothing sits in bandit.yml that is not a Bandit test ID."""
    table = load_table("bandit.yml")
    stale = [tid for tid in table if tid not in BANDIT_TEST_IDS]
    assert stale == [], f"bandit.yml has unknown ids: {stale}"


def test_bandit_kb_matches_installed_bandit_when_available() -> None:
    """If bandit is installed, its registry and our KB must agree exactly."""
    if importlib.util.find_spec("bandit") is None:
        import pytest

        pytest.skip("bandit is not installed in this environment")
    from importlib.metadata import entry_points

    from bandit.blacklists import calls, imports

    registry: set[str] = set()
    for ep in entry_points(group="bandit.plugins"):
        fn = ep.load()
        test_id = getattr(fn, "_test_id", None)
        if test_id:
            registry.add(test_id)
    for module in (calls, imports):
        for entries in module.gen_blacklist().values():
            registry.update(entry["id"] for entry in entries)

    table = set(load_table("bandit.yml"))
    assert table == registry, f"missing={sorted(registry - table)} stale={sorted(table - registry)}"


def test_every_bandit_entry_is_complete() -> None:
    """Title, description, impact, fix and references are all populated."""
    table = load_table("bandit.yml")
    problems: list[str] = []
    for rule_id, entry in table.items():
        for field in ("title", "description", "impact", "fix"):
            if not getattr(entry, field).strip():
                problems.append(f"{rule_id}: empty {field}")
        if not entry.references:
            problems.append(f"{rule_id}: no references")
        if not all(ref.startswith("https://") for ref in entry.references):
            problems.append(f"{rule_id}: reference is not https")
        if entry.cwe is not None and not re.fullmatch(r"CWE-\d+", entry.cwe):
            problems.append(f"{rule_id}: malformed cwe {entry.cwe!r}")
    assert problems == []


def test_impact_describes_consequences_not_the_rule() -> None:
    """Impact must say what an attacker gains, not restate the finding."""
    table = load_table("bandit.yml")
    problems: list[str] = []
    for rule_id, entry in table.items():
        if entry.impact.strip() == entry.description.strip():
            problems.append(f"{rule_id}: impact restates description")
        if entry.impact.strip() == entry.title.strip():
            problems.append(f"{rule_id}: impact restates title")
        if len(entry.impact.strip()) < 80:
            problems.append(f"{rule_id}: impact too short to describe impact")
    assert problems == []


def test_some_fixes_carry_code_examples() -> None:
    """Where a fix makes sense it shows before/after code (section 6)."""
    table = load_table("bandit.yml")
    with_code = [r for r, e in table.items() if "```" in e.fix]
    assert len(with_code) >= 20, "too few fixes carry a code example"


def test_blacklist_entries_have_cwes() -> None:
    """The B3xx/B4xx blacklist IDs carry the CWE bandit itself assigns."""
    table = load_table("bandit.yml")
    for rule_id in ("B301", "B303", "B307", "B308", "B403", "B404"):
        assert table[rule_id].cwe is not None, rule_id


# --- fallback ---------------------------------------------------------------


def test_fallback_entry_fits_unknown_rules() -> None:
    """_fallback.yml provides generic impact/fix; description stays empty so
    the scanner's own message fills it in."""
    entry = fallback_entry()
    assert entry.impact.strip()
    assert entry.fix.strip()
    assert entry.description == ""


def test_get_entry_falls_back_for_unknown_rule() -> None:
    assert get_entry("bandit", "B999999") is fallback_entry()
    assert get_entry("some-new-tool", "whatever") is fallback_entry()


def test_get_entry_returns_bandit_entry() -> None:
    entry = get_entry("bandit", "B101")
    assert entry.title == "Assert used"
    assert entry is not fallback_entry()


# --- enrichment -------------------------------------------------------------


def test_bandit_enrichment_uses_the_kb() -> None:
    """KB text wins over scanner text; scanner cwe fills a KB gap."""
    finding = make_finding(rule_id="B101", cwe=None)
    result = enrich_finding(finding)
    entry = get_entry("bandit", "B101")
    assert result.title == entry.title
    assert result.description == entry.description
    assert result.impact == entry.impact
    assert result.fix == entry.fix
    assert result.cwe == "CWE-617"
    assert result.references == entry.references


def test_bandit_enrichment_unknown_rule_keeps_scanner_text() -> None:
    finding = make_finding(rule_id="B999999", message="scanner says what")
    result = enrich_finding(finding)
    assert result.description == "scanner says what"
    assert result.impact == fallback_entry().impact
    assert result.fix == fallback_entry().fix


def test_bandit_enrichment_prefers_entry_cwe_over_scanner() -> None:
    finding = make_finding(rule_id="B101", cwe="CWE-000")
    assert enrich_finding(finding).cwe == "CWE-617"


def test_dependency_enrichment_with_fix_versions() -> None:
    """pip-audit: description from the advisory, upgrade instruction from
    fix_versions (section 6)."""
    finding = make_finding(
        tool="pip-audit",
        rule_id="CVE-2023-12345",
        category=Category.dependency,
        file_path=None,
        package="django",
        vuln_id="CVE-2023-12345",
        title="django 4.2.0 has a vulnerability",
        message="advisory text from the database",
        fixed_versions=["4.2.1", "5.0.1"],
        snippet="",
    )
    result = enrich_finding(finding)
    assert result.description == "advisory text from the database"
    assert result.fix == "Upgrade `django` to `4.2.1, 5.0.1`"
    assert "django" in result.impact
    assert result.references[0] == "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"


def test_dependency_enrichment_without_fix_versions() -> None:
    finding = make_finding(
        tool="pip-audit",
        rule_id="CVE-2024-0001",
        category=Category.dependency,
        file_path=None,
        package="leftpad",
        vuln_id="CVE-2024-0001",
        title="leftpad advisory",
        message="advisory text",
        fixed_versions=[],
        snippet="",
    )
    result = enrich_finding(finding)
    assert result.fix == "No fixed version published yet; consider mitigation or replacement"


def test_dependency_enrichment_uses_advisory_references() -> None:
    finding = make_finding(
        tool="pip-audit",
        rule_id="GHSA-xxxx",
        category=Category.dependency,
        file_path=None,
        package="requests",
        vuln_id="GHSA-1234",
        title="advisory",
        message="advisory text",
        raw={"references": ["https://github.com/advisories/GHSA-1234", "not-a-url"]},
        snippet="",
    )
    result = enrich_finding(finding)
    assert result.references == ["https://github.com/advisories/GHSA-1234"]


def test_ruff_enrichment_prefers_raw_explanation() -> None:
    finding = make_finding(
        tool="ruff",
        rule_id="F401",
        title="[F401] unused import",
        message="module imported but unused",
        raw={"explanation": "F401: the import is never used."},
    )
    result = enrich_finding(finding)
    assert result.description == "F401: the import is never used."
    assert result.impact == load_table("ruff.yml")["F"].impact
    assert result.fix == load_table("ruff.yml")["F"].fix
    assert result.title == "[F401] unused import"


def test_ruff_enrichment_falls_back_to_scanner_message() -> None:
    finding = make_finding(
        tool="ruff",
        rule_id="B006",
        title="B006 mutable default",
        message="do not use mutable defaults",
        raw=None,
    )
    result = enrich_finding(finding)
    assert result.description == "do not use mutable defaults"
    assert result.impact == load_table("ruff.yml")["B"].impact


def test_ruff_enrichment_unknown_family_uses_fallback() -> None:
    finding = make_finding(
        tool="ruff",
        rule_id="S101",
        title="S101 assert",
        message="assert used",
        raw=None,
    )
    result = enrich_finding(finding)
    assert result.impact == fallback_entry().impact
