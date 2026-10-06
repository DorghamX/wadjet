"""Demo dataset for the UI (section 17, T4.0): ``wadjet-server seed-demo``.

Everything is deterministic - fixed usernames (``demo-`` prefixed), fixed
project keys, fingerprints derived from ``project|tool|rule|file`` - and
inserted in ONE transaction: a failed seed leaves nothing behind, and a
second run prints a skip message instead of duplicating rows.

The dataset covers every page the UI renders: users for each permission
template, a group with group grants, projects carrying validated
settings, two gates, analyses that passed / failed / came back
incomplete, issues across every severity, category, triage status and
presence, a triaged-and-resolved history with events, comments and
requests, tokens and audit entries. Notifications arrive with T5.2 and
extend this module.

Gate results are produced by the real evaluator (``evaluate_gate``) with
each analysis' own historical metrics, so past gate rows stay consistent
with their stored metrics instead of being recomputed from today's
issues; the latest analysis of every project matches the current issue
table exactly (asserted in the tests).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Connection, Engine, text

from app.gate import ISSUE_METRICS, evaluate_gate
from app.permissions import PERMISSION_TEMPLATES
from app.security import hash_password
from app.tokens import generate_token
from wadjet_schema import ProjectSettings

#: One password for every demo account (demo tooling, printed on seed).
DEMO_PASSWORD = "demo-password"

#: The seed is markered on this account; it never touches other users.
DEMO_ADMIN = "demo-admin"

#: (username, display name, is_admin, last login days ago)
DEMO_USERS: tuple[tuple[str, str, bool, int], ...] = (
    (DEMO_ADMIN, "Wadjet Admin", True, 0),
    ("demo-alice", "Alice Nguyen", False, 1),
    ("demo-bob", "Bob Okafor", False, 2),
    ("demo-carol", "Carol Reyes", False, 1),
    ("demo-dave", "Dave Lindqvist", False, 5),
)

#: Fixed project keys - also the wipe markers if the demo is ever reset.
DEMO_PROJECT_KEYS = ("payments", "web-portal", "data-pipeline")

RELEASE_GATE_CONDITIONS = (
    ("issues_blocker", ">", 0.0),
    ("secrets", ">", 0.0),
    ("issues_total", ">", 10.0),
    ("coverage_line_percent", "<", 85.0),
)

#: (grant plan) project key, subject type, template - subjects resolved later.
GRANT_PLAN = (
    ("payments", "user", "demo-alice", "project_admin"),
    ("payments", "user", "demo-bob", "developer"),
    ("payments", "user", "demo-carol", "triager"),
    ("payments", "user", "demo-dave", "viewer"),
    ("web-portal", "group", "Platform team", "triager"),
    ("data-pipeline", "group", "Platform team", "developer"),
    ("data-pipeline", "user", "demo-dave", "viewer"),
)


def _ago(days: int = 0, hours: int = 0, minutes: int = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days, hours=hours, minutes=minutes)


def _insert(conn: Connection, table: str, row: dict[str, Any]) -> int:
    """Insert one row and return its identity id."""
    columns = ", ".join(f'"{name}"' for name in row)
    placeholders = ", ".join(f":{name}" for name in row)
    result = conn.execute(
        text(f'INSERT INTO "{table}" ({columns}) VALUES ({placeholders}) RETURNING id'),
        row,
    )
    return int(result.scalar_one())


def _fingerprint(project_key: str, tool: str, rule_id: str, file_path: str) -> str:
    """A deterministic 64-hex fingerprint (the ingest format, not its inputs)."""
    seed = f"{project_key}|{tool}|{rule_id}|{file_path}"
    return hashlib.sha256(seed.encode()).hexdigest()


def _metrics(**values: float) -> dict[str, float]:
    """Full section-9 issue metrics; overrides name the non-zero ones."""
    metrics = dict.fromkeys(ISSUE_METRICS, 0.0)
    metrics.update(values)
    return metrics


def _scanner_runs(*, bandit_error: str | None = None) -> str:
    bandit: dict[str, Any] = {"version": "1.7.10", "status": "ok", "duration": 3.4}
    if bandit_error is not None:
        bandit.update(status="error", duration=0.0, error=bandit_error)
    return json.dumps(
        {
            "bandit": bandit,
            "pip_audit": {"version": "2.7.3", "status": "ok", "duration": 8.2},
            "ruff": {"version": "0.16.10", "status": "ok", "duration": 0.6},
            "detect_secrets": {"version": "1.5.0", "status": "ok", "duration": 1.1},
        }
    )


def _issue(
    project_key: str,
    *,
    alias: str,
    first: tuple[str, int],
    last: tuple[str, int],
    created_days: int,
    **values: Any,
) -> dict[str, Any]:
    """One issue row; ``first``/``last`` name the (project, index) analyses."""
    row: dict[str, Any] = {
        "tool": "bandit",
        "line_start": 1,
        "line_end": 1,
        "snippet": "",
        "triage_status": "open",
        "presence": "present",
        "created_at": _ago(created_days),
    }
    row.update(values)
    row["_alias"] = alias
    row["_first"] = first
    row["_last"] = last
    row["fingerprint"] = _fingerprint(
        project_key, str(row["tool"]), str(row["rule_id"]), str(row.get("file_path") or "")
    )
    return row


_SECRET_IMPACT = (
    "A credential committed to the repository is readable by anyone with access "
    "to it - and by every fork, mirror and CI log that ever saw it: once a secret "
    "is in history it must be treated as compromised."
)
_SECRET_FIX = (
    "Rotate the credential at its provider, replace the value with a configuration "
    "or secret-manager reference, and purge the old value from the repository history."
)


def _project_settings() -> dict[str, str]:
    """Validated settings JSON per project (one schema, section 10)."""
    return {
        "payments": ProjectSettings.model_validate(
            {
                "scanners": {
                    "bandit": {"skipped_test_ids": ["B101"]},
                    "ruff": {"families": ["F", "B", "C90", "PLE"]},
                    "coverage": {"report_path": "coverage.xml"},
                },
                "scope": {"include": ["src", "tests"]},
                "timeout_seconds": 120,
            }
        ).model_dump_json(),
        "web-portal": ProjectSettings().model_dump_json(),
        "data-pipeline": ProjectSettings.model_validate(
            {"scanners": {"pip_audit": {"dependency_files": ["requirements.txt"]}}}
        ).model_dump_json(),
    }


def _already_seeded(conn: Connection) -> bool:
    row = conn.execute(
        text("SELECT 1 FROM users WHERE username = :name"), {"name": DEMO_ADMIN}
    ).scalar()
    return row is not None


def seed_demo(engine: Engine) -> dict[str, int]:
    """Insert the demo dataset in one transaction.

    Returns the per-table counts, or an empty dict when the demo data is
    already present (the command is idempotent).
    """
    with engine.begin() as conn:
        if _already_seeded(conn):
            return {}
        return _seed(conn)


def _seed(conn: Connection) -> dict[str, int]:
    # --- users, group, gate ------------------------------------------------
    password_hash = hash_password(DEMO_PASSWORD)
    users: dict[str, int] = {}
    for username, display, is_admin, login_days in DEMO_USERS:
        users[username] = _insert(
            conn,
            "users",
            {
                "username": username,
                "email": f"{username}@wadjet.demo",
                "display_name": display,
                "password_hash": password_hash,
                "is_admin": is_admin,
                "is_active": True,
                "last_login_at": _ago(days=login_days, hours=3),
            },
        )

    group_id = _insert(
        conn,
        "groups",
        {"name": "Platform team", "description": "Engineers who ship the demo services."},
    )
    for username in ("demo-alice", "demo-bob", "demo-carol"):
        _insert(conn, "group_members", {"group_id": group_id, "user_id": users[username]})

    strict_gate_id = _insert(
        conn, "quality_gates", {"name": "Release gate", "is_default": False, "is_builtin": False}
    )
    for metric, operator, threshold in RELEASE_GATE_CONDITIONS:
        _insert(
            conn,
            "gate_conditions",
            {
                "gate_id": strict_gate_id,
                "metric": metric,
                "operator": operator,
                "threshold": threshold,
            },
        )

    # --- projects and grants ------------------------------------------------
    settings_json = _project_settings()
    descriptions = {
        "payments": "Card processing API - every change touches the money path.",
        "web-portal": "Customer-facing React portal and its FastAPI backend.",
        "data-pipeline": "Nightly ETL into the warehouse.",
    }
    names = {
        "payments": "Payments service",
        "web-portal": "Web portal",
        "data-pipeline": "Data pipeline",
    }
    projects: dict[str, int] = {}
    for key in DEMO_PROJECT_KEYS:
        projects[key] = _insert(
            conn,
            "projects",
            {
                "key": key,
                "name": names[key],
                "description": descriptions[key],
                "gate_id": strict_gate_id if key == "payments" else None,
                "settings": settings_json[key],
                "created_by": users[DEMO_ADMIN],
            },
        )

    grants = 0
    for key, subject_type, subject, template in GRANT_PLAN:
        if subject_type == "group":
            subject_id = group_id if subject == "Platform team" else users[subject]
        else:
            subject_id = users[subject]
        for permission in PERMISSION_TEMPLATES[template]:
            _insert(
                conn,
                "project_grants",
                {
                    "project_id": projects[key],
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                    "permission": permission.value,
                },
            )
            grants += 1

    # --- analyses -----------------------------------------------------------
    # (project, days ago, status, bandit error, issue metrics, coverage, excluded)
    analysis_plan: dict[
        str, list[tuple[int, str, str | None, dict[str, float], float | None, int]]
    ] = {
        "payments": [
            (
                14,
                "complete",
                None,
                _metrics(issues_total=3, issues_medium=1, issues_low=2, bugs=1, code_smells=2),
                91.2,
                0,
            ),
            (
                7,
                "complete",
                None,
                _metrics(
                    issues_total=7,
                    issues_high=1,
                    issues_medium=3,
                    issues_low=3,
                    vulnerabilities=1,
                    bugs=3,
                    code_smells=3,
                ),
                84.1,
                0,
            ),
            (
                2,
                "complete",
                None,
                _metrics(
                    issues_total=13,
                    issues_blocker=1,
                    issues_high=2,
                    issues_medium=7,
                    issues_low=3,
                    vulnerabilities=3,
                    secrets=1,
                    dependency_vulns=1,
                    dependency_vulns_with_fix=1,
                    bugs=5,
                    code_smells=3,
                ),
                78.0,
                1,
            ),
            (
                1,
                "complete",
                None,
                _metrics(
                    issues_total=12,
                    issues_blocker=1,
                    issues_high=2,
                    issues_medium=7,
                    issues_low=2,
                    vulnerabilities=3,
                    secrets=1,
                    dependency_vulns=1,
                    dependency_vulns_with_fix=1,
                    bugs=5,
                    code_smells=2,
                ),
                76.4,
                1,
            ),
        ],
        "web-portal": [
            (12, "complete", None, _metrics(issues_total=1, issues_low=1, code_smells=1), 88.0, 0),
            (
                5,
                "complete",
                None,
                _metrics(
                    issues_total=2, issues_high=1, issues_low=1, vulnerabilities=1, code_smells=1
                ),
                90.5,
                0,
            ),
            (1, "complete", None, _metrics(issues_total=1, issues_low=1, code_smells=1), 92.1, 0),
        ],
        "data-pipeline": [
            (9, "complete", None, _metrics(), 74.0, 0),
            (
                1,
                "incomplete",
                "bandit is not installed",
                _metrics(
                    issues_total=1,
                    issues_critical=1,
                    dependency_vulns=1,
                    dependency_vulns_with_fix=1,
                ),
                None,
                0,
            ),
        ],
    }

    analyses: dict[tuple[str, int], int] = {}
    analysis_created: dict[tuple[str, int], datetime] = {}
    for key, plan in analysis_plan.items():
        for index, (days, status, bandit_error, _metrics_at, _coverage, excluded) in enumerate(
            plan
        ):
            created = _ago(days=days)
            build = hashlib.sha256(f"{key}|build|{index}".encode()).hexdigest()[:40]
            analysis_id = _insert(
                conn,
                "analyses",
                {
                    "project_id": projects[key],
                    "commit_sha": build,
                    "ci_url": f"https://ci.wadjet.demo/{key}/builds/{140 + index * 37}",
                    "started_at": created - timedelta(minutes=4),
                    "finished_at": created + timedelta(minutes=1),
                    "status": status,
                    "scanner_runs": _scanner_runs(bandit_error=bandit_error),
                    "excluded_count": excluded,
                    "created_at": created,
                },
            )
            analyses[(key, index)] = analysis_id
            analysis_created[(key, index)] = created

    # --- issues -------------------------------------------------------------
    # alias, tool, rule, severity, category, title, file, first, last, extra
    issue_plan: dict[str, list[dict[str, Any]]] = {
        "payments": [
            _issue(
                "payments",
                alias="secret",
                first=("payments", 2),
                last=("payments", 3),
                created_days=2,
                tool="detect_secrets",
                rule_id="Private Key",
                severity="blocker",
                category="secret",
                title="Private Key",
                file_path="src/config/deploy_key.pem",
                line_start=1,
                line_end=1,
                description="Private Key detected on line 1; the value is never "
                "uploaded (file, line, type and hash only)",
                impact=_SECRET_IMPACT,
                fix=_SECRET_FIX,
                cwe="CWE-798",
            ),
            _issue(
                "payments",
                alias="requests-cve",
                first=("payments", 2),
                last=("payments", 3),
                created_days=2,
                tool="pip_audit",
                rule_id="CVE-2024-35195",
                severity="high",
                category="dependency",
                title="requests: session verification bypass",
                package="requests",
                vuln_id="CVE-2024-35195",
                installed_version="2.31.0",
                fixed_versions=json.dumps(["2.32.0"]),
                file_path="requirements.txt",
                line_start=12,
                line_end=12,
                description="A caller can disable certificate verification on a "
                "session, so a redirect can leak the Authorization "
                "header.",
                impact="Requests made through a redirected session may send "
                "credentials to an attacker-controlled host.",
                fix="Upgrade requests to 2.32.0 or later.",
                references=json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2024-35195"]),
            ),
            _issue(
                "payments",
                alias="b105",
                first=("payments", 1),
                last=("payments", 3),
                created_days=7,
                rule_id="B105",
                severity="high",
                category="vulnerability",
                title="B105: hardcoded password string",
                file_path="src/payments/webhooks.py",
                line_start=31,
                line_end=31,
                snippet="password = settings.MIGRATION_PASSWORD",
                description="Hardcoded password string in a webhooks module.",
                impact="Anyone who can read the repository knows the password; "
                "rotating it means shipping code.",
                fix="Read the password from the environment or a secret manager.",
                triage_status="confirmed",
                triaged_by="demo-carol",
                triaged_at_days=6,
                assignee="demo-bob",
                references=json.dumps(
                    [
                        "https://bandit.readthedocs.io/en/latest/"
                        "plugins/b105_hardcoded_password_string.html"
                    ]
                ),
            ),
            _issue(
                "payments",
                alias="b311",
                first=("payments", 2),
                last=("payments", 3),
                created_days=2,
                rule_id="B311",
                severity="medium",
                category="vulnerability",
                title="B311: random module used for security",
                file_path="src/payments/tokens.py",
                line_start=8,
                line_end=8,
                snippet="token = random.getrandbits(128)",
                description="The standard random module is not cryptographically secure.",
                impact="Predictable tokens let an attacker forge session or card references.",
                fix="Use secrets.token_hex() (or an equivalent CSPRNG) instead.",
                references=json.dumps(
                    ["https://bandit.readthedocs.io/en/latest/plugins/b311_random.html"]
                ),
            ),
            _issue(
                "payments",
                alias="eval",
                first=("payments", 0),
                last=("payments", 3),
                created_days=14,
                tool="ruff",
                rule_id="PLE1307",
                severity="medium",
                category="bug",
                title="PLE1307: use of eval",
                file_path="src/payments/service.py",
                line_start=44,
                line_end=44,
                snippet="result = eval(discount_expression)",
                description="Built-in eval() with a non-literal expression.",
                impact="An attacker who influences the expression runs arbitrary "
                "code with the service's privileges.",
                fix="Parse the expression with ast.literal_eval() or a real expression parser.",
            ),
            _issue(
                "payments",
                alias="b006",
                first=("payments", 2),
                last=("payments", 3),
                created_days=2,
                tool="ruff",
                rule_id="B006",
                severity="medium",
                category="bug",
                title="B006: mutable default argument",
                file_path="src/payments/routes.py",
                line_start=19,
                line_end=19,
                snippet="def quote(items=[], rate_table=RATES):",
                description="A mutable default argument is shared between calls.",
                impact="State leaks between requests: one caller's items appear "
                "in the next caller's quote.",
                fix="Default to None and create the list inside the function.",
            ),
            _issue(
                "payments",
                alias="f401",
                first=("payments", 1),
                last=("payments", 3),
                created_days=7,
                tool="ruff",
                rule_id="F401",
                severity="medium",
                category="bug",
                title="F401: unused import",
                file_path="src/payments/client.py",
                line_start=4,
                line_end=4,
                snippet="import urllib.parse",
                description="Imported but never used.",
                impact="Dead imports hide real dependencies and slow reviews.",
                fix="Remove the import, or run `ruff check --fix .`.",
            ),
            _issue(
                "payments",
                alias="f841",
                first=("payments", 1),
                last=("payments", 3),
                created_days=7,
                tool="ruff",
                rule_id="F841",
                severity="medium",
                category="bug",
                title="F841: unused variable",
                file_path="src/payments/reconcile.py",
                line_start=57,
                line_end=57,
                snippet="settled = fetch_settlements(batch)",
                description="A variable is assigned but never used.",
                impact="Unused results usually mean a missing check or a half-finished change.",
                fix="Delete the assignment or use the value.",
                triage_status="confirmed",
                triaged_by="demo-carol",
                triaged_at_days=5,
            ),
            _issue(
                "payments",
                alias="c901",
                first=("payments", 0),
                last=("payments", 3),
                created_days=14,
                tool="ruff",
                rule_id="C901",
                severity="low",
                category="code_smell",
                title="C901: function too complex",
                file_path="src/payments/service.py",
                line_start=12,
                line_end=12,
                snippet="def price_line_item(item, context):",
                description="Complexity 14 (max 10).",
                impact="Deeply branching pricing code is where silent over-charges hide.",
                fix="Split the function along its branches.",
            ),
            _issue(
                "payments",
                alias="w291",
                first=("payments", 0),
                last=("payments", 3),
                created_days=14,
                tool="ruff",
                rule_id="W291",
                severity="low",
                category="code_smell",
                title="W291: trailing whitespace",
                file_path="src/payments/formats.py",
                line_start=88,
                line_end=88,
                snippet="amount = f'{value:.2f}'   ",
                description="Trailing whitespace.",
                impact="Noisy diffs and review fatigue.",
                fix="Strip the whitespace (ruff --fix does it).",
            ),
            _issue(
                "payments",
                alias="b300",
                first=("payments", 2),
                last=("payments", 3),
                created_days=2,
                rule_id="B300",
                severity="medium",
                category="vulnerability",
                title="B300: calls to md5",
                file_path="src/payments/receipts.py",
                line_start=23,
                line_end=23,
                snippet="digest = md5(payload).hexdigest()",
                description="MD5 is collision-broken and unsuitable for integrity checks.",
                impact="Forged receipts can pass the integrity check.",
                fix="Switch to hashlib.sha256 or hmac.compare_digest.",
                references=json.dumps(
                    ["https://bandit.readthedocs.io/en/latest/plugins/b300_calls_to_md5.html"]
                ),
            ),
            _issue(
                "payments",
                alias="e999",
                first=("payments", 2),
                last=("payments", 3),
                created_days=2,
                tool="ruff",
                rule_id="E999",
                severity="medium",
                category="bug",
                title="E999: SyntaxError: unexpected ':'",
                file_path="src/pipeline/parser.py",
                line_start=61,
                line_end=61,
                snippet="value = first if cond: second",
                description="The file cannot be parsed (syntax error).",
                impact="The module fails to import at runtime.",
                fix="Fix the ternary: `value = first if cond else second`.",
            ),
            # --- excluded from the gate by triage --------------------------
            _issue(
                "payments",
                alias="fp",
                first=("payments", 0),
                last=("payments", 3),
                created_days=14,
                tool="ruff",
                rule_id="B008",
                severity="medium",
                category="bug",
                title="B008: function call in default argument",
                file_path="tests/test_health.py",
                line_start=11,
                line_end=11,
                snippet="def test_health(client=TEST_CLIENT):",
                description="Function call in a default argument.",
                impact="The default is created once and shared across tests.",
                fix="Create the client inside the test.",
                triage_status="false_positive",
                triaged_by="demo-carol",
                triaged_at_days=12,
                triage_reason="False positive: the shared test client is intentional "
                "and never mutated.",
            ),
            _issue(
                "payments",
                alias="wontfix",
                first=("payments", 2),
                last=("payments", 3),
                created_days=2,
                rule_id="B105",
                severity="high",
                category="vulnerability",
                title="B105: hardcoded password string",
                file_path="src/payments/webhooks_v1.py",
                line_start=14,
                line_end=14,
                snippet="password = LEGACY_WEBHOOK_PASSWORD",
                description="Hardcoded password string in the v1 webhook shim.",
                impact="The credential is readable in the repository.",
                fix="Read it from the environment.",
                triage_status="wont_fix",
                triaged_by="demo-alice",
                triaged_at_days=1,
                triage_reason="Legacy webhook endpoint is decommissioned next "
                "quarter - tracked in OPS-1124.",
            ),
            _issue(
                "payments",
                alias="risk",
                first=("payments", 1),
                last=("payments", 3),
                created_days=7,
                rule_id="B605",
                severity="medium",
                category="vulnerability",
                title="B605: shell injection via os.system",
                file_path="scripts/backfill.py",
                line_start=37,
                line_end=37,
                snippet="os.system(f'psql -c \"{sql}\"')",
                description="os.system with an f-string command.",
                impact="Untrusted input in the SQL string becomes shell code.",
                fix="Use subprocess.run with an argument list.",
                triage_status="accepted_risk",
                triaged_by="demo-carol",
                triaged_at_days=5,
                triage_reason="Confirmed twice by the scanner: the script runs only "
                "in the build sandbox with static input.",
            ),
            _issue(
                "payments",
                alias="resolved",
                first=("payments", 1),
                last=("payments", 3),
                created_days=7,
                resolved_days=1,
                tool="ruff",
                rule_id="W605",
                severity="low",
                category="code_smell",
                title="W605: invalid escape sequence",
                file_path="src/payments/legacy_export.py",
                line_start=72,
                line_end=72,
                snippet="pattern = '\\d+\\.\\d+'",
                description="Invalid escape sequence in a string literal.",
                impact="The pattern silently stops matching on newer Pythons.",
                fix="Use a raw string (r'\\d+\\.\\d+').",
            ),
        ],
        "web-portal": [
            _issue(
                "web-portal",
                alias="oauth",
                first=("web-portal", 1),
                last=("web-portal", 2),
                created_days=5,
                resolved_days=1,
                rule_id="B105",
                severity="high",
                category="vulnerability",
                title="B105: hardcoded password string",
                file_path="src/portal/oauth.py",
                line_start=27,
                line_end=27,
                snippet="client_secret = PORTAL_CLIENT_SECRET",
                description="Hardcoded OAuth client secret.",
                impact="The secret is readable in the repository and every fork.",
                fix="Read the secret from the environment.",
                references=json.dumps(
                    [
                        "https://bandit.readthedocs.io/en/latest/"
                        "plugins/b105_hardcoded_password_string.html"
                    ]
                ),
            ),
            _issue(
                "web-portal",
                alias="fp",
                first=("web-portal", 0),
                last=("web-portal", 2),
                created_days=12,
                tool="ruff",
                rule_id="B008",
                severity="medium",
                category="bug",
                title="B008: function call in default argument",
                file_path="tests/test_views.py",
                line_start=9,
                line_end=9,
                snippet="def render(view=make_view()):",
                description="Function call in a default argument.",
                impact="The default view is shared across tests.",
                fix="Create the view inside the test.",
                triage_status="false_positive",
                triaged_by="demo-carol",
                triaged_at_days=11,
                triage_reason="False positive: the factory result is an immutable "
                "namedtuple used by every case.",
            ),
            _issue(
                "web-portal",
                alias="open-low",
                first=("web-portal", 0),
                last=("web-portal", 2),
                created_days=12,
                tool="ruff",
                rule_id="W391",
                severity="low",
                category="code_smell",
                title="W391: blank line at end of file",
                file_path="src/portal/templatetags/extras.py",
                line_start=64,
                line_end=64,
                snippet="",
                description="Too many trailing blank lines.",
                impact="Noisy diffs.",
                fix="Strip the trailing blank lines (ruff --fix does it).",
            ),
        ],
        "data-pipeline": [
            _issue(
                "data-pipeline",
                alias="pyyaml",
                first=("data-pipeline", 1),
                last=("data-pipeline", 1),
                created_days=1,
                tool="pip_audit",
                rule_id="CVE-2020-14343",
                severity="critical",
                category="dependency",
                title="PyYAML: arbitrary code execution in unsafe load",
                package="pyyaml",
                vuln_id="CVE-2020-14343",
                installed_version="5.3.1",
                fixed_versions=json.dumps(["5.4"]),
                file_path="requirements.txt",
                line_start=41,
                line_end=41,
                description="unsafe_load()/full_load() can construct arbitrary "
                "Python objects from untrusted YAML.",
                impact="Crafted YAML in the feed executes code on the worker.",
                fix="Upgrade PyYAML to 5.4 or later and use yaml.safe_load().",
                references=json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"]),
            ),
            _issue(
                "data-pipeline",
                alias="wontfix",
                first=("data-pipeline", 0),
                last=("data-pipeline", 1),
                created_days=9,
                tool="ruff",
                rule_id="W605",
                severity="low",
                category="code_smell",
                title="W605: invalid escape sequence",
                file_path="pipeline/transforms.py",
                line_start=18,
                line_end=18,
                snippet="path = 'C:\\data\\input'",
                description="Invalid escape sequence in a string literal.",
                impact="The path stops resolving on newer Pythons.",
                fix="Use a raw string.",
                triage_status="wont_fix",
                triaged_by="demo-alice",
                triaged_at_days=8,
                triage_reason="Documented Windows-only path: renaming it would "
                "churn every caller for no runtime change.",
            ),
            _issue(
                "data-pipeline",
                alias="fp",
                first=("data-pipeline", 0),
                last=("data-pipeline", 1),
                created_days=9,
                tool="ruff",
                rule_id="B007",
                severity="medium",
                category="bug",
                title="B007: unused loop control variable",
                file_path="pipeline/loader.py",
                line_start=52,
                line_end=52,
                snippet="for batch in batches:",
                description="The loop variable is never used in the body.",
                impact="Dead bindings confuse readers.",
                fix="Rename to _batch or iterate differently.",
                triage_status="false_positive",
                triaged_by="demo-carol",
                triaged_at_days=8,
                triage_reason="False positive: the loop variable is read by the "
                "trace logger via frame inspection.",
            ),
        ],
    }

    issue_ids: dict[tuple[str, str], int] = {}
    events: list[dict[str, Any]] = []
    # Keys that steer the row but are not columns of their own.
    control_keys = {"triaged_by", "triaged_at_days", "assignee", "resolved_days"}
    for key, rows in issue_plan.items():
        for row in rows:
            values = {
                k: v for k, v in row.items() if not k.startswith("_") and k not in control_keys
            }
            values["project_id"] = projects[key]
            values["first_seen_analysis_id"] = analyses[row["_first"]]
            values["last_seen_analysis_id"] = analyses[row["_last"]]
            triaged_at: datetime | None = None
            if row.get("triaged_by"):
                values["triaged_by"] = users[row["triaged_by"]]
                triaged_at = _ago(days=int(row.get("triaged_at_days", 0)))
                values["triaged_at"] = triaged_at
            if row.get("assignee"):
                values["assignee_id"] = users[row["assignee"]]
            if row.get("resolved_days") is not None:
                values["presence"] = "resolved"
                values["resolved_at"] = _ago(days=int(row["resolved_days"]))
            issue_id = _insert(conn, "issues", values)
            issue_ids[(key, str(row["_alias"]))] = issue_id

            events.append(
                {
                    "issue_id": issue_id,
                    "actor_id": None,
                    "type": "created",
                    "payload": json.dumps({"analysis": analyses[row["_first"]]}),
                    "created_at": analysis_created[row["_first"]],
                }
            )
            if row.get("triage_status") not in (None, "open"):
                payload: dict[str, Any] = {"status": row["triage_status"]}
                if row.get("triage_reason"):
                    payload["reason"] = row["triage_reason"]
                events.append(
                    {
                        "issue_id": issue_id,
                        "actor_id": users[row["triaged_by"]],
                        "type": "triaged",
                        "payload": json.dumps(payload, default=str),
                        "created_at": triaged_at or analysis_created[row["_first"]],
                    }
                )
            if row.get("resolved_days") is not None:
                events.append(
                    {
                        "issue_id": issue_id,
                        "actor_id": None,
                        "type": "resolved_by_scan",
                        "payload": json.dumps({"analysis": analyses[row["_last"]]}),
                        "created_at": _ago(days=int(row["resolved_days"])),
                    }
                )

    for event in events:
        _insert(conn, "issue_events", event)

    # --- comments and requests ---------------------------------------------
    comments = (
        (
            "payments",
            "b105",
            "demo-bob",
            "@demo-carol can you confirm this is only the migration fixture? It shows up "
            "in the prod config scan too.",
            6,
        ),
        (
            "payments",
            "b105",
            "demo-carol",
            "Confirmed - rotating the credential in Vault now and tracking it in OPS-1124.",
            6,
        ),
        (
            "payments",
            "secret",
            "demo-admin",
            "This blocks the 1.8 release. Rotate the key before Friday.",
            2,
        ),
        (
            "web-portal",
            "oauth",
            "demo-alice",
            "Fixed in portal 2024.11: the secret now comes from the environment.",
            2,
        ),
    )
    for key, alias, author, body, days in comments:
        _insert(
            conn,
            "issue_comments",
            {
                "issue_id": issue_ids[(key, alias)],
                "author_id": users[author],
                "body_md": body,
                "created_at": _ago(days=days, hours=2),
            },
        )

    requests = (
        (
            "payments",
            "fp",
            "demo-dave",
            "demo-carol",
            "flag_false_positive",
            "Looks like a test fixture leaking through - could you flag it?",
            "pending",
            None,
            None,
            2,
        ),
        (
            "payments",
            "b006",
            "demo-bob",
            "demo-alice",
            "fix_help",
            "Can someone fix the mutable default argument in routes.py?",
            "approved",
            "demo-alice",
            "Replaced the default with None in the next release.",
            5,
        ),
        (
            "payments",
            "risk",
            "demo-dave",
            "demo-carol",
            "flag_accepted_risk",
            "This one looks exploitable from the build box - worth flagging?",
            "declined",
            "demo-carol",
            "Declined: confirmed twice by the scanner and we accepted the risk.",
            4,
        ),
    )
    for key, alias, by, target, action, message, state, resolver, note, days in requests:
        request_row: dict[str, Any] = {
            "issue_id": issue_ids[(key, alias)],
            "requested_by": users[by],
            "target_user_id": users[target],
            "requested_action": action,
            "message": message,
            "state": state,
            "created_at": _ago(days=days, hours=4),
        }
        if resolver is not None:
            request_row.update(
                resolved_by=users[resolver],
                resolved_note=note,
                resolved_at=_ago(days=max(days - 1, 0), hours=1),
                updated_at=_ago(days=max(days - 1, 0), hours=1),
            )
        _insert(conn, "issue_requests", request_row)

    # --- tokens and audit ---------------------------------------------------
    token_ids: dict[str, int] = {}
    for key in DEMO_PROJECT_KEYS:
        _full, prefix, token_hash = generate_token()
        token_ids[key] = _insert(
            conn,
            "api_tokens",
            {
                "project_id": projects[key],
                "name": f"CI {key}",
                "token_prefix": prefix,
                "token_hash": token_hash,
                "created_by": users[DEMO_ADMIN],
            },
        )

    audit_rows = (
        ("login", users[DEMO_ADMIN], "user", users[DEMO_ADMIN], None, 0, 1),
        ("login", users["demo-alice"], "user", users["demo-alice"], None, 1, 6),
        ("logout", users["demo-alice"], "user", users["demo-alice"], None, 1, 5),
        (
            "gate.create",
            users[DEMO_ADMIN],
            "quality_gate",
            strict_gate_id,
            {"name": "Release gate", "conditions": len(RELEASE_GATE_CONDITIONS)},
            10,
            4,
        ),
        (
            "project.settings_update",
            users["demo-alice"],
            "project",
            projects["payments"],
            {"changed": ["scanners.ruff.families", "scanners.coverage.report_path"]},
            6,
            3,
        ),
        (
            "token.create",
            users[DEMO_ADMIN],
            "project",
            projects["payments"],
            {"name": "CI payments", "token_id": token_ids["payments"]},
            6,
            2,
        ),
    )
    for action, actor, target_type, target_id, audit_details, days, hours in audit_rows:
        _insert(
            conn,
            "audit_log",
            {
                "actor_id": actor,
                "action": action,
                "target_type": target_type,
                "target_id": str(target_id),
                "details": json.dumps(audit_details) if audit_details is not None else None,
                "ip": "192.0.2.10",
                "created_at": _ago(days=days, hours=hours),
            },
        )

    # --- gate results through the real evaluator ---------------------------
    for key, plan in analysis_plan.items():
        for index, (_days, status, _err, issue_metrics, coverage, _excluded) in enumerate(plan):
            uploaded = {"coverage_line_percent": coverage} if coverage is not None else {}
            gate_status, details, metrics = evaluate_gate(
                conn,
                projects[key],
                analysis_status=status,
                uploaded_metrics=uploaded,
                issue_metrics=issue_metrics,
            )
            conn.execute(
                text(
                    "UPDATE analyses SET gate_status = :gs, gate_details = :gd, "
                    "metrics = :metrics WHERE id = :aid"
                ),
                {
                    "gs": gate_status,
                    "gd": json.dumps({"conditions": details}, default=str),
                    "metrics": json.dumps(metrics, default=str),
                    "aid": analyses[(key, index)],
                },
            )

    return {
        "users": len(DEMO_USERS),
        "groups": 1,
        "grants": grants,
        "projects": len(DEMO_PROJECT_KEYS),
        "gates": 1,
        "analyses": sum(len(plan) for plan in analysis_plan.values()),
        "issues": sum(len(rows) for rows in issue_plan.values()),
        "events": len(events),
        "comments": len(comments),
        "requests": len(requests),
        "tokens": len(DEMO_PROJECT_KEYS),
        "audit entries": len(audit_rows),
    }
