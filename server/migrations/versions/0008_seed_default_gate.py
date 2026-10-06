"""Migration seeding the built-in default quality gate (section 9).

"Wadjet default": fail when issues_blocker > 0, issues_critical > 0,
issues_high > 0, secrets > 0, dependency_vulns_with_fix > 0,
coverage_line_percent < 70.  Every project that has not picked a gate of its
own falls back to it.

Revision ID: 0008_seed_default_gate
Revises: 0007_analyses_issues
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0008_seed_default_gate"
down_revision: str | None = "0007_analyses_issues"
branch_labels: str | list[str] | None = None
depends_on: str | list[str] | None = None

#: Frozen here rather than imported: a migration must never change behaviour
#: when application code evolves.  test_gates.py asserts the database matches.
DEFAULT_CONDITIONS: list[tuple[str, str, float]] = [
    ("issues_blocker", ">", 0.0),
    ("issues_critical", ">", 0.0),
    ("issues_high", ">", 0.0),
    ("secrets", ">", 0.0),
    ("dependency_vulns_with_fix", ">", 0.0),
    ("coverage_line_percent", "<", 70.0),
]


def upgrade() -> None:
    bind = op.get_bind()
    gate_id = bind.execute(
        sa.text(
            "INSERT INTO quality_gates (name, is_default, is_builtin) "
            "VALUES ('Wadjet default', TRUE, TRUE) RETURNING id"
        )
    ).scalar_one()
    for metric, operator, threshold in DEFAULT_CONDITIONS:
        bind.execute(
            sa.text(
                "INSERT INTO gate_conditions (gate_id, metric, operator, threshold) "
                "VALUES (:gate_id, :metric, :operator, :threshold)"
            ),
            {
                "gate_id": gate_id,
                "metric": metric,
                "operator": operator,
                "threshold": threshold,
            },
        )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "DELETE FROM gate_conditions WHERE gate_id IN "
            "(SELECT id FROM quality_gates WHERE is_builtin AND name = 'Wadjet default')"
        )
    )
    bind.execute(
        sa.text(
            "DELETE FROM quality_gates WHERE is_builtin AND name = 'Wadjet default'"
        )
    )
