"""baseline anchor.

Empty first revision: it exists so every later revision has a parent and the migration
machinery can be tested against an empty database. Migrations are forward-only.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-10-06
"""

from __future__ import annotations

from alembic import op

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | list[str] | None = None
depends_on: str | list[str] | None = None


def upgrade() -> None:
    """No tables yet; the next revision creates the first ones."""


def downgrade() -> None:
    raise NotImplementedError("Wadjet migrations are forward-only")
