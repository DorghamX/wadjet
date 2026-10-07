"""Migration creating the notifications table (section 4).

A notification is a pointer, not a message: ``ref`` names the request or
issue it is about (the JSONB object travels with both ids) and the inbox
reads the live rows behind it, so the sentence shown at read time is the
truth *now* - pending, approved, declined, cancelled - rather than a copy
of the text that went stale the moment somebody decided.

Revision ID: 0009_notifications
Revises: 0008_seed_default_gate
Create Date: 2026-10-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_notifications"
down_revision: str | None = "0008_seed_default_gate"
branch_labels: str | list[str] | None = None
depends_on: str | list[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "user_id", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=False, index=True
        ),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("ref", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("notifications")
