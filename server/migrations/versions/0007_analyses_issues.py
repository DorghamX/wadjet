"""Migration creating analyses, issues, issue_events, issue_comments, issue_requests.

Revision ID: 0007_analyses_issues
Revises: 0006_sessions
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_analyses_issues"
down_revision: str | None = "0006_sessions"
branch_labels: str | list[str] | None = None
depends_on: str | list[str] | None = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "project_id", sa.BigInteger(), sa.ForeignKey("projects.id"), nullable=False, index=True
        ),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("ci_url", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("scanner_runs", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("gate_status", sa.String(16), nullable=True),
        sa.Column("gate_details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("excluded_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "issues",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "project_id", sa.BigInteger(), sa.ForeignKey("projects.id"), nullable=False, index=True
        ),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("snippet", sa.Text(), nullable=True),
        sa.Column("snippet_norm_hash", sa.String(64), nullable=True),
        sa.Column("package", sa.String(255), nullable=True),
        sa.Column("vuln_id", sa.String(64), nullable=True),
        sa.Column("installed_version", sa.String(64), nullable=True),
        sa.Column("fixed_versions", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("cwe", sa.String(32), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("fix", sa.Text(), nullable=True),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "triage_status", sa.String(24), nullable=False, server_default="open"
        ),
        sa.Column("presence", sa.String(16), nullable=False, server_default="present"),
        sa.Column("triage_reason", sa.Text(), nullable=True),
        sa.Column("triaged_by", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assignee_id", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "first_seen_analysis_id", sa.BigInteger(), sa.ForeignKey("analyses.id"), nullable=True
        ),
        sa.Column(
            "last_seen_analysis_id", sa.BigInteger(), sa.ForeignKey("analyses.id"), nullable=True
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("project_id", "fingerprint", name="uq_issue_fingerprint"),
    )
    op.create_index("ix_issues_fingerprint", "issues", ["fingerprint"])
    op.create_index("ix_issues_triage_status", "issues", ["triage_status"])
    op.create_index("ix_issues_presence", "issues", ["presence"])

    op.create_table(
        "issue_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "issue_id", sa.BigInteger(), sa.ForeignKey("issues.id"), nullable=False, index=True
        ),
        sa.Column("actor_id", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_issue_events_type", "issue_events", ["type"])

    op.create_table(
        "issue_comments",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "issue_id", sa.BigInteger(), sa.ForeignKey("issues.id"), nullable=False, index=True
        ),
        sa.Column("author_id", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("body_md", sa.Text(), nullable=False),
        sa.Column("edited_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "issue_requests",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "issue_id", sa.BigInteger(), sa.ForeignKey("issues.id"), nullable=False, index=True
        ),
        sa.Column("requested_by", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("target_user_id", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("requested_action", sa.String(24), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("resolved_by", sa.BigInteger(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("resolved_note", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_issue_requests_state", "issue_requests", ["state"])


def downgrade() -> None:
    op.drop_table("issue_requests")
    op.drop_table("issue_comments")
    op.drop_table("issue_events")
    op.drop_table("issues")
    op.drop_table("analyses")
