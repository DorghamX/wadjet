"""Project token management: create, hash, revoke, last used.

Section 13: Project tokens: 32 random bytes, shown once, stored as a SHA-256
hash with a visible prefix; constant-time comparison; a token can only call
agent endpoints for its own project.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Engine, text


def generate_token() -> tuple[str, str, str]:
    """Generate a new project token.

    Returns:
        (full_token, prefix, hash) where:
        - full_token: the complete token to show once
        - prefix: first 8 chars for display
        - hash: SHA-256 hex digest for storage
    """
    # 32 random bytes = 256 bits
    raw = secrets.token_bytes(32)
    full_token = raw.hex()
    prefix = full_token[:8]
    token_hash = hash_token(full_token)
    return full_token, prefix, token_hash


def hash_token(token: str) -> str:
    """Compute SHA-256 hash of a token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b, strict=True):
        result |= ord(x) ^ ord(y)
    return result == 0


def create_token(
    engine: Engine,
    project_id: int,
    name: str,
    created_by: int,
    expires_at: datetime | None = None,
) -> tuple[str, str]:
    """Create a new API token for a project.

    Args:
        engine: Database engine
        project_id: Project ID
        name: Token name/description
        created_by: User ID creating the token
        expires_at: Optional expiry datetime

    Returns:
        (full_token, token_id) - full_token is shown once, token_id for revocation
    """
    full_token, prefix, token_hash = generate_token()

    with engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO api_tokens "
                "(project_id, name, token_prefix, token_hash, expires_at, created_by) "
                "VALUES (:pid, :name, :prefix, :hash, :expires, :created_by) RETURNING id"
            ),
            {
                "pid": project_id,
                "name": name,
                "prefix": prefix,
                "hash": token_hash,
                "expires": expires_at,
                "created_by": created_by,
            },
        )
        token_id = result.scalar_one()

    return full_token, token_id


def validate_token(engine: Engine, token: str) -> dict[str, Any] | None:
    """Validate an API token and return its data if valid.

    Args:
        engine: Database engine
        token: The token to validate

    Returns:
        dict with token data if valid, None if invalid/expired/revoked
    """
    token_hash = hash_token(token)

    with engine.begin() as conn:
        result = conn.execute(
            text(
                "SELECT id, project_id, name, expires_at, revoked_at "
                "FROM api_tokens WHERE token_hash = :hash"
            ),
            {"hash": token_hash},
        ).first()

    if not result:
        return None

    token_id, project_id, name, expires_at, revoked_at = result

    # Check if revoked
    if revoked_at is not None:
        return None

    # Check if expired
    if expires_at and datetime.now(timezone.utc) > expires_at:
        return None

    return {
        "id": token_id,
        "project_id": project_id,
        "name": name,
    }


def update_last_used(engine: Engine, token_id: int) -> None:
    """Update the last_used_at timestamp for a token."""
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE api_tokens SET last_used_at = NOW() WHERE id = :tid"),
            {"tid": token_id},
        )


def revoke_token(engine: Engine, token_id: int) -> bool:
    """Revoke an API token.

    Args:
        engine: Database engine
        token_id: Token ID to revoke

    Returns:
        True if a token was revoked, False if not found or already revoked
    """
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "UPDATE api_tokens SET revoked_at = NOW() "
                "WHERE id = :tid AND revoked_at IS NULL RETURNING 1"
            ),
            {"tid": token_id},
        ).first()
    return result is not None


def list_tokens(engine: Engine, project_id: int) -> list[dict[str, Any]]:
    """List all tokens for a project (without the hash).

    Args:
        engine: Database engine
        project_id: Project ID

    Returns:
        List of token dicts (id, name, prefix, expires_at, last_used_at,
        revoked_at, created_by, created_at).
    """
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "SELECT id, name, token_prefix, expires_at, last_used_at, "
                "revoked_at, created_by, created_at "
                "FROM api_tokens WHERE project_id = :pid ORDER BY created_at DESC"
            ),
            {"pid": project_id},
        )
        rows = result.fetchall()

    return [
        {
            "id": row[0],
            "name": row[1],
            "prefix": row[2],
            "expires_at": row[3],
            "last_used_at": row[4],
            "revoked_at": row[5],
            "created_by": row[6],
            "created_at": row[7],
        }
        for row in rows
    ]
