"""Audit log writer (section 13).

Every state change records who, when, and why: logins, token creation and
revocation, permission changes, flags, settings changes, and gate changes.
One function, ``write_audit``, is used by every caller so the shape of an
entry never drifts between features.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import Engine, text

logger = logging.getLogger(__name__)


def write_audit(
    engine: Engine,
    *,
    action: str,
    actor_id: int | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    details: dict[str, Any] | None = None,
    ip: str | None = None,
) -> None:
    """Append one entry to the audit log.

    A failing audit write is logged but never raised: recording an action must
    not break the action itself.
    """
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO audit_log "
                    "(actor_id, action, target_type, target_id, details, ip) "
                    "VALUES (:actor_id, :action, :target_type, :target_id, :details, :ip)"
                ),
                {
                    "actor_id": actor_id,
                    "action": action,
                    "target_type": target_type,
                    "target_id": str(target_id) if target_id is not None else None,
                    "details": json.dumps(details, default=str) if details else None,
                    "ip": ip,
                },
            )
    except Exception:  # noqa: BLE001 - the audit trail must not break the action
        logger.exception("failed to write audit entry for action=%s", action)


def read_audit(
    engine: Engine,
    *,
    action: str | None = None,
    actor_id: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Read recent audit entries, newest first (used by tests and the admin page)."""
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit}
    if action is not None:
        clauses.append("action = :action")
        params["action"] = action
    if actor_id is not None:
        clauses.append("actor_id = :actor_id")
        params["actor_id"] = actor_id
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT id, actor_id, action, target_type, target_id, details, ip, created_at "
                f"FROM audit_log {where} ORDER BY created_at DESC, id DESC LIMIT :limit"
            ),
            params,
        ).fetchall()
    return [
        {
            "id": row[0],
            "actor_id": row[1],
            "action": row[2],
            "target_type": row[3],
            "target_id": row[4],
            "details": row[5],
            "ip": row[6],
            "created_at": row[7],
        }
        for row in rows
    ]
