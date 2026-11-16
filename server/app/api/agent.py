"""``GET /api/v1/agent/config`` - server-side settings for the agent (section 11).

Step 2 of the ``wadjet scan`` flow: the agent fetches settings, exclusions and
the gate conditions on every run, so the server stays the authority
(principle 3) - changing a setting takes effect on the next CI run without
redeploying the agent.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import Connection, text

from app.deps import require_project_token
from app.exclusions import effective_exclusion_globs
from app.gate import load_gate_conditions
from wadjet_schema import AgentConfig

router = APIRouter()


def _parse_settings(raw: str | None) -> dict[str, Any]:
    """Stored settings JSON, or an empty dict when absent or corrupt."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _settings_for(conn: Connection, project_id: int) -> tuple[str, dict[str, Any]]:
    row = conn.execute(
        text("SELECT key, settings FROM projects WHERE id = :pid"),
        {"pid": project_id},
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return row.key, _parse_settings(row.settings)


@router.get("/api/v1/agent/config", response_model=AgentConfig)
def agent_config(
    request: Request, token: dict[str, Any] = Depends(require_project_token)
) -> AgentConfig:
    """Settings, exclusions and gate conditions for the token's project."""
    engine = request.app.state.engine
    project_id = token["project_id"]
    with engine.begin() as conn:
        project_key, settings = _settings_for(conn, project_id)
        gate_conditions = load_gate_conditions(conn, project_id)
    return AgentConfig(
        project_key=project_key,
        settings=settings,
        gate_conditions={"conditions": gate_conditions},
        exclusion_globs=effective_exclusion_globs(settings),
    )
