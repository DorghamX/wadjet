"""Gate CRUD (section 15.2: ``GET/POST/PATCH/DELETE /api/v1/gates``).

Session-authenticated: reading the list needs a login, writing needs the
global ``gates.admin`` permission (section 7).  The built-in default gate
cannot be deleted, and neither ``is_default`` nor ``is_builtin`` is ever set
through the API - the flags belong to the migration and to future project
settings, not to gate authors.  Every change lands in the audit log
(section 15.4: gate changes).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Connection, Engine, text

from app.audit import write_audit
from app.deps import get_current_user
from app.gate import ALL_METRICS, OPERATORS
from app.permissions import Permission, can

router = APIRouter()


class ConditionIn(BaseModel):
    """One "fail when" condition (section 9)."""

    metric: str
    operator: str
    threshold: float

    @field_validator("metric")
    @classmethod
    def _known_metric(cls, value: str) -> str:
        if value not in ALL_METRICS:
            raise ValueError(f"unknown metric {value!r}; expected one of {', '.join(ALL_METRICS)}")
        return value

    @field_validator("operator")
    @classmethod
    def _known_operator(cls, value: str) -> str:
        if value not in OPERATORS:
            raise ValueError(f"unknown operator {value!r}; expected one of {', '.join(OPERATORS)}")
        return value


class GateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    conditions: list[ConditionIn] = Field(default_factory=list)


class GatePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    conditions: list[ConditionIn] | None = None


class ConditionOut(BaseModel):
    metric: str
    operator: str
    threshold: float


class GateOut(BaseModel):
    id: int
    name: str
    is_default: bool
    is_builtin: bool
    conditions: list[ConditionOut]


def _require_gates_admin(engine: Engine, user: dict[str, Any]) -> None:
    if not can(engine, int(user["user_id"]), Permission.GATES_ADMIN):
        raise HTTPException(status_code=403, detail="gates.admin permission required")


def _load_gate(conn: Connection, gate_id: int) -> Any:
    return conn.execute(
        text("SELECT id, name, is_default, is_builtin FROM quality_gates WHERE id = :gid"),
        {"gid": gate_id},
    ).first()


def _load_conditions(conn: Connection, gate_id: int) -> list[ConditionOut]:
    rows = conn.execute(
        text(
            "SELECT metric, operator, threshold FROM gate_conditions "
            "WHERE gate_id = :gid ORDER BY id"
        ),
        {"gid": gate_id},
    ).fetchall()
    return [ConditionOut(metric=row[0], operator=row[1], threshold=float(row[2])) for row in rows]


def _gate_out(conn: Connection, gate_id: int) -> GateOut:
    row = _load_gate(conn, gate_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Gate not found")
    return GateOut(
        id=int(row.id),
        name=row.name,
        is_default=bool(row.is_default),
        is_builtin=bool(row.is_builtin),
        conditions=_load_conditions(conn, gate_id),
    )


def _insert_conditions(conn: Connection, gate_id: int, conditions: list[ConditionIn]) -> None:
    for condition in conditions:
        conn.execute(
            text(
                "INSERT INTO gate_conditions (gate_id, metric, operator, threshold) "
                "VALUES (:gid, :metric, :operator, :threshold)"
            ),
            {
                "gid": gate_id,
                "metric": condition.metric,
                "operator": condition.operator,
                "threshold": condition.threshold,
            },
        )


def _ensure_name_free(conn: Connection, name: str, *, exclude_gate_id: int | None = None) -> None:
    clauses = "name = :name"
    params: dict[str, Any] = {"name": name}
    if exclude_gate_id is not None:
        clauses += " AND id <> :exclude"
        params["exclude"] = exclude_gate_id
    if conn.execute(text(f"SELECT 1 FROM quality_gates WHERE {clauses}"), params).scalar():
        raise HTTPException(status_code=409, detail="A gate with that name already exists")


@router.get("/api/v1/gates", response_model=list[GateOut])
def list_gates(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> list[GateOut]:
    """Every gate with its conditions (section 15.2: session)."""
    engine = request.app.state.engine
    with engine.begin() as conn:
        gate_ids = [
            int(row[0]) for row in conn.execute(text("SELECT id FROM quality_gates ORDER BY id"))
        ]
        return [_gate_out(conn, gate_id) for gate_id in gate_ids]


@router.post("/api/v1/gates", response_model=GateOut, status_code=201)
def create_gate(
    request: Request,
    payload: GateCreate,
    user: dict[str, Any] = Depends(get_current_user),
) -> GateOut:
    """Create a gate (section 15.2: gates.admin)."""
    engine = request.app.state.engine
    _require_gates_admin(engine, user)
    with engine.begin() as conn:
        _ensure_name_free(conn, payload.name)
        gate_id = conn.execute(
            text(
                "INSERT INTO quality_gates (name, is_default, is_builtin) "
                "VALUES (:name, FALSE, FALSE) RETURNING id"
            ),
            {"name": payload.name},
        ).scalar_one()
        _insert_conditions(conn, gate_id, payload.conditions)
        created = _gate_out(conn, int(gate_id))
    write_audit(
        engine,
        action="gate.create",
        actor_id=int(user["user_id"]),
        target_type="quality_gate",
        target_id=created.id,
        details={"name": created.name, "conditions": len(created.conditions)},
    )
    return created


@router.patch("/api/v1/gates/{gate_id}", response_model=GateOut)
def update_gate(
    request: Request,
    gate_id: int,
    payload: GatePatch,
    user: dict[str, Any] = Depends(get_current_user),
) -> GateOut:
    """Rename a gate and/or replace its conditions (gates.admin).

    The built-in gate is editable (section 9), but only its name and
    conditions: the default/builtin flags are never API-writable.
    """
    engine = request.app.state.engine
    _require_gates_admin(engine, user)
    if payload.name is None and payload.conditions is None:
        raise HTTPException(status_code=422, detail="Nothing to update")
    with engine.begin() as conn:
        if _load_gate(conn, gate_id) is None:
            raise HTTPException(status_code=404, detail="Gate not found")
        if payload.name is not None:
            _ensure_name_free(conn, payload.name, exclude_gate_id=gate_id)
            conn.execute(
                text("UPDATE quality_gates SET name = :name WHERE id = :gid"),
                {"name": payload.name, "gid": gate_id},
            )
        if payload.conditions is not None:
            conn.execute(
                text("DELETE FROM gate_conditions WHERE gate_id = :gid"),
                {"gid": gate_id},
            )
            _insert_conditions(conn, gate_id, payload.conditions)
        updated = _gate_out(conn, gate_id)
    write_audit(
        engine,
        action="gate.update",
        actor_id=int(user["user_id"]),
        target_type="quality_gate",
        target_id=gate_id,
        details={
            "name": updated.name,
            "conditions": [condition.model_dump() for condition in updated.conditions],
        },
    )
    return updated


@router.delete("/api/v1/gates/{gate_id}", status_code=204)
def delete_gate(
    request: Request,
    gate_id: int,
    user: dict[str, Any] = Depends(get_current_user),
) -> Response:
    """Delete a gate (gates.admin).

    The built-in default cannot be deleted (section 9), and a gate that
    projects still use must be detached first - a project always has a gate.
    """
    engine = request.app.state.engine
    _require_gates_admin(engine, user)
    with engine.begin() as conn:
        gate = _load_gate(conn, gate_id)
        if gate is None:
            raise HTTPException(status_code=404, detail="Gate not found")
        if gate.is_builtin:
            raise HTTPException(
                status_code=403, detail="The built-in default gate cannot be deleted"
            )
        in_use = conn.execute(
            text("SELECT COUNT(*) FROM projects WHERE gate_id = :gid"),
            {"gid": gate_id},
        ).scalar_one()
        if in_use:
            raise HTTPException(
                status_code=409,
                detail=f"Gate is used by {in_use} project(s); select another gate first",
            )
        conn.execute(text("DELETE FROM gate_conditions WHERE gate_id = :gid"), {"gid": gate_id})
        conn.execute(text("DELETE FROM quality_gates WHERE id = :gid"), {"gid": gate_id})
        deleted_name = gate.name
    write_audit(
        engine,
        action="gate.delete",
        actor_id=int(user["user_id"]),
        target_type="quality_gate",
        target_id=gate_id,
        details={"name": deleted_name},
    )
    return Response(status_code=204)
