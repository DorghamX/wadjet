"""``POST /api/v1/analyses`` - one-transaction ingest (sections 11, 5, 6, 9).

The agent uploads gzipped JSON; the server ingests in one transaction and
returns the analysis id, gate result and dashboard URL synchronously. One
transaction means a crash never leaves half an analysis behind: either the
analysis, its issue lifecycle changes and the gate result all land, or none
of them do.
"""

from __future__ import annotations

import json
import zlib
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import Connection, Engine, text
from starlette.concurrency import run_in_threadpool

from app.deps import require_project_token
from app.exclusions import effective_exclusion_globs
from app.fingerprint import ComputedFinding, compute_fingerprints
from app.gate import evaluate_gate
from app.kb import enrich_finding
from app.lifecycle import Event, ExistingIssue, LifecyclePlan, plan_lifecycle
from wadjet_schema import AnalysisResult, AnalysisUpload, Category, filter_findings

#: Payload cap for uploads, compressed or not (section 11: 20 MB).
MAX_UPLOAD_BYTES = 20 * 1024 * 1024

router = APIRouter()

EXISTING_ISSUE_COLUMNS = (
    "id",
    "fingerprint",
    "tool",
    "rule_id",
    "category",
    "file_path",
    "snippet",
    "line_start",
    "line_end",
    "triage_status",
    "presence",
    "first_seen_analysis_id",
)


def derive_analysis_status(scanner_runs: dict[str, Any]) -> str:
    """``complete`` only when every scanner run reports ``ok`` (section 6)."""
    if not scanner_runs:
        return "complete"
    for run in scanner_runs.values():
        if not isinstance(run, dict) or run.get("status") != "ok":
            return "incomplete"
    return "complete"


def _decompress_gzip(body: bytes) -> bytes:
    """Gunzip with the payload cap enforced on the output (bomb protection)."""
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = decoder.decompress(body, MAX_UPLOAD_BYTES + 1)
    if len(out) > MAX_UPLOAD_BYTES or decoder.unconsumed_tail:
        raise HTTPException(status_code=413, detail="Upload exceeds the 20 MB cap")
    out += decoder.flush()
    if len(out) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds the 20 MB cap")
    return out


def _read_payload(request: Request, body: bytes) -> bytes:
    """Apply the Content-Encoding policy and the size cap."""
    if len(body) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds the 20 MB cap")
    encoding = (request.headers.get("content-encoding") or "").lower().strip()
    if encoding in ("", "identity"):
        return body
    if encoding == "gzip":
        return _decompress_gzip(body)
    raise HTTPException(status_code=415, detail="Unsupported Content-Encoding")


def _reject_secret_leaks(upload: AnalysisUpload) -> None:
    """Never store secret values (section 11): a finding of category
    ``secret`` may carry only file, line, type and hash.

    Runs before any database work, so a leaky upload writes nothing. The
    detail names the offending *fields* - never the content that might be
    hiding inside them, which would echo the value back out.
    """
    for finding in upload.findings:
        if finding.category != Category.secret:
            continue
        offenders = []
        if finding.snippet:
            offenders.append("snippet")
        if (
            finding.package
            or finding.installed_version
            or finding.vuln_id
            or finding.aliases
            or finding.fixed_versions
            or finding.cwe
        ):
            offenders.append("vulnerability or dependency fields")
        extra_keys = sorted(set(finding.raw or ()) - {"hashed_secret"})
        if extra_keys:
            offenders.append(f"raw keys {extra_keys}")
        if offenders:
            where = f"{finding.file_path}:{finding.line_start}"
            raise HTTPException(
                status_code=422,
                detail=(
                    f"secret finding {where} may only carry file, line, type "
                    f"and hash; remove: {', '.join(offenders)}"
                ),
            )


def _load_existing(conn: Connection, project_id: int) -> list[ExistingIssue]:
    rows = conn.execute(
        text(
            "SELECT id, fingerprint, tool, rule_id, category, file_path, snippet, "
            "line_start, line_end, triage_status, presence, first_seen_analysis_id "
            "FROM issues WHERE project_id = :pid"
        ),
        {"pid": project_id},
    ).fetchall()
    return [ExistingIssue(**dict(zip(EXISTING_ISSUE_COLUMNS, row, strict=True))) for row in rows]


def _dedupe(computed: list[ComputedFinding]) -> list[ComputedFinding]:
    """Keep the first of any repeated fingerprint.

    Duplicates inside one upload (a tool listing the same finding twice)
    would otherwise violate the (project, fingerprint) uniqueness: matching
    only ever pairs against issues that already exist.
    """
    seen: set[str] = set()
    kept: list[ComputedFinding] = []
    for item in computed:
        if item.fingerprint not in seen:
            seen.add(item.fingerprint)
            kept.append(item)
    return kept


def _bind(fields: dict[str, Any]) -> dict[str, Any]:
    """Serialize dict/list values for JSONB columns.

    psycopg3 does not adapt them on its own (same convention as audit.py).
    """
    return {
        name: json.dumps(value, default=str) if isinstance(value, (dict, list)) else value
        for name, value in fields.items()
    }


def _insert_issue(conn: Connection, fields: dict[str, Any]) -> int:
    columns = ", ".join(f'"{name}"' for name in fields)
    placeholders = ", ".join(f":{name}" for name in fields)
    issue_id = conn.execute(
        text(f"INSERT INTO issues ({columns}) VALUES ({placeholders}) RETURNING id"),
        _bind(fields),
    ).scalar_one()
    return int(issue_id)


def _update_issue(conn: Connection, issue_id: int, fields: dict[str, Any]) -> None:
    assignments = ", ".join(f'"{name}" = :{name}' for name in fields)
    conn.execute(
        text(f"UPDATE issues SET {assignments} WHERE id = :_issue_id"),
        {**_bind(fields), "_issue_id": issue_id},
    )


def _insert_events(conn: Connection, issue_id: int, events: list[Event]) -> None:
    """Append timeline entries; a scan is a machine actor, so actor_id is null."""
    for event in events:
        conn.execute(
            text(
                "INSERT INTO issue_events (issue_id, actor_id, type, payload) "
                "VALUES (:issue_id, NULL, :type, :payload)"
            ),
            {
                "issue_id": issue_id,
                "type": event.type,
                "payload": json.dumps(dict(event.payload), default=str),
            },
        )


def _apply_plan(conn: Connection, plan: LifecyclePlan) -> None:
    for creation in plan.creations:
        finding = creation.computed.finding
        enrichment = enrich_finding(finding)
        fields = dict(creation.fields)
        fields.update(
            {
                "title": enrichment.title,
                "description": enrichment.description,
                "impact": enrichment.impact,
                "fix": enrichment.fix,
                "references": enrichment.references,
                "cwe": enrichment.cwe,
            }
        )
        issue_id = _insert_issue(conn, fields)
        _insert_events(conn, issue_id, creation.events)
    for update in (*plan.updates, *plan.resolutions):
        _update_issue(conn, update.issue_id, update.fields)
        _insert_events(conn, update.issue_id, update.events)


def _ingest(engine: Engine, upload: AnalysisUpload, token: dict[str, Any]) -> AnalysisResult:
    """Run the whole ingest inside one transaction (section 11, step 7)."""
    project_id = token["project_id"]
    now = datetime.now(timezone.utc)

    with engine.begin() as conn:
        project = conn.execute(
            text("SELECT id, key, settings FROM projects WHERE id = :pid"),
            {"pid": project_id},
        ).first()
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if upload.project_key != project.key:
            raise HTTPException(status_code=403, detail="Token is not valid for this project")

        settings: dict[str, Any] = {}
        if project.settings:
            try:
                parsed = json.loads(project.settings)
                if isinstance(parsed, dict):
                    settings = parsed
            except ValueError:
                settings = {}

        # Defense in depth: the server drops excluded paths itself.
        kept, excluded_count = filter_findings(upload.findings, effective_exclusion_globs(settings))
        computed = _dedupe(compute_fingerprints(project.key, kept))
        existing = _load_existing(conn, project_id)
        status = derive_analysis_status(upload.scanner_runs)

        analysis_id = conn.execute(
            text(
                "INSERT INTO analyses "
                "(project_id, commit_sha, ci_url, started_at, finished_at, status, "
                "scanner_runs, excluded_count) "
                "VALUES (:pid, :commit_sha, :ci_url, :now, :now, :status, :scanner_runs, "
                ":excluded_count) RETURNING id"
            ),
            {
                "pid": project_id,
                "commit_sha": upload.commit_sha,
                "ci_url": upload.ci_url,
                "now": now,
                "status": status,
                "scanner_runs": json.dumps(dict(upload.scanner_runs), default=str),
                "excluded_count": excluded_count,
            },
        ).scalar_one()

        plan = plan_lifecycle(
            existing,
            computed,
            analysis_id=analysis_id,
            analysis_status=status,
            now=now,
            extra_issue_fields={"project_id": project_id},
        )
        _apply_plan(conn, plan)

        # The gate sees the issues this analysis just wrote.
        gate_status, gate_details, computed_metrics = evaluate_gate(
            conn,
            project_id,
            analysis_status=status,
            uploaded_metrics=upload.metrics,
        )
        stored_metrics = {**upload.metrics, **computed_metrics}
        conn.execute(
            text(
                "UPDATE analyses SET gate_status = :gs, gate_details = :gd, "
                "metrics = :metrics WHERE id = :aid"
            ),
            {
                "gs": gate_status,
                "gd": json.dumps({"conditions": gate_details}, default=str),
                "metrics": json.dumps(stored_metrics, default=str),
                "aid": analysis_id,
            },
        )

    return AnalysisResult(
        analysis_id=str(analysis_id),
        gate_status=gate_status,
        gate_details={"conditions": gate_details},
        issues_resolved=len(plan.resolutions),
        issues_created=len(plan.creations),
    )


@router.post("/api/v1/analyses", response_model=AnalysisResult, status_code=201)
async def upload_analysis(
    request: Request, token: dict[str, Any] = Depends(require_project_token)
) -> AnalysisResult:
    """Ingest one analysis upload for the token's project (section 11)."""
    body = await request.body()
    payload = _read_payload(request, body)
    try:
        upload = AnalysisUpload.model_validate_json(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=json.loads(exc.json())) from None
    _reject_secret_leaks(upload)
    # Blocking database work off the event loop; the app's endpoints are sync.
    return await run_in_threadpool(_ingest, request.app.state.engine, upload, token)
