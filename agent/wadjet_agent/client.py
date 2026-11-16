"""HTTP against the Wadjet server (section 11, steps 2 and 7).

Config fetch and upload are the agent's only two network calls.  Every
failure - unreachable server, rejected token, invalid body - raises
:class:`AgentError`, which the CLI turns into exit code 2.
"""

from __future__ import annotations

import gzip

import httpx

from wadjet_schema import AgentConfig, AnalysisResult, AnalysisUpload

#: How long each call may take before we call it a network error.
CONFIG_TIMEOUT = 30.0
UPLOAD_TIMEOUT = 120.0


class AgentError(Exception):
    """Config, auth or network failure: the scan cannot proceed (exit 2)."""


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _failure(response: httpx.Response, what: str) -> AgentError:
    detail = response.text[:500]
    if response.status_code in (401, 403):
        return AgentError(
            f"{what}: the server rejected the project token (HTTP {response.status_code})"
        )
    return AgentError(f"{what}: HTTP {response.status_code}: {detail}")


def fetch_config(base_url: str, token: str) -> AgentConfig:
    """``GET /api/v1/agent/config`` (section 11, step 2)."""
    url = f"{base_url.rstrip('/')}/api/v1/agent/config"
    try:
        response = httpx.get(url, headers=_headers(token), timeout=CONFIG_TIMEOUT)
    except httpx.HTTPError as exc:
        raise AgentError(f"cannot reach the Wadjet server at {base_url}: {exc}") from exc
    if response.status_code != 200:
        raise _failure(response, "config fetch failed")
    try:
        return AgentConfig.model_validate_json(response.content)
    except ValueError as exc:
        raise AgentError(f"the server sent an invalid config: {exc}") from exc


def upload_analysis(base_url: str, token: str, upload: AnalysisUpload) -> AnalysisResult:
    """``POST /api/v1/analyses`` as gzipped JSON (section 11, step 7)."""
    url = f"{base_url.rstrip('/')}/api/v1/analyses"
    body = gzip.compress(upload.model_dump_json().encode("utf-8"))
    headers = {
        **_headers(token),
        "Content-Encoding": "gzip",
        "Content-Type": "application/json",
    }
    try:
        response = httpx.post(url, content=body, headers=headers, timeout=UPLOAD_TIMEOUT)
    except httpx.HTTPError as exc:
        raise AgentError(f"upload failed: {exc}") from exc
    if response.status_code != 201:
        raise _failure(response, "upload failed")
    try:
        return AnalysisResult.model_validate_json(response.content)
    except ValueError as exc:
        raise AgentError(f"the server sent an invalid result: {exc}") from exc
