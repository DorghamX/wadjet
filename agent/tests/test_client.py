"""HTTP client tests: config fetch and gzipped upload (section 11)."""

from __future__ import annotations

import gzip
import json

import httpx
import pytest

from wadjet_agent import client
from wadjet_agent.client import AgentError
from wadjet_schema import AgentConfig, AnalysisUpload, Finding, Severity


def make_upload() -> AnalysisUpload:
    finding = Finding(
        tool="bandit",
        rule_id="B101",
        severity=Severity.medium,
        category="bug",
        title="Assert used",
        message="assert statement found",
        file_path="app.py",
        line_start=1,
        line_end=1,
        snippet="assert x",
    )
    return AnalysisUpload(
        project_key="demo",
        commit_sha="abc",
        ci_url=None,
        findings=[finding],
        metrics={},
        scanner_runs={"bandit": {"version": "1.7.10", "status": "ok", "duration": 0.1}},
    )


def test_fetch_config_success(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = AgentConfig(
        project_key="demo",
        settings={"scope": {"exclude": ["private/"]}},
        gate_conditions={"conditions": []},
        exclusion_globs=["private/"],
    )

    def fake_get(url: str, **kwargs: object) -> httpx.Response:
        assert url == "https://wadjet.example/api/v1/agent/config"
        headers = kwargs.get("headers") or {}
        assert headers["Authorization"] == "Bearer tok"  # type: ignore[index]
        return httpx.Response(200, json=payload.model_dump())

    monkeypatch.setattr(client.httpx, "get", fake_get)
    config = client.fetch_config("https://wadjet.example", "tok")
    assert config.project_key == "demo"
    assert config.exclusion_globs == ["private/"]


def test_fetch_config_reports_auth_and_network_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client.httpx, "get", lambda url, **kwargs: httpx.Response(401, text="nope"))
    with pytest.raises(AgentError, match="rejected the project token"):
        client.fetch_config("https://wadjet.example", "tok")

    def unreachable(url: str, **kwargs: object) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(client.httpx, "get", unreachable)
    with pytest.raises(AgentError, match="cannot reach"):
        client.fetch_config("https://wadjet.example", "tok")

    monkeypatch.setattr(client.httpx, "get", lambda url, **kwargs: httpx.Response(500, text="boom"))
    with pytest.raises(AgentError, match="HTTP 500"):
        client.fetch_config("https://wadjet.example", "tok")


def test_upload_sends_gzipped_json(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        captured["url"] = url
        captured.update(kwargs)
        return httpx.Response(
            201,
            json={
                "analysis_id": "12",
                "gate_status": "passed",
                "gate_details": {"conditions": []},
                "issues_resolved": 0,
                "issues_created": 1,
            },
        )

    monkeypatch.setattr(client.httpx, "post", fake_post)
    upload = make_upload()
    result = client.upload_analysis("https://wadjet.example/", "tok", upload)

    assert captured["url"] == "https://wadjet.example/api/v1/analyses"
    headers = captured["headers"] or {}
    assert headers["Content-Encoding"] == "gzip"  # type: ignore[index]
    body = gzip.decompress(captured["content"])  # type: ignore[arg-type]
    sent = json.loads(body)
    assert sent["project_key"] == "demo"
    assert sent["findings"][0]["rule_id"] == "B101"
    assert result.analysis_id == "12"
    assert result.gate_status == "passed"


def test_upload_failures_raise_agent_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        client.httpx, "post", lambda url, **kwargs: httpx.Response(413, text="too big")
    )
    with pytest.raises(AgentError, match="HTTP 413"):
        client.upload_analysis("https://wadjet.example", "tok", make_upload())

    monkeypatch.setattr(
        client.httpx,
        "post",
        lambda url, **kwargs: httpx.Response(201, json={"not": "a result"}),
    )
    with pytest.raises(AgentError, match="invalid result"):
        client.upload_analysis("https://wadjet.example", "tok", make_upload())
