"""The shipped stack never contains a database (section 15.1 and 15.5)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = REPO_ROOT / "deploy"
COMPOSE = DEPLOY / "docker-compose.yml"
ENV_EXAMPLE = DEPLOY / ".env.example"


def _compose() -> dict:
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_compose_has_exactly_one_service() -> None:
    services = _compose()["services"]
    assert list(services) == ["wadjet"]


def test_compose_service_has_no_build_volumes_or_dependency_on_a_database() -> None:
    service = _compose()["services"]["wadjet"]
    for key in ("build", "volumes", "depends_on"):
        assert key not in service, f"compose must not contain {key!r}"
    # no top-level volumes key
    assert "volumes" not in _compose(), "compose must not declare volumes"


def test_compose_image_is_referenced_by_tag_not_by_build() -> None:
    service = _compose()["services"]["wadjet"]
    assert service["image"] == "ghcr.io/OWNER/wadjet-server:0.1.0"


def test_compose_defines_no_database_service() -> None:
    for name, service in _compose()["services"].items():
        image = str(service.get("image", "")).lower()
        assert not any(
            hint in image
            for hint in ("postgres", "postgresql", "mysql", "mariadb", "mongo", "redis", "db")
        ), f"{name} looks like a database"
        assert not any(
            hint in name.lower()
            for hint in ("postgres", "postgresql", "mysql", "mariadb", "mongo", "redis", "db")
        ), f"{name} looks like a database"


def test_compose_healthcheck_is_a_cli_call() -> None:
    healthcheck = _compose()["services"]["wadjet"]["healthcheck"]
    test = healthcheck["test"]
    assert isinstance(test, list) and len(test) >= 1
    # first element of test should be "CMD"
    assert test[0] == "CMD", "healthcheck test must start with CMD"
    # remaining args should mention the CLI command and healthcheck
    args = " ".join(str(a) for a in test[1:])
    assert "wadjet-server" in args
    assert "healthcheck" in args


def test_compose_publishes_8080_and_restarts() -> None:
    service = _compose()["services"]["wadjet"]
    assert service["ports"] == ["8080:8080"]
    assert service["restart"] == "unless-stopped"
    assert service["env_file"] == [".env"]


def test_env_example_has_exactly_the_documented_variables() -> None:
    content = ENV_EXAMPLE.read_text(encoding="utf-8")
    expected = (
        "DATABASE_URL=postgresql+psycopg://wadjet:change-me@db.example.internal:5432/wadjet"
        "?sslmode=require\n"
        "WADJET_SECRET_KEY=generate-with-openssl-rand-hex-32\n"
        "WADJET_BASE_URL=https://wadjet.example.com\n"
        "WADJET_ADMIN_USER=admin\n"
        "WADJET_ADMIN_PASSWORD=change-me-on-first-login\n"
    )
    assert content == expected


@pytest.mark.parametrize(
    ("dockerfile", "required"),
    [
        ("Dockerfile.server", ["FROM python:3.12-slim", "USER 10001", "EXPOSE 8080"]),
        ("Dockerfile.agent", ["FROM python:3.12-slim", "USER 10001", 'ENTRYPOINT ["wadjet"]']),
    ],
)
def test_dockerfiles_are_multi_stage_non_root_and_have_required_elements(
    dockerfile: str, required: list[str]
) -> None:
    content = (DEPLOY / dockerfile).read_text(encoding="utf-8")
    assert content.count("FROM ") >= 2, "image must be multi-stage"
    for fragment in required:
        assert fragment in content, f"{dockerfile} must contain {fragment!r}"
    # no USER root in the final stage
    # check final stage only (last FROM block)
    # The final stage is the second FROM; its USER line should be "USER 10001"
    assert "USER root" not in content, f"{dockerfile} must not contain USER root"
