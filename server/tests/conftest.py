"""Fixtures for the server test suite."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text

from app.config import Settings
from app.main import create_app

SECRET_KEY = "test-secret-key-0123456789abcdef0123456789abcdef"


@pytest.fixture()
def settings(database_url: str) -> Settings:
    """Settings bound to the session schema of the test database."""
    return Settings(
        database_url=database_url,
        secret_key=SECRET_KEY,
        base_url="http://testserver",
        cookie_secure=False,
        auto_migrate=False,
        log_level="debug",
    )


@pytest.fixture(scope="session")
def engine(database_url: str) -> Engine:
    """Database engine for direct SQL in tests."""
    eng = create_engine(database_url)
    yield eng
    eng.dispose()


@pytest.fixture()
def app(settings: Settings) -> Iterator[FastAPI]:
    """A Wadjet application pointed at the test database.

    Every application owns its own engine (section 15.3.2), so the fixture
    disposes it on the way out: a suite that leaks one pool per test would
    run PostgreSQL out of connections before it ran out of assertions.
    """
    application = create_app(settings)
    yield application
    application.state.engine.dispose()


@pytest.fixture()
def client(app: FastAPI) -> Iterator[TestClient]:
    """HTTP client for the application."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def admin_user_id(engine: Engine) -> int:
    """Create an admin user and return their ID."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('admin', 'admin@test.com', 'hash', TRUE, TRUE) RETURNING id"
            )
        )
        return result.scalar_one()


@pytest.fixture(scope="session")
def regular_user_id(engine: Engine) -> int:
    """Create a regular user and return their ID."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('user', 'user@test.com', 'hash', FALSE, TRUE) RETURNING id"
            )
        )
        return result.scalar_one()


@pytest.fixture(scope="session")
def project_id(engine: Engine, admin_user_id: int) -> int:
    """Create a test project and return its ID."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES ('test-project', 'Test Project', :uid) RETURNING id"
            ),
            {"uid": admin_user_id},
        )
        return result.scalar_one()


@pytest.fixture(scope="session")
def group_id(engine: Engine) -> int:
    """Create a test group and return its ID."""
    with engine.begin() as conn:
        result = conn.execute(text("INSERT INTO groups (name) VALUES ('test-group') RETURNING id"))
        return result.scalar_one()


@pytest.fixture(scope="session")
def viewer_user_id(engine: Engine, project_id: int) -> int:
    """Create a viewer user with viewer grant on test-project."""
    with engine.begin() as conn:
        # Create user
        result = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('viewer', 'viewer@test.com', 'hash', FALSE, TRUE) RETURNING id"
            )
        )
        uid = result.scalar_one()
        # Get project id
        pid = conn.execute(text("SELECT id FROM projects WHERE key = 'test-project'")).scalar_one()
        # Grant viewer permission
        conn.execute(
            text(
                "INSERT INTO project_grants (project_id, subject_type, subject_id, permission) "
                "VALUES (:pid, 'user', :uid, 'project.browse')"
            ),
            {"pid": pid, "uid": uid},
        )
        return uid


@pytest.fixture(scope="session")
def developer_user_id(engine: Engine, project_id: int) -> int:
    """Create a developer user with developer grants on test-project."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('developer', 'developer@test.com', 'hash', FALSE, TRUE) RETURNING id"
            )
        )
        uid = result.scalar_one()
        pid = conn.execute(text("SELECT id FROM projects WHERE key = 'test-project'")).scalar_one()
        # Grant developer permissions
        for perm in ["project.browse", "issue.comment", "issue.request", "issue.assign"]:
            conn.execute(
                text(
                    "INSERT INTO project_grants (project_id, subject_type, subject_id, permission) "
                    "VALUES (:pid, 'user', :uid, :perm)"
                ),
                {"pid": pid, "uid": uid, "perm": perm},
            )
        return uid


@pytest.fixture(scope="session")
def triager_user_id(engine: Engine, project_id: int) -> int:
    """Create a triager user with triager grants on test-project."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('triager', 'triager@test.com', 'hash', FALSE, TRUE) RETURNING id"
            )
        )
        uid = result.scalar_one()
        pid = conn.execute(text("SELECT id FROM projects WHERE key = 'test-project'")).scalar_one()
        # Grant triager permissions
        perms = [
            "project.browse",
            "issue.comment",
            "issue.request",
            "issue.assign",
            "flag.confirm",
            "flag.false_positive",
            "flag.accepted_risk",
            "flag.wont_fix",
            "flag.reopen",
        ]
        for perm in perms:
            conn.execute(
                text(
                    "INSERT INTO project_grants (project_id, subject_type, subject_id, permission) "
                    "VALUES (:pid, 'user', :uid, :perm)"
                ),
                {"pid": pid, "uid": uid, "perm": perm},
            )
        return uid


@pytest.fixture(scope="session")
def project_admin_user_id(engine: Engine, project_id: int) -> int:
    """Create a project admin user with project_admin grants on test-project."""
    with engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('projadmin', 'projadmin@test.com', 'hash', FALSE, TRUE) RETURNING id"
            )
        )
        uid = result.scalar_one()
        pid = conn.execute(text("SELECT id FROM projects WHERE key = 'test-project'")).scalar_one()
        # Grant project_admin permissions
        perms = [
            "project.browse",
            "issue.comment",
            "issue.request",
            "issue.assign",
            "flag.confirm",
            "flag.false_positive",
            "flag.accepted_risk",
            "flag.wont_fix",
            "flag.reopen",
            "project.admin",
        ]
        for perm in perms:
            conn.execute(
                text(
                    "INSERT INTO project_grants (project_id, subject_type, subject_id, permission) "
                    "VALUES (:pid, 'user', :uid, :perm)"
                ),
                {"pid": pid, "uid": uid, "perm": perm},
            )
        return uid


@pytest.fixture(scope="session")
def group_member_user_id(engine: Engine, group_id: int, project_id: int) -> int:
    """Create a user in the test group with viewer grant via group."""
    with engine.begin() as conn:
        # Create user
        result = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('groupmember', 'groupmember@test.com', 'hash', FALSE, TRUE) RETURNING id"
            )
        )
        uid = result.scalar_one()
        # Add to group
        conn.execute(
            text("INSERT INTO group_members (group_id, user_id) VALUES (:gid, :uid)"),
            {"gid": group_id, "uid": uid},
        )
        # Get project id
        pid = conn.execute(text("SELECT id FROM projects WHERE key = 'test-project'")).scalar_one()
        # Grant viewer permission to group
        conn.execute(
            text(
                "INSERT INTO project_grants (project_id, subject_type, subject_id, permission) "
                "VALUES (:pid, 'group', :gid, 'project.browse')"
            ),
            {"pid": pid, "gid": group_id},
        )
        return uid


@pytest.fixture()
def live_server(settings: Settings) -> Iterator[str]:
    """A real uvicorn server on a local port, for CLI health checks."""
    application = create_app(settings)
    config = uvicorn.Config(
        application,
        host="127.0.0.1",
        port=8123,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:  # pragma: no cover - startup failure
        pytest.fail("test server did not start")
    yield "http://127.0.0.1:8123"
    server.should_exit = True
    thread.join(timeout=10)
    application.state.engine.dispose()
