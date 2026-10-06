"""ASGI application factory and the liveness endpoint (section 15.3.5)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app import __version__
from app.config import Settings, load_settings
from app.db import create_database_engine, create_session_factory, ping_database
from app.logging_setup import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the Wadjet application.

    The startup sequence of section 15.3.3 (wait for the database, advisory lock,
    migrations, first admin) belongs to ``wadjet-server serve``; the application itself
    only ever reports on the database it was given.
    """
    resolved = settings if settings is not None else load_settings()
    configure_logging(resolved)

    application = FastAPI(
        title="Wadjet",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    engine = create_database_engine(resolved)
    application.state.settings = resolved
    application.state.engine = engine
    application.state.session_factory = create_session_factory(engine)

    @application.get("/healthz")
    def healthz() -> JSONResponse:
        """Liveness and database check: 200 when ``SELECT 1`` answers within 2 seconds."""
        if ping_database(engine, timeout_seconds=2.0):
            return JSONResponse(status_code=200, content={"status": "ok", "db": "ok"})
        return JSONResponse(status_code=503, content={"status": "unavailable", "db": "down"})

    return application
