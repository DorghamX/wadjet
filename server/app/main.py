"""Application factory. The real stack is wired in during T0.2 and later tasks."""

from fastapi import FastAPI


def create_app() -> FastAPI:
    """Build the Wadjet ASGI application."""
    app = FastAPI(
        title="Wadjet", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json"
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
