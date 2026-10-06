"""Engine creation, sessions, wait-for-database and the startup advisory lock."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings

log = logging.getLogger("wadjet.db")

#: Fixed key for the migration advisory lock (section 15.3.3).
MIGRATION_LOCK_KEY = 7_610_202


def create_database_engine(settings: Settings) -> Engine:
    """Build an engine exactly as described in section 15.3.2."""
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        connect_args={"connect_timeout": 10, "application_name": "wadjet"},
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """One session factory per application instance."""
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def wait_for_database(
    engine: Engine,
    seconds: int,
    redact: Callable[[str], str] = lambda value: value,
) -> bool:
    """Retry connecting until ``seconds`` elapse, logging every attempt (section 15.3.3)."""
    deadline = time.monotonic() + max(seconds, 0)
    delay = 0.5
    attempt = 0
    while True:
        attempt += 1
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            if attempt > 1:
                log.info("database reachable after %d attempt(s)", attempt)
            return True
        except Exception as exc:  # noqa: BLE001 - every driver error means "keep waiting"
            log.warning(
                "database attempt %d failed: %s",
                attempt,
                redact(str(exc) or type(exc).__name__),
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(delay, remaining))
        delay = min(delay * 2, 5.0)


def ping_database(engine: Engine, timeout_seconds: float = 2.0) -> bool:
    """``SELECT 1`` bounded by ``timeout_seconds``; used by ``GET /healthz``."""

    def _ping() -> bool:
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql(f"SET statement_timeout TO {int(timeout_seconds * 1000)}")
                conn.execute(text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001 - any failure means "not healthy"
            return False

    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="wadjet-ping")
    try:
        return pool.submit(_ping).result(timeout=timeout_seconds)
    except (FutureTimeoutError, OSError):
        return False
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


@contextmanager
def advisory_lock(engine: Engine, key: int = MIGRATION_LOCK_KEY) -> Iterator[None]:
    """Hold a PostgreSQL advisory lock for the duration of the block (section 15.3.3).

    The lock is session scoped, so it is taken and released with explicit commits and the
    connection is always released unlocked. Starting several replicas at once is safe.
    """
    conn = engine.connect()
    try:
        conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": key})
        conn.commit()
        try:
            yield
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            conn.commit()
    finally:
        conn.close()
