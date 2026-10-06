# Decisions

Log of every choice the build guide left open, and every contract change after T0.4.
Format: date, task, decision, reason.

## 2026-10-06

- **T0.1 — Tool configuration lives in a root `pyproject.toml`.** Section 3 shows no root
  package, but ruff, mypy and pytest need one shared config file. The root `pyproject.toml`
  has no build system; the three real distributions stay in `server/`, `agent/` and `schema/`.
- **T0.1 — Primary keys are `bigint` identity columns everywhere.** Section 4 allows UUID or
  bigint; bigint keeps joins and indexes small and URLs readable. No public identifier relies
  on the key being unguessable: routes always sit behind a permission check.
- **T0.1 — Package names.** Distribution `wadjet-schema` provides import `wadjet_schema`,
  distribution `wadjet-server` provides import `app` (entry point `wadjet-server`),
  distribution `wadjet-agent` provides import `wadjet_agent` (entry point `wadjet`).
- **T0.1 — Local development database.** No docker or root access is available in this
  environment, so a user-space PostgreSQL 16.15 binary distribution is used for development
  and tests. This is a developer convenience only; the shipped stack never contains a
  database (section 15.1).
- **T0.1 — Brand assets are generated here.** The guide says brand assets are supplied next
  to the design file, but only `wadjet-build-guide.md` and `wadjet-design.html` are present.
  The eye mark and wordmark paths are taken from the `#lg` / `#wm` symbols in
  `wadjet-design.html` and written to `server/app/static/brand/`.
- **T0.2 — The startup sequence lives in `wadjet-server serve`, not in the ASGI lifespan.**
  Section 15.3.3 describes a process startup sequence (wait, lock, migrate, admin, serve).
  Keeping it in the CLI means `create_app()` stays side-effect free, so tests can build an
  application against any URL — including a dead database, which is how the `/healthz` 503
  test is written.
- **T0.2 — Redaction is applied twice.** Every message passes through
  `Settings.redact()` before it is printed, and a `logging.RedactingFilter` is attached to
  every root handler as a backstop. The filter is merged, never replaced, because handlers
  outlive a single settings object.
- **T0.2 — Alembic runs with an explicit revision anchor.** `0001_baseline` is empty on
  purpose: migrations are forward-only, so every later revision has a parent and the
  machinery can be tested against an empty database before any table exists.
