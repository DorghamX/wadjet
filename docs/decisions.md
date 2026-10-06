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
- **T0.4 — Frozen contract lives in `schema/wadjet_schema/models.py`.** Finding, Severity,
  Category, AnalysisUpload, AnalysisResult and AgentConfig are Pydantic v2 models with
  `FINGERPRINT_*` constants beside them. Any change to this file from here on gets a line
  in this log.
- **T1.1 — Server-side sessions in a `sessions` table, not signed stateless tokens.**
  Section 2 requires DB-backed sessions so a logout or a password change can revoke every
  active session immediately (`revoke_session`, `expire_sessions_for_user`).
- **T1.1 — The UI authenticates with the session cookie; the `Authorization: Bearer`
  header accepts the same session token as a fallback** for API clients and tests
  (section 15: session cookie for the UI, Bearer project token for agent endpoints only).
- **T1.1 — CSRF uses the double-submit-cookie pattern.** A readable `wadjet_csrf` cookie
  is issued on safe requests and echoed in `X-CSRF-Token` on unsafe ones; enforced only
  when the request actually carries cookies, so health checks and cookie-less API clients
  keep working while cross-site browser posts cannot. Agent endpoints
  (`/api/v1/agent*`, `/api/v1/analyses*`) are exempt: they carry no ambient authority.
- **T1.1 — The `sessions` table got its own migration (`0006_sessions`).** It was missing
  from `0002_users`; login would have failed at runtime. Migrations are forward-only, so
  the fix is a new revision rather than an edit.
- **T1.1 — Login rate limiting is in-process** (per username+IP key, 5 failures per
  5 minutes, exponential lockout from 1 minute to 1 hour). The guide leaves the store
  open; a single-process dict is correct for the one-container deployment of section 15
  and is trivially testable. A shared store would only be needed for replicas.
- **T1.2 — `can()` takes an optional `project_id`.** Project-scoped permissions are
  checked against `project_grants` (direct and via group membership); global permissions
  (`gates.admin`, `users.admin`) are checked with `project_id=None` and, for now, only a
  global admin holds them.
- **T1.3 — Tokens are 32 random bytes shown once as hex with an 8-char display prefix,
  stored as a SHA-256 digest.** Lookup is by hash, then `revoked_at`/`expires_at` are
  checked; `last_used_at` is refreshed on every successful agent request.
- **T1.4 — One `write_audit()` entry point, and it never raises.** A failed audit insert
  is logged with `logger.exception` instead of breaking the action it describes: an
  outage in bookkeeping must not roll back a user's flag or a token revocation.
- **T1.4 — `audit_log.target_id` is a string.** The guide does not type it, and targets
  span users, projects, gates and issues; one varchar keeps a single writer function.
  `actor_id` stays a nullable FK to `users` so anonymous events (failed logins) fit.
