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
- **T2.1 — JSONB columns are real `JSONB`, not text.** `analyses.scanner_runs`,
  `analyses.metrics`, `analyses.gate_details`, `issues.fixed_versions`,
  `issues.references` and `issue_events.payload` use the Postgres JSONB type; the
  database is PostgreSQL only (section 15.1), so portability buys nothing.
- **T2.1 — `issues` is unique on (project_id, fingerprint).** Section 5 makes one
  persistent issue per fingerprint per project; the constraint keeps the matcher's
  rule 1 honest instead of trusting application code alone.
- **T2.2 — The flagged/context split inside a snippet is derived from line numbers.**
  The agent builds a snippet as up to 3 context lines above, the flagged lines
  (`line_start..line_end`), then up to 3 below (section 5.1), so
  `split_snippet()` reverses that convention; a snippet that does not follow it is
  treated as entirely flagged. The agent (T2.6) must build snippets exactly so.
- **T2.2 — On a same-lines or moved match the stored issue adopts the new
  fingerprint, path, lines and snippet.** The guide says "update context hash and
  line numbers"; adopting the incoming fingerprint keeps the unique constraint and
  rule 1 working on the next upload. Triage and presence are never touched by a
  match - only by a human flag or by resolution/reopen.
- **T2.2 — Rules are applied as whole-upload passes, not per-finding in input
  order:** all exact hits first, then all same-lines, then all moves. Each existing
  issue is claimed at most once; candidates are claimed in id order, incoming in
  upload order, so the result is deterministic.
- **T2.2 — An incomplete analysis still ingests what arrived (matches, new
  sightings, reopened issues) but never resolves anything** (section 5.4).
- **T2.3 — The Bandit KB covers the full bandit 1.9.4 registry: 75 test IDs
  (B101..B704).** The guide says "B101 to B703"; current bandit adds B704, so the
  KB is a superset of what the guide names. The completeness test freezes the
  registry in the test file (bandit itself is not a server dependency, so CI stays
  deterministic) and additionally cross-checks against an installed bandit when one
  is importable - dev machines catch drift immediately.
- **T2.3 — pip-audit enrichment is computed, not tabulated.** Advisory text becomes
  the description, impact is generic by vulnerability, fix text is built from
  `fixed_versions` ("Upgrade `pkg` to `v`" / "No fixed version published yet..."),
  and CVE identifiers gain an NVD reference. A static file could not track an
  advisory database.
- **T2.3 — `ruff.yml` is keyed by family, longest prefix first** (C90 before C,
  PLE before E), because Ruff rule explanations arrive per-rule at scan time
  (`raw.explanation`) while impact/fix are the parts that are stable per family.
- **T2.3 — `_fallback.yml` leaves `description` empty on purpose** so the scanner's
  own message survives for unknown rules; impact and fix carry the generic
  guidance. The loader merges: KB text wins where present, scanner text fills gaps,
  and the KB's CWE wins over the scanner's when the KB has one.
- **T2.3 — PyYAML became a server dependency** (guide's KB files are YAML), with
  `types-PyYAML` in the server dev extra for mypy.
- **T2.4 — The ingest endpoint reads the raw body itself.** It must enforce the
  20 MB cap and `Content-Encoding` (gzip) policy *before* any JSON parsing, so the
  route is `async`, reads `await request.body()`, and runs the blocking DB work in
  a threadpool (`run_in_threadpool`) - the rest of the app stays sync per the guide.
  Unsupported encodings get 415, oversized or gzip-bomb payloads 413, bad JSON 422.
- **T2.4 — Auth dependencies moved to `server/app/deps.py`.** `get_current_user`
  and `require_project_token` were closures inside `create_app`; routers cannot
  import closures. They are now module-level, read the engine from `app.state`,
  and are still re-exposed as `application.state.require_project_token` so existing
  tests keep working.
- **T2.4 — Exclusion globs are a documented approximation of gitignore.** A plain
  name (`.venv/`, `build/`) matches that path segment at any depth; patterns with
  wildcards or slashes match the whole relative path with `fnmatch`, whose `*`
  crosses `/` (gitignore-like for simple patterns). A project's stored
  `scope.exclude` replaces the defaults; absent settings fall back to the editable
  default list. Dependency findings (no path) are never excluded.
- **T2.4 — JSONB parameters are serialized with `json.dumps` (with `default=str`),
  the same convention as `audit.py`.** psycopg3 does not adapt Python dicts/lists
  through SQLAlchemy `text()` placeholders; the tests caught this immediately.
- **T2.4 — Gate evaluation landed here, not in T2.5.** The frozen `AnalysisResult`
  contract requires a gate verdict at upload time, so ingest computes the
  project-scoped issue metrics, evaluates the project's conditions and stores
  `gate_status`/`gate_details`/`metrics` in the same transaction. T2.5 then adds the
  built-in default gate, gate selection and the section-9 matrix.
- **T2.4 — Metrics are scoped to the uploading project** (`WHERE project_id = :pid`).
  The first version counted globally and the gate tests caught it: a quality gate
  must never see another project's issues.
- **T2.4 — Analysis status is derived, not sent:** `complete` only when every entry
  in `scanner_runs` is a dict with `status == "ok"`; an empty dict is `complete`.
  An incomplete analysis resolves nothing (section 5.4) and fails the gate with a
  synthetic `all_scanners_completed` condition - T3.5 refines this behind
  `fail_on_scanner_error`.
- **T2.4 — Coverage flows from the agent's uploaded metrics** into
  `coverage_line_percent`; stored analysis metrics are the merge of uploaded and
  computed (computed wins on collision). A gate condition naming a metric the
  analysis does not produce shows `actual: null` and does not trigger; an unknown
  *operator* fails closed.
- **T2.4 — Duplicate findings inside one upload are deduped by fingerprint**
  before lifecycle planning (matching only pairs against pre-existing issues, so a
  doubled dependency row would otherwise hit the `(project_id, fingerprint)`
  uniqueness).
- **T2.4 — No audit row for ingest.** The guide's audit list does not include
  uploads, and `write_audit` opens its own connection - committing it early would
  break the one-transaction guarantee the endpoint exists to provide.
