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
- **T2.5 — Migration `0008_seed_default_gate` freezes the six section-9 conditions
  in the migration itself** (Wadjet default: blocker, critical, high, secrets,
  dependency_vulns_with_fix, coverage < 70). A migration must never change
  behaviour when application code evolves, so it does not import `app.gate`;
  `test_gates.py` freezes the same list and fails if either side drifts.
- **T2.5 — A project with no gate falls back to the default gate** with
  `COALESCE(p.gate_id, (SELECT id FROM quality_gates WHERE is_default ...))` in
  `load_gate_conditions`: every analysis is judged by something. A project that
  picked a gate is never fallback'd, even if that gate has zero conditions.
- **T2.5 — The gate engine itself landed with T2.4**, because the frozen
  `AnalysisResult` contract needs a verdict at upload time; T2.5 completes the
  story: built-in default, fallback, CRUD API and the section-9 matrix tests
  (all five operators, metric vocabulary, triage exclusions).
- **T2.5 — `is_default` and `is_builtin` are never API-writable.** They belong to
  the migration; the API only creates plain gates. The built-in gate is editable
  (name/conditions, section 9) but DELETE refuses it with 403, and a gate still
  referenced by projects is refused with 409 ("select another gate first") rather
  than silently reassigning projects.
- **T2.5 — Gate CRUD lives in `server/app/api/gates.py`:** GET needs any session;
  POST/PATCH/DELETE need `gates.admin` (global, admin-only via `can()`); duplicate
  names are 409; unknown metric/operator are 422 from pydantic validators that
  share `ALL_METRICS`/`OPERATORS` with the engine; every change writes a
  `gate.create`/`gate.update`/`gate.delete` audit entry (section 15.4).
- **T2.6 — Exclusion matching moved into `wadjet_schema.exclusions`.** The agent
  post-filters and the server drops, so the logic lives once in the shared
  contract package (`DEFAULT_EXCLUSION_GLOBS`, `path_is_excluded`,
  `filter_findings`); `app.exclusions` keeps only the server-side
  `effective_exclusion_globs`. This is the "never duplicate logic" principle
  applied to a second consumer.
- **T2.6 — `GET /api/v1/agent/config` returns `gate_conditions` as
  `{"conditions": [...]}`**, mirroring `gate_details` in `AnalysisResult` (the
  frozen contract types the field as a dict). The default-gate fallback
  (migration 0008) travels with every config fetch, settings come back raw
  until T3.4's schema validates them, and the T1.3 stub route in `test_tokens`
  is deleted now that the real endpoint exists.
- **T2.6 — A parseable JSON body means "scanner ok", regardless of exit code.**
  Bandit exits 1 when it finds issues and pip-audit exits 1 when it finds
  vulnerabilities, and the codes differ across versions; both verified against
  the recorded fixtures. Unparseable/empty output becomes `status=error`, which
  makes the analysis incomplete (exit 3) even though the upload still happens.
- **T2.6 — Fixtures are real recordings:** `fixtures/bandit/1.9.4/` from
  bandit 1.9.4 run over the committed sample (relative filenames, so the
  fixture is portable and snippets rebuild from the sample source) and
  `fixtures/pip-audit/2.10.1/` from pip-audit 2.10.1 auditing
  `requests==2.19.0`. Bandit's JSON has no `line_end`; the adapter derives it
  from `line_range[-1]`. Modern pip-audit wraps findings in `{"dependencies":
  ...}`; `run` unwraps it and still accepts the older bare-list shape.
- **T2.6 — The agent builds snippets with exactly `min(3, line_start - 1)`
  lines above the flagged region** - the same formula the server's
  `split_snippet` uses to re-derive the split. The first version used the wrong
  start index; the contract test caught it before anything was uploaded.
- **T2.6 — Exit-code precedence: incomplete beats the gate verdict.** Any
  scanner run with `status=error` returns 3 even if the gate passed; config,
  auth and network failures (including a rejected upload, e.g. 413) return 2;
  otherwise 0/1 from `gate_status`. `wadjet doctor` returns 2 on config error,
  1 on a missing/unsupported tool, 0 otherwise - the guide does not define
  doctor's codes, so the scan codes were reused by severity.
- **T2.6 — `scan --dry-run` prints the plan only** (project, include paths,
  exclusions, gate conditions, per-tool status) without running scanners or
  uploading, matching the guide's "prints what would run". The dashboard link
  is composed agent-side (`{url}/projects/{key}`) because the frozen
  `AnalysisResult` carries no URL. `WADJET_PYTHON` overrides the interpreter
  `python -m pip_audit` runs under (default `sys.executable`).
- **T2.6 — `agent/fixtures` is excluded from ruff:** the recorded sample is
  deliberately vulnerable (and would be "fixed" by RET504), and the agent test
  file `test_cli.py` was renamed `test_agent_cli.py` to avoid a pytest module
  name collision with `server/tests/test_cli.py` (no `__init__.py` packages).
- **T2.7 - The end-to-end script is `tests/e2e.py`, run by `make e2e`** (root
  `tests/` is not in pytest's `testpaths`, so the suite never starts a server).
  Each run creates a unique schema with the same `?options=search_path` URL
  trick the test suite uses, migrates it, starts `wadjet-server serve` on a
  free port, seeds admin/project/token in-process, drives the real `wadjet`
  CLI against a temp **copy** of the sample, and drops the schema in `finally`.
  All flag/triage manipulation is direct SQL - there is no triage API until
  T4.x.
- **T2.7 - Scanner binaries resolve next to the agent's interpreter first**
  (`local_executable` in `adapters/base.py`). The first e2e run failed because
  `bandit` was launched as a bare name and the inherited `PATH` (under `make`,
  or any CI step without activation) lacks `.venv/bin` - while `probe()` had
  reported bandit installed via importlib metadata. Preferring the
  interpreter's directory makes probe and run agree in every environment;
  absolute paths (`WADJET_PYTHON`) are left untouched.
- **T2.7 - pip-audit's `-r` mode is impossible on this host, so the e2e
  exercises the active-environment mode instead.** `-r` builds an internal
  virtualenv (`venv.EnvBuilder(with_pip=True)`), and Debian's python3.12 has
  no `ensurepip` (it ships in `python3-venv`, which needs sudo - forbidden).
  The script bootstraps a dedicated, cached environment
  (`~/.cache/wadjet/e2e-audit-venv`: `venv --without-pip` + `pip --python`
  installs) with pip-audit 2.10.1 plus the sample's pinned requirements, sets
  `WADJET_PYTHON` to it and leaves `dependency_files` empty - the agent's
  documented "audit the active environment" path. Warm runs take ~14s.
- **T2.7 - The sample pin moved from `requests==2.19.0` to `2.31.0`.**
  2.19.0 cannot run under Python 3.12 (its urllib3 1.23 pin dies on
  `six.moves`) and contradicts pip-audit's own `requests>=2.31.0` requirement,
  which broke importing pip-audit itself in the audit environment. 2.31.0 is
  still vulnerable (CVE-2024-35195, fixed in 2.32.0) and satisfies pip-audit.
- **T2.7 - Dependency expectations match package + installed version + fix
  version, never advisory ids.** The server stores only `vuln_id` (the upload's
  `aliases` are dropped at ingest), and PyPI's advisory ids churn: the same
  CVEs that carried 2018-era PYSEC ids in the recorded fixture come back as
  `PYSEC-2026-...` today. Fix versions (`2.32.0`) are stable per CVE, so
  `expected_findings.json` asserts those.
- **T2.7 - The committed sample is ruff-excluded** (`tests/sample_projects` in
  `extend-exclude`): linting or formatting the sample would silently "fix"
  the vulnerabilities the acceptance checks depend on. The e2e always mutates
  a temp copy, so the committed sample never changes - verified by two
  consecutive green runs.
- **T3.1 - Coverage is a metrics producer, not a scanner.** The agent parses
  the report named by `scanners.coverage.report_path` (relative to the repo
  root) in `wadjet_agent/coverage_report.py` and emits metrics only: no
  `scanner_runs` entry, so a missing or broken report can never make the
  analysis incomplete or change the exit code - agent-side it warns, and the
  verdict belongs to the gate. `doctor` shows the report's status
  informationally (it never flips the exit code, because the report comes from
  the *project's* test step), and `--dry-run` prints the configured path.
- **T3.1 - Gate rule: a coverage condition with no report triggers with
  `reason: "no coverage report"`** (section 6 coverage row). "No data must not
  read as green": the built-in default gate therefore fails any analysis that
  uploads no coverage metric, visibly and with the reason spelled out. Every
  other unproduced metric keeps the T2.4 behaviour (null, not triggered) -
  only `coverage_line_percent` is a documented promise the gate can demand.
  This changed `test_first_upload_creates_analysis_and_issues`, which now
  supplies a clean report (100%) the way a real test step would.
- **T3.1 - Parsing needs no coverage.py installation.** `coverage.json` is
  read from `totals.percent_covered` plus per-file `summary.percent_covered`;
  Cobertura XML uses the exact `lines-covered`/`lines-valid` counts on the
  root (the `line-rate` attribute is rounded to 4 decimals) and aggregates
  per-file percentages from each `<class>` element's `<line hits=...>`
  entries, because coverage.py splits one file into several classes.
  Key scheme: `coverage_line_percent` (the section 9 gate metric) and
  `coverage_file_percent:<path>` per file - display/export data the gate
  builder never offers.
- **T3.1 - The e2e covers both sides of the rule:** the sample project ships
  no report on purpose, so every sample analysis must carry the
  `reason: "no coverage report"` condition, while the clean project (exit-0
  scenario) writes a `coverage.json` at 100% and the stored analysis must
  contain the overall and per-file metrics.
- **T3.2 - Ruff severity/classification:** the defect families (`F`, `B`,
  `PLE`, plus the `E9` syntax errors) map to `bug` at medium; every other
  family maps to `code_smell` at low - nothing from Ruff ever exceeds
  medium (section 6). The family is the leading non-digit letters of the
  code (`PLE1307` -> `PLE`), so unknown/future families fall safely into
  the smell bucket. This is what the `bugs`/`code_smells` gate metrics
  count.
- **T3.2 - Rule explanations are fetched in `run()`, not `normalize()`**:
  one `ruff rule <CODE> --output-format json` per unique code (not per
  finding), stored in `RawOutput.data["explanations"]` and attached as
  `raw.explanation`. This keeps `normalize()` pure, so the contract fixture
  stays a recording of the real tool; a failed fetch never fails the run -
  the server then describes the finding with the scanner's message
  (`_ruff_enrichment` already falls back). The fetches count toward the
  duration stored in `scanner_runs`.
- **T3.2 - `S` is filtered out even when configured** (Bandit owns security;
  enabling both would double-report), and an empty/`S`-only selection falls
  back to the section 6 defaults rather than running Ruff with nothing
  selected. `scanners.ruff.families` accepts a list or a comma string;
  T3.4 formalises the settings schema.
- **T3.2 - `_relative` moved to `adapters/base.py` as `relative_path`**,
  shared by the Bandit and Ruff adapters: server-side fingerprints are
  computed from `file_path`, so two adapters must never disagree about
  what a path means.
- **T3.2 - Fixture:** `fixtures/ruff/0.16.10/` holds the check output
  (8 diagnostics over 5 codes) plus the five `ruff rule` payloads; the
  committed `sample/messy.py` deliberately triggers all four default
  families (F401/F841, B006, C901, PLE1307). Absolute filenames were
  rewritten to relative (`messy.py`) after recording so the fixture is
  machine-independent; the README documents the exact commands. Ruff's
  issue title carries the code (`F401: ...`) because, unlike Bandit, the
  KB does not replace it.
- **T3.2 - The e2e keeps Ruff disabled** (settings): the frozen
  `expected_findings.json` covers Bandit and pip-audit only, and Ruff's
  rule set drifts between releases - the adapter's contract tests cover
  it. The baseline severity loop now iterates the expected entries
  instead of the stored issues, so extra tools can never break it.
- **T3.3 - The keep list is enforced on both sides.** The agent's
  detect-secrets normalize emits exactly file, line, type and hash:
  `rule_id` = detector type, `raw = {"hashed_secret"}` and an empty
  `snippet` (the source line IS the secret - it never leaves the machine).
  The server's `_reject_secret_leaks` answers with 422 for a secret
  finding carrying a snippet, vulnerability/dependency fields, or raw keys
  beyond `hashed_secret`, before any database work, and the error detail
  names the offending *fields* - echoing a value back would leak it into
  response logs. Known limit: a rogue agent could hide a value in
  `title`/`message`, which the server cannot judge; the schema and this
  rule cover everything structural.
- **T3.3 - Masking is by line location, not by value.** detect-secrets'
  JSON carries no plaintext at all (only `hashed_secret`), so the agent
  cannot know *what* to mask - but it knows *where*. Scan flow step 6
  (`scan.mask_secret_lines`, run after all adapters, before exclusions)
  replaces every line of any other finding's snippet - flagged or context
  - that coincides with a detected secret line with `<secret redacted>`,
  and force-clears a secret finding's own snippet as belt and braces. The
  snippet geometry mirrors `build_snippet` (`min(3, line_start - 1)`
  lines above), so line numbers agree exactly; masking happens before the
  upload, so fingerprints are computed on the masked text and stay stable
  across runs.
- **T3.3 - Enrichment dispatches on the category, not the tool name.**
  `enrich_finding` picks `_secret_enrichment` for `category == secret`
  whatever tool reported it: the detector type stays the title (the
  fallback's generic "Scanner finding" would hide it), the agent's message
  becomes the description, impact/fix explain rotate-and-purge, CWE-798.
- **T3.3 - Same-type secrets in one file collapse to one issue.** With
  `snippet=""` the fingerprint (tool, rule, file, flagged, context -
  deliberately line-blind, one fingerprint module) is identical for two
  `Secret Keyword` hits in the same file, so ingest dedupes them. Accepted
  cost of never storing the line; removing one of two keys therefore does
  not resolve the issue until both are gone.
- **T3.3 - e2e keeps detect-secrets disabled** (settings): it wants a git
  checkout, and the frozen `expected_findings.json` covers Bandit and
  pip-audit only - the contract tests and a live smoke run cover the
  adapter. Outside a checkout `detect-secrets scan .` finds nothing on its
  own (its own behavior); the agent passes `include_paths` through
  positionally, and the scan flow already assumes a git repo for
  `git_commit`.
- **T3.3 - Fixture:** `fixtures/detect-secrets/1.5.0/` recorded with
  positional file arguments so it works outside git and the `results`
  keys come back relative with no rewriting; `sample/` holds planted fake
  secrets (keyword, URL credential, PEM block -> `Secret Keyword`,
  `Basic Auth Credentials`, `Private Key`). `run()` treats a stderr
  "fatal: not a git repository" as noise: exit 0 plus parseable JSON is
  success.
- **T3.4 - One validated settings schema, additive to the frozen contract.**
  `wadjet_schema.ProjectSettings` (new module `settings.py`) is the
  write-side validator for `projects.settings`; `AgentConfig.settings`
  stays a plain dict because T0.4 froze the agent contract - the server
  validates on write, the agent keeps reading known keys leniently (one
  validator, no drift). Per T0.4's rule this note records the additive
  contract change: `ProjectSettings`, `ScannerSettings`, `ScopeSettings`,
  `ScannersSettings`, `SCANNER_NAMES` and `DEFAULT_TIMEOUT_SECONDS` are
  now exported from `wadjet_schema`.
- **T3.4 - Structured options only, enforced by `extra="forbid"` at every
  level.** Section 10's named options are the whole vocabulary:
  bandit `skipped_test_ids` / `minimum_confidence` (Literal low|medium|
  high), pip-audit `dependency_files` / `dependency_default_severity`
  (Severity names), ruff `families` (uppercase codes; `S` rejected - it
  duplicates Bandit), coverage `report_path`, plus `enabled` and a
  positive per-scanner `timeout` on every scanner. A smuggled `args` /
  `extra_args` key or an unknown scanner fails validation with 422 and
  never reaches the database. Scope: `include` (at least one non-empty
  path, default `.`) and `exclude` (default = `DEFAULT_EXCLUSION_GLOBS`,
  exactly the guide's editable UI list). Global: `fail_on_scanner_error`
  (default true per section 6) and `timeout_seconds` (default 300, must be
  positive). Gate choice, general fields, tokens and members are not
  settings - they live on the project row and their own tables.
- **T3.4 - Settings endpoints: `GET/PUT /api/v1/projects/{id}/settings`.**
  GET needs `project.browse`, PUT needs `project.admin`; the PUT body is a
  complete `ProjectSettings` (pydantic fills defaults for omitted fields),
  so stored JSON is valid by construction, and a null or historically
  invalid row degrades to defaults on read instead of 500ing. Each change
  is audited as `project.settings_update` with the leaf-level key paths
  that changed (`scanners.ruff.families`, ...) - key paths, not values.
  The choice of PUT (whole-object replace) over merge-PATCH keeps
  validation of the *final* state trivial, which is the point of a
  server-side, validated schema.
- **T3.4 - Per-scanner timeouts resolve through `RunContext.timeout_for`**
  (the scanner's own positive override, else the run's global
  `timeout_seconds`), and `run_one_adapter` runs each adapter under a
  context carrying that timeout. Booleans and non-positive values fall
  back rather than surprising a scanner with a 0-second budget.
- **T3.4 - No new exclusion logic.** The schema's `scope.exclude` feeds
  the existing `effective_exclusion_globs` (asserted through the API
  round-trip), which already drives both the agent's config endpoint and
  the ingest drop with `excluded_count` (T2.4/T2.6) - one matcher in
  `wadjet_schema.exclusions`, applied twice as the guide requires.
- **T3.5 - `fail_on_scanner_error` is the switch inside the synthetic
  condition, not a second gate path.** `evaluate_gate` gained a
  `fail_on_scanner_error` parameter (default true): an incomplete analysis
  always gets the `all_scanners_completed` row first in `gate_details`, but
  the row's `triggered` flag *is* the setting, and gate status is now
  "passed iff nothing triggered". With the default this reproduces section
  9 exactly (incomplete => synthetic triggered => failed); a project that
  sets `fail_on_scanner_error: false` keeps the row and the `incomplete`
  status while the gate may pass. Reading the flag is
  `gate.scanner_errors_fail_gate(settings)`: only an explicit boolean
  `false` opts out, anything else (junk, missing) fails closed - same
  lenient-reader style as `effective_exclusion_globs`.
- **T3.5 - The opt-out changes nothing else.** An incomplete analysis
  still never resolves issues (lifecycle, section 5.4), the agent still
  exits 3 before it looks at the gate (guide exit codes), and
  `derive_analysis_status` still marks `complete` only when every reported
  run is `ok`. "Missing scanner" stays the agent's job to record (a probe
  or run failure writes `status=error`); the server cannot know which
  enabled scanners an old agent has never heard of, and second-guessing
  `scanner_runs` would break the one-contract rule between agent and
  server.
- **T4.0 - `seed-demo` is one idempotent transaction keyed on the
  `demo-admin` user.** All rows are inserted between `engine.begin()` and
  commit: a failed seed leaves nothing behind, and a second run prints
  "already present - skipped" (exit 0) instead of duplicating. The demo
  identity is unambiguous by construction - `demo-*` usernames, the fixed
  project keys `payments` / `web-portal` / `data-pipeline`, one group name
  - so nothing outside the dataset can be touched and a manual reset is
  "delete those keys". There is deliberately no `--force` yet; the seed is
  cheap to re-run after a wipe. All five accounts share one password
  (`demo-password`), hashed once and reused (same password, same verify),
  and the command prints the login line - demo tooling, not production
  provisioning.
- **T4.0 - Historical gate results are produced by the real evaluator,
  not by hand.** `evaluate_gate` gained an `issue_metrics` override so the
  seed can hand each analysis its own point-in-time counts; everything
  else (condition loading, the synthetic `all_scanners_completed` row,
  status derivation) stays the one gate evaluator from section 9 - the
  seed contains no gate logic of its own. The trade-off: older analyses'
  metrics are the seed author's story (passed -> failed on coverage ->
  failed on everything for payments; found-and-fixed for web-portal;
  incomplete for data-pipeline), while the *latest* analysis of every
  project must equal what `compute_issue_metrics` returns today - the
  test recomputes it through `evaluate_gate` and diffs status, conditions
  and metrics. Gate name is `Release gate` because gate names are unique
  and existing tests already claim "Strict".
- **T4.0 - Seed introduces the `triaged` timeline event.** The app only
  produced `created` / `resolved_by_scan` / `reopened_by_scan` so far; the
  seed adds `triaged` with payload `{status, reason?}` because an issue
  that shows a triage in its row but nothing in its timeline lies.
  **T4.4's triage action must append this same type** (or the seed gets
  updated in the same commit). Assignment events are *not* invented yet -
  T4.4 defines assignment first. Notifications have no table until T5.2,
  which extends the seed. Seeded secret findings carry an empty snippet
  like every other ingest path (the T3.3 rule).
- **T4.1 - The design's own CSS is the stylesheet; no Tailwind.** The
  guide's stack line mentions Tailwind, but `wadjet-design.html` ships a
  complete component vocabulary (`.win`, `.t`, `.b`, `.k`, `.sv`, `.c`,
  tokens on `:root`) and the instruction for phase 4 is "match
  wadjet-design.html". `static/css/wadjet.css` is that CSS verbatim plus
  an "app shell" section (top bar, skip link, auth card): no build step,
  no toolchain, and what ships is what was designed. HTMX arrives with
  T4.3 (filters), vendored then.
- **T4.1 - Brand assets are generated from the `#lg`/`#wm` symbols.**
  Three files produced mechanically from the design's sprite:
  `static/brand/mark.svg` (the eye, light-theme hex literals),
  `static/brand/wadjet.svg` (mark + wordmark, `viewBox="16 26 963 259"`),
  `static/favicon.svg`. The app chrome inlines the original sprite
  (`templates/sprite.html`) so the paths keep their `var(--...)` fills and
  the navy lightens on dark exactly as the design says; standalone files
  cannot resolve CSS variables, hence literal hex there.
- **T4.1 - One login endpoint, two dialects.** `POST /session` remains
  the only credential check (same rate limiter, same audit, same argon2
  verify); a browser form post (`Accept: text/html`) gets a 303 to the
  local `next` path, or the login page re-rendered with the error, while
  API clients keep 201/401/429 JSON untouched. `next` travels in the form
  action's query string (readable synchronously in the sync handler) and
  is filtered by `safe_next` - local paths only, no open redirect.
  Likewise `POST /session/logout` redirects HTML clients to `/login`.
- **T4.1 - CSRF doubles up for forms: header OR hidden field.** The
  double-submit contract is unchanged; `CsrfMiddleware` now also accepts
  the token from a `csrf_token` form field, because HTML forms cannot set
  headers. Two details that matter: the body is read with `request.body()`
  *before* `request.form()` so Starlette's `_CachedRequest` replays the
  cached body downstream (otherwise the login route sees an empty form and
  answers 422), and the token is published to templates through
  `request.state.csrf_token`, which the middleware shares via the ASGI
  scope - the cookie exists before the first render, so the very first
  login page already carries a valid hidden field.
- **T4.1 - Page auth redirects, API auth 401s.** `get_current_user`
  stays as it is; pages depend on `require_page_user`, which raises
  `NotAuthenticated(next_url)` to a registered handler that answers 303
  `/login?next=...`. The nav is permission-aware in the template
  (`Admin` only for `is_admin`), autoescaping is on everywhere (the test
  logs in with a `<script>` display name and asserts the escaped form),
  and the theme is system-first with an explicit `data-theme` choice in
  localStorage (two inline scripts, no FOUC, no server state). The top
  bar renders all four design links now; `/inbox` and `/admin` fill in
  with T4.7/T5.2, and `/` is a brand-hero stub until T4.2's list.

## 2026-10-07

- **T4.2 - `/` and `/projects` render one list, and the hero is gone.**
  Section 14 makes `/` the projects list; the brand hero now lives only on
  the login page, and `templates/home.html` was deleted rather than left as
  a second, rotting answer to the same question. Both addresses share
  `_render_list`, so the nav link and the root can never drift.
- **T4.2 - Every number on the list and the overview is the *latest
  analysis* snapshot - except the flagged count, which is live.** The gate
  judged `analyses.metrics`, and the design's columns (blocker/critical/
  high, coverage) are exactly what that snapshot says; recomputing them
  from `issues` would show today's counts next to yesterday's verdict. The
  one live number is "Flagged false positive": triage is not part of the
  gate metrics at all, so a snapshot could not contain it. The trend bars
  likewise read each analysis's own `issues_total`.
- **T4.2 - Project creation is a global-admin action, on the page too.**
  Section 7 lists the whole permission set and `project.create` is not in
  it, so both `POST /api/v1/projects` and the form at `/projects/new` answer
  403 for everyone else ("Ask an admin to create the project, then add
  yourself as a member"). The form and the endpoint call the *same*
  `create_project()` in `app/projects.py`: one key validator, one duplicate
  rule, one audit row, one grant template. A bad or duplicate key
  re-renders the form with 400 and the typed values (an HTML client wants
  its input back, not a 422 document); the JSON endpoint keeps 422/409.
- **T4.2 - `/projects/{key}` answers 404 for "no such key" *and* for "no
  grant", with one message.** Telling a stranger "exists, but forbidden"
  would leak which projects a company runs; both cases render
  `error.html`, and the key is echoed through Jinja autoescaping (the test
  requests `/projects/<script>alert(1)` and asserts the escaped form).
- **T4.2 - One query decides visibility: `visible_projects()` in
  `app/projects.py`.** The page and the JSON API both need "projects this
  session may browse", so the `LEFT JOIN LATERAL` latest-analysis query and
  the `project.browse`-through-user-or-group predicate live in the service
  module and are imported by both (section 12's `GET /api/v1/projects` was
  missing entirely; it now exists and returns `analysis: null` until a
  project's first upload).
- **T4.2 - Relative times come from one `timeago` Jinja filter**
  (`2 hours ago`, `yesterday`, per the design's copy): naive timestamps are
  read as UTC, anything unparseable is passed through as-is so a malformed
  row degrades to readable text instead of a 500, and `None` reads
  `never`. The trend chart carries an `aria-label` with the exact
  per-analysis counts, because height alone is not an accessible channel.
- **T4.2 - The seed's audit rows are marked with `DEMO_AUDIT_IP`
  (192.0.2.10, RFC 5737).** `test_seed` counted every audit row by a
  `demo-%` actor, and T4.2's page tests sign in as `demo-dave` - each login
  writes a real audit row from the session address, which took the count
  from 6 to 10. Filtering on the seed's own marker keeps the assertion
  about *seeded* data honest without forbidding tests from using the demo
  accounts.
- **T4.3 - One issues route answers three ways, chosen by the `HX-Target`
  header htmx already sends** (section 14 + 12): no header = the whole page,
  `issues-body` = sidebar + mirrors + table (a facet click or a filter clear),
  `issues-table` = table + pager only (typing in the search box, which is what
  keeps the caret in the field - the input lives outside that fragment). One
  URL, so the address bar only ever shows the canonical `?status=...&text=...`
  filter URL, and a no-JS browser gets the same filters via a plain GET form.
- **T4.3 - Facet links carry every filter but never `text` or `sort`.** Those
  two travel with the form (`hx-include` points at the search box and the sort
  menu only), so a link rendered before you finished typing cannot drag a
  stale search back behind your back - and so each parameter arrives exactly
  once, no matter which of the two sources states it. The one degradation is
  deliberate and documented: without JavaScript a facet click drops the typed
  search. `IssueFilters.params()` is the single URL builder for facets,
  pager, "Clear filters" and "page 1", so no link can forget a filter; it
  omits defaults (page 1, default sort) to keep URLs short, and the parser
  reads the *first* occurrence of a repeated key, which is always the URL's
  own value.
- **T4.3 - "Clear filters" sits outside the facet `hx-include` on purpose.**
  It must be able to drop the text in the search box; if the form were
  included, the just-cleared search would be re-sent with the link.
- **T4.3 - Facet counts ignore the active filters.** A count labels the set
  you would get by clicking that link, so a number that shrank while you
  filtered would be a lie about it. A value with no issues is hidden unless
  it is the active filter, which still has to say so (word + `aria-current`).
- **T4.3 - `GET /api/v1/projects/{key}/issues` (section 12 gap) parses and
  sorts with the same `app.issues` code as the page**, so an API call and a
  dashboard link with the same parameters always agree: unknown enum values
  answer 422 naming what was expected (never silently "all issues"),
  `per_page` is capped at 200 rather than refused, and a page past the end is
  an empty list with a truthful `total`. Visibility goes through
  `visible_project()`, T4.2's rule widened to one project: unknown key and
  "no grant" are the same 404 for the page and the API.
- **T4.3 - An empty *page* is not an empty *project*.** `page=99` says "That
  page is past the end" with a link back; only a project with zero issues
  gets the "No issues yet / run `wadjet scan`" copy. A page that answered
  "nothing here" to a stale bookmark would be telling the user their project
  was clean.
- **T4.3 - htmx 2.0.5 is vendored under `static/js/` and loaded once, with
  `defer`, from `base.html`** (2.1.0 does not exist on unpkg). The issues
  title is plain text until T4.4 adds `/projects/{key}/issues/{id}`: the
  design shows no link there, and a link to a page that does not exist yet
  would be a dead end. The sort menu is the one addition to the design's
  toolbar - section 12 requires `sort`, and a list you cannot re-order hides
  its worst rows below the fold.
- **T4.3 - Test fixtures now dispose their engines.** `create_app` builds one
  pooled engine per application (5 + 10 connections), and `conftest` kept
  every one of them alive for the life of the session; T4.3's 17 tests pushed
  the suite past PostgreSQL's `max_connections = 100` and six unrelated tests
  failed with "too many clients already". The `app` and `live_server`
  fixtures now dispose on teardown - the leak was pre-existing, the new file
  just found its edge.
- **T4.3 - The overview is the hub of its project pages.** The design mocks
  pages as isolated windows and has no cross-page links, so section 14's
  "every page is reachable" needs a nav of our own: a `.tabs` row (the same
  pattern the design uses inside project settings) after the gate banner,
  "Overview" active. The banner keeps the top of the page - failing
  conditions first, as the design copy demands. Track A extends this row
  with its own links (analyses, settings); Track B (issues) landed it before
  the split so the tracks never both edit this template.
- **Parallel build - two tracks in two worktrees.** Work is split by feature
  vertical (guide 17.4): Track A (worktree `wadjet-trackA`, branch `track-a`)
  takes T4.5-T4.9, T5.4, T5.5, T6.2, T6.3 - pages over existing data,
  admin, exports, release workflows; Track B (this worktree) takes T4.4,
  T5.1-T5.3, T6.1, T6.4 - the issue-workflow chain, which is too
  interdependent to split (detail -> requests -> notifications -> inbox ->
  mentions). Each track gets its own database (`wadjet`, `wadjet_a`) so
  Alembic heads and seed data never collide; only Track B creates
  migrations. Shared files (`main.py`, `TASKS.md`, `decisions.md`,
  `wadjet.css`) are append-only per track and merged by Track B.
  Details: `~/projects/wadjet-files/track-a-brief.md`.
- **T4.5 - Settings is one shell, six tabs, and one gate to get in.** The
  tabs share `settings_shell.html` so the design's sub-navigation (`.tabs`,
  active `aria-current`) is written once; every tab sits behind
  `project.admin` and a refusal names that permission, while the overview's
  "Settings" link renders only for holders (`is_project_admin` context var) -
  hidden, not just refused, per section 14. Deletion stays **global-admin
  only** plus a typed `?confirm=<key>`: section 7 never lists delete under
  project.admin, and creation is admin-only, so the pair is symmetric.
  `PATCH /api/v1/projects/{key}` accepts `key` only to answer that the key is
  immutable, and a project the caller cannot see is 404 everywhere - section
  7's "no existence leak" applies to settings reads as much as issues.
- **T4.5 - One save path, one cascade list.** The pages and the pre-existing
  `PUT .../settings` now both write through `save_settings()`, so the audit
  row (`project.settings_update` with changed keys, never values) and the
  Pydantic validation cannot drift between the two front doors; the general
  tab adds `project.update`, the gate picker `project.gate_update`, members
  `permission.grant`/`permission.revoke`, tokens reuse `token.create`/
  `token.revoke`. No FK cascades, so `delete_project()` walks the explicit
  `PROJECT_CASCADE` (comments -> requests -> events -> issues -> analyses ->
  grants -> tokens -> project): **any new table that references a project
  must be added there or deletion stops short.** A gate choice of `null`
  means section 9's built-in default - reported as null by the API and shown
  as the checked radio by the picker - and a created token is printed once
  in the render, never re-readable.

**T4.6 -** Gate pages read like the API list (session-scoped, no special
  privilege) but every write - create, save, delete - requires global
  `gates.admin` and renders a 403 page naming it; the CRUD itself moved into
  public `add_gate()`/`edit_gate()`/`remove_gate()` services in
  `app/api/gates.py` so pages and endpoints share one write path, one audit
  (`gate.create`/`gate.update`/`gate.delete`) and one rule set (builtin and
  in-use gates refuse deletion). Unknown or non-digit gate ids 404 before any
  permission check, and the detail page offers no rename - names change only
  via `PATCH /api/v1/gates/{id}`, matching the design's edit rows.
