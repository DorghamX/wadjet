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
