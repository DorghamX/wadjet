# Wadjet tasks

Source: `wadjet-build-guide.md` section 17.3. One checkbox per task. A task is done when its
code, tests and one docs line exist, `make lint test` is green and the commit message is
`T<id>: <summary>`.

## Phase 0: Foundations
- [ ] **T0.1 (S)** Repository skeleton, pyprojects, Makefile, ruff, mypy, pytest, CI with PostgreSQL service
- [x] **T0.2 (M)** Config, engine, wait-for-database, advisory-lock migrations, check-db, healthcheck, /healthz, Alembic, password redaction
- [x] **T0.3 (S)** Dockerfile.server, Dockerfile.agent, docker-compose.yml, .env.example + compose test
- [x] **T0.4 (S)** Freeze `wadjet_schema` contract + OpenAPI skeleton

## Phase 1: Identity and access
- [x] **T1.1 (M)** Users, sessions, login/logout, argon2id, CSRF, rate limit, create-admin
- [x] **T1.2 (M)** Groups, projects, grants, permission templates, `can()`
- [x] **T1.3 (S)** Project tokens and token auth dependency
- [x] **T1.4 (M)** Audit log writer + exhaustive permission matrix test

## Phase 2: Analysis pipeline (the core)
- [x] **T2.1 (S)** Models and migrations for analyses, issues, events, comments, requests
- [x] **T2.2 (L)** Fingerprint, matching and lifecycle as pure functions + unit tests
- [x] **T2.3 (M)** Knowledge base loader, full Bandit KB + completeness test, pip-audit enrichment
- [x] **T2.4 (M)** `POST /api/v1/analyses` one-transaction ingest
- [x] **T2.5 (M)** Gate engine, built-in default gate, stored results
- [x] **T2.6 (L)** Agent: CLI, config fetch, Bandit and pip-audit adapters, upload, exit codes, doctor, --dry-run
- [x] **T2.7 (S)** Sample vulnerable project and end-to-end script

## Phase 3: Remaining scanners and settings
- [x] **T3.1 (S)** Coverage report ingestion and coverage metric
- [x] **T3.2 (M)** Ruff adapter
- [x] **T3.3 (M)** detect-secrets adapter with secret masking and server rejection rule
- [x] **T3.4 (M)** Settings schema, scanner options, exclusions (agent and server)
- [x] **T3.5 (S)** Scanner failure policy: incomplete analysis and synthetic gate condition

## Phase 4: Web UI
- [x] **T4.0 (S)** seed-demo
- [x] **T4.1 (M)** Base layout, theme tokens, light/dark, brand assets, login
- [x] **T4.2 (M)** Projects list and overview
- [x] **T4.3 (M)** Issues list with HTMX filters
- [x] **T4.4 (L)** Issue detail: triage, assignment, comments, timeline
- [x] **T4.5 (M)** Project settings pages
- [x] **T4.6 (M)** Gates pages
- [x] **T4.7 (M)** Admin users, groups, permission matrix page
- [x] **T4.8 (S)** Analyses history
- [x] **T4.9 (S)** Profile and password page ``/me`` (section 14 route; no id in 17.3) — JSON endpoints exist, the page itself is still missing

## Phase 5: Collaboration
- [x] **T5.1 (M)** Request-action workflow
- [x] **T5.2 (M)** Notifications and inbox
- [x] **T5.3 (S)** `@mentions`
- [x] **T5.4 (S)** Audit log page
- [x] **T5.5 (M)** CSV and SARIF export, quality gate badge

## Phase 6: Release
- [x] **T6.1 (M)** Docs: README quickstart, operations, writing-an-adapter, supported tools
- [x] **T6.2 (S)** `scanner-compat.yml` weekly workflow
- [x] **T6.3 (S)** Image build and push workflow
- [ ] **T6.4 (S)** Walk through section 18
