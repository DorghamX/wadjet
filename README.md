# Wadjet

> **A security-first quality gate aggregator.** Runs maintained open-source scanners, normalizes their findings, stores them as triageable issues, evaluates a quality gate, and returns pass/fail. People triage issues in a web dashboard.

> **Wadjet is an aggregator, not an analysis engine.** It never writes detection rules. It uses maintained tools through thin adapters.

---

## Quickstart

### Prerequisites

A PostgreSQL 16+ database (local or remote). Wadjet does not ship a database container.

### Create the role and database (run once, as a PostgreSQL superuser)

```sql
CREATE ROLE wadjet LOGIN PASSWORD 'change-me';
CREATE DATABASE wadjet OWNER wadjet;
```

### Configure and run

```bash
cp deploy/.env.example deploy/.env
# edit deploy/.env: set DATABASE_URL, WADJET_SECRET_KEY, WADJET_BASE_URL, admin credentials
cd deploy
docker compose pull
docker compose up -d
docker compose logs -f wadjet
```

The server listens on `http://localhost:8080`. The health endpoint is `GET /healthz`.

```bash
curl -fsS http://localhost:8080/healthz
```

### Upgrade

Change the image tag in `deploy/docker-compose.yml`, then:

```bash
docker compose pull && docker compose up -d
```

Migrations run automatically on startup.

### Backup and restore

Documented in [docs/operations.md](docs/operations.md).

---

## First scan

```bash
# Install the agent with scanners
pip install "wadjet-agent[scanners]"

# In your repository (after dependencies are installed for pip-audit)
export WADJET_URL=http://your-wadjet:8080
export WADJET_TOKEN=your-project-token
wadjet scan
```

The agent reads `WADJET_URL` and `WADJET_TOKEN` (bound to one project), runs enabled scanners, uploads findings, and exits with:
- `0` gate passed
- `1` gate failed
- `2` config/auth/network error
- `3` analysis incomplete (scanner error)

### GitHub Actions example

```yaml
- run: pip install -r requirements.txt "wadjet-agent[scanners]"
- run: pytest --cov --cov-report=xml   # coverage.py report for the gate
- run: wadjet scan
  env:
    WADJET_URL: ${{ vars.WADJET_URL }}
    WADJET_TOKEN: ${{ secrets.WADJET_TOKEN }}
```

Also documented: [Jenkins](docs/operations.md#jenkins) and [GitLab CI](docs/operations.md#gitlab-ci) stages.

---

## Architecture at a glance

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your CI / Developer                        │
└───────────────────────────────┬─────────────────────────────────┘
                                │ wadjet scan (agent)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  wadjet-agent (Python package, runs in your CI)                  │
│  ├── Bandit          │  ├── pip-audit      │  ├── Ruff          │
│  ├── detect-secrets  │  └── coverage.py    │                    │
│  └── uploads normalized findings (gzip JSON, ≤20 MB)            │
└───────────────────────────────┬─────────────────────────────────┘
                                │ POST /api/v1/analyses (project token)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  wadjet-server (FastAPI, single binary)                          │
│  ├── Ingest (one transaction)                                    │
│  │   ├── Fingerprint matching (exact → context → moved file)    │
│  │   ├── Flag carry-over (non-open triage_status survives)      │
│  │   └── Lifecycle (presence=resolved when unseen, etc.)        │
│  ├── Quality gate (stored SQL conditions, per-project)          │
│  ├── Web UI (issues, triage, inbox, requests, audit, exports)   │
│  └── PostgreSQL (source of truth, no branches, no secrets)      │
└─────────────────────────────────────────────────────────────────┘
```

---

## What Wadjet is (and is not)

| ✅ Wadjet is... | ❌ Wadjet is not... |
|-----------------|---------------------|
| An aggregator for maintained scanners | A new detection engine (no custom rules) |
| A triage dashboard with flag memory | A SAST tool that writes its own queries |
| A quality gate that fails the build | A replacement for SonarQube's rule engine |
| Secure by default (no secrets stored) | A secret scanner that uploads secret values |
| Git-branch-agnostic (latest analysis wins) | A branch-aware PR decorator (planned) |

**Honest comparison**

| | Wadjet | SonarQube | DefectDojo |
|---|---|---|---|
| **Engine** | Aggregates Bandit, Ruff, pip-audit, detect-secrets, coverage | Own rule engine + plugins | Imports from other tools |
| **Triage** | Flag memory (survives line shifts, file moves) | Status + resolution | Status + custom fields |
| **Gate** | SQL conditions on normalized metrics | Quality profiles / gates | Policy engine |
| **Secrets** | Rejects findings with raw values | Detects, can upload values | Imports, stores values |
| **Deploy** | Single binary + Postgres, no DB container | Heavy (Java, ES, DB) | Python + DB |
| **License** | GPL-3.0 | LGPL / Commercial | BSD-3-Clause |

---

## Supported tools (tested version ranges)

| Adapter | Distribution | Supported range | Notes |
|---------|--------------|-----------------|-------|
| `bandit` | `bandit` | `>=1.7.8,<2` | Fixture `fixtures/bandit/1.9.4/` |
| `pip_audit` | `pip-audit` | `>=2.7,<3` | Fixture `fixtures/pip-audit/2.10.1/` |
| `ruff` | `ruff` | `>=0.6,<1` | Fixture `fixtures/ruff/0.16.10/` |
| `detect_secrets` | `detect-secrets` | `>=1.4,<2` | Fixture `fixtures/detect-secrets/1.5.0/` |
| `coverage` | `coverage` | `>=7.4,<8` | Reads `coverage.json` / `coverage.xml` from project's test step |

Install with `pip install "wadjet-agent[scanners]"` (pins the same ranges). `wadjet doctor` reports installed versions and flags anything outside its range; each `scanner_runs` entry records the exact version an analysis ran with.

Contract tests parse recorded fixtures under `fixtures/<tool>/<version>/`, so a newer scanner release cannot silently change normalization: re-record the fixture under the new version directory and keep both passing.

---

## Security

Wadjet is a security tool and must be secure:

- **Passwords**: argon2id (never plaintext, never logged)
- **Sessions**: HttpOnly, Secure (HTTPS), SameSite=Lax cookies; CSRF token on every state-changing form and HTMX request
- **Project tokens**: 32 random bytes, shown once, stored as SHA-256 hash with visible prefix; constant-time comparison; scoped to one project's agent endpoints
- **Uploaded content treated as hostile**: autoescape everywhere, Markdown sanitized with nh3, strict CSP, no inline scripts
- **Payload validation**: Pydantic on every endpoint; size limits on uploads and fields
- **Authorization in service layer**: not only in routes
- **Never store secret values**: server rejects `secret` category findings that include anything but file, line, type, and hash
- **Audit log**: logins, token creation/revocation, permission changes, flags, settings changes, gate changes
- **Configuration via env vars only**: no secrets in repo; `.env.example` with placeholders

---

## Documentation

- [Operations guide](docs/operations.md) — database setup, backup/restore, upgrades, CI integrations
- [Writing an adapter](docs/writing-an-adapter.md) — the `Adapter` protocol, `RunContext`, contract tests, KB enrichment
- [API reference](docs/api.md) — OpenAPI at `/api/docs`
- [Decisions log](docs/decisions.md) — design rationale per task

---

## License

GPL-3.0. See [LICENSE](LICENSE).