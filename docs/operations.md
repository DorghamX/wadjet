# Operations guide

## Database

### Setup (run once)

```sql
CREATE ROLE wadjet LOGIN PASSWORD 'strong-password';
CREATE DATABASE wadjet OWNER wadjet;
```

Grant only what Wadjet needs:
```sql
GRANT CREATE ON DATABASE wadjet TO wadjet;   -- for test schema creation
-- If you run tests against this DB:
ALTER ROLE wadjet CREATEDB;  -- only for test suite
```

### Schema and migrations

On every startup (`wadjet-server serve`), if `WADJET_AUTO_MIGRATE=true` (default), the server:
1. Waits for the database (up to `WADJET_DB_WAIT_SECONDS`)
2. Takes an advisory lock (`pg_advisory_xact_lock`) so concurrent replicas don't race
3. Runs `alembic upgrade head` — all migrations are transactional DDL

No manual migration step is needed. The lock ensures exactly one replica migrates.

### Backup

```bash
# Use the plain postgresql:// scheme for pg_dump
DATABASE_URL_PLAIN=$(echo "$DATABASE_URL" | sed 's/postgresql+psycopg:/postgresql:/')
pg_dump --format=custom --file=wadjet.dump "$DATABASE_URL_PLAIN"
```

### Restore

```bash
DATABASE_URL_PLAIN=$(echo "$DATABASE_URL" | sed 's/postgresql+psycopg:/postgresql:/')
pg_restore --clean --no-owner --dbname="$DATABASE_URL_PLAIN" wadjet.dump
```

### Upgrade

1. Change the image tag in `deploy/docker-compose.yml`
2. `docker compose pull && docker compose up -d`
3. Migrations run automatically under the advisory lock.

Rollback: `docker compose up -d` with the previous tag (downgrade migrations exist for every revision).

---

## Configuration

All settings are environment variables (or `_FILE` variants for Docker secrets). The server refuses to start if any required value is missing or invalid.

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | `postgresql+psycopg://user:pass@host:5432/db?sslmode=require` |
| `WADJET_SECRET_KEY` | yes | — | ≥32 chars, used for sessions and token hashing |
| `WADJET_BASE_URL` | yes | — | Public URL, e.g. `https://wadjet.example.com` |
| `WADJET_ADMIN_USER` | no | — | First-boot admin username (with `WADJET_ADMIN_PASSWORD`) |
| `WADJET_ADMIN_PASSWORD` | no | — | First-boot admin password (with `WADJET_ADMIN_USER`) |
| `WADJET_LOG_LEVEL` | no | `info` | `debug`, `info`, `warning`, `error`, `critical` |
| `WADJET_DB_POOL_SIZE` | no | `5` | SQLAlchemy pool size |
| `WADJET_DB_MAX_OVERFLOW` | no | `10` | Pool overflow |
| `WADJET_DB_POOL_TIMEOUT` | no | `30` | Pool checkout timeout (seconds) |
| `WADJET_DB_WAIT_SECONDS` | no | `60` | Startup wait for database |
| `WADJET_AUTO_MIGRATE` | no | `true` | Run migrations on startup |
| `WADJET_COOKIE_SECURE` | no | `true` | Secure cookies (set `false` for local HTTP) |

**First-boot admin**: If `WADJET_ADMIN_USER` and `WADJET_ADMIN_PASSWORD` are both set and no admin exists yet, `wadjet-server serve` creates that admin once. After any admin exists, the pair does nothing. **Remove them from `.env` after setup** — leaving them in is harmless but unnecessary.

### Docker secrets

Every variable also reads from a `_FILE` sibling (e.g., `WADJET_SECRET_KEY_FILE=/run/secrets/secret_key`). The file contents are trimmed and used as the value. Prefer files in production.

---

## CI integrations

### GitHub Actions

```yaml
- name: Install agent with scanners
  run: pip install -r requirements.txt "wadjet-agent[scanners]"
- name: Run tests with coverage
  run: pytest --cov --cov-report=xml
- name: Wadjet scan
  run: wadjet scan
  env:
    WADJET_URL: ${{ vars.WADJET_URL }}
    WADJET_TOKEN: ${{ secrets.WADJET_TOKEN }}
```

### GitLab CI

```yaml
wadjet_scan:
  image: python:3.12
  script:
    - pip install -r requirements.txt "wadjet-agent[scanners]"
    - pytest --cov --cov-report=xml
    - wadjet scan
  variables:
    WADJET_URL: $WADJET_URL
    WADJET_TOKEN: $WADJET_TOKEN
```

### Jenkins (declarative pipeline)

```groovy
stage('Wadjet Scan') {
  agent { docker { image 'python:3.12' } }
  steps {
    sh 'pip install -r requirements.txt "wadjet-agent[scanners]"'
    sh 'pytest --cov --cov-report=xml'
    withCredentials([string(credentialsId: 'wadjet-token', variable: 'WADJET_TOKEN')]) {
      sh '''
        export WADJET_URL=http://wadjet.example.com
        wadjet scan
      '''
    }
  }
}
```

---

## Agent behaviour

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Gate passed |
| 1 | Gate failed |
| 2 | Config / auth / network error |
| 3 | Analysis incomplete (scanner error) |

### `wadjet doctor`

```bash
wadjet doctor
```
Checks every configured scanner: installed version, supported range, and whether it runs. Exits non-zero if any enabled scanner is missing or outside its range.

### `wadjet scan --dry-run`

```bash
wadjet scan --dry-run
```
Prints the adapters that would run, their configured options, and the estimated payload size — without uploading.

### Dependency scanning note

`pip-audit` must run **after dependencies are installed** (it scans the active environment by default, or a requirements file with `-r`). Ensure your CI installs dependencies before `wadjet scan`.

---

## Health and monitoring

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | Liveness + DB connectivity (returns 200/503) |
| `GET /api/docs` | session | OpenAPI / Swagger UI |
| `GET /api/v1/analyses/{id}` | session/token | Gate details for a specific analysis |

The health check is also the Docker `HEALTHCHECK` command (`wadjet-server healthcheck`).

---

## Logs

Structured JSON logs (`log_level` from config). Secrets (database password, secret key, admin password, tokens) are automatically redacted before any log line is emitted. The redaction list includes every value the server considers secret.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Database unreachable after N seconds` | Wrong `DATABASE_URL`, DB down, network | Check URL, `pg_isready`, security groups |
| `Configuration error: WADJET_SECRET_KEY must be at least 32 characters` | Key too short | `openssl rand -hex 32` |
| `Admin user already exists` | Re-running first-boot | Remove `WADJET_ADMIN_USER` from `.env` |
| `wadjet scan` exits 2 | Missing `WADJET_URL` / `WADJET_TOKEN`, or network | Set env vars, check connectivity |
| `wadjet scan` exits 3 | Scanner crashed / timed out | Check agent logs, increase `timeout` in settings |
| Gate fails unexpectedly | Condition threshold too strict, or missing coverage | Adjust gate, add `coverage.json` to test step |