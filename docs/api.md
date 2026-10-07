# API reference

OpenAPI/Swagger UI: `GET /api/docs` (served by the server).

Base URL: `WADJET_BASE_URL` (e.g., `https://wadjet.example.com`).

Authentication:
- **Web UI**: session cookie (`wadjet_session`) + CSRF token on every mutating form/HTMX request
- **Agent endpoints**: Bearer project token (`Authorization: Bearer <token>`)

---

## Agent endpoints (project token)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/agent/config` | Settings, exclusions, gate id for this project |
| `POST` | `/api/v1/analyses` | Upload findings + metrics (gzip JSON, ≤20 MB); returns analysis id, gate result, dashboard URL |

---

## Project endpoints (session)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/projects` | List projects (visible to user) |
| `POST` | `/api/v1/projects` | Create project |
| `GET` | `/api/v1/projects/{key}` | Project detail + settings |
| `PATCH` | `/api/v1/projects/{key}` | Update project settings |
| `DELETE` | `/api/v1/projects/{key}` | Delete project |
| `GET` | `/api/v1/projects/{key}/issues` | Filtered, paginated issue list |
| `GET` | `/api/v1/projects/{key}/export` | `?format=csv\|sarif` — export issues |
| `GET` | `/api/v1/projects/{key}/tokens` | List project tokens |
| `POST` | `/api/v1/projects/{key}/tokens` | Create token |
| `DELETE` | `/api/v1/projects/{key}/tokens/{id}` | Revoke token |

---

## Issue endpoints (session)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/issues/{id}` | Issue detail |
| `PATCH` | `/api/v1/issues/{id}` | Triage (status + reason) |
| `POST` | `/api/v1/issues/{id}/assign` | Assign to user |
| `GET` | `/api/v1/issues/{id}/comments` | List comments |
| `POST` | `/api/v1/issues/{id}/comments` | Add comment |
| `POST` | `/api/v1/issues/{id}/comments/{comment_id}/edit` | Edit own comment |
| `POST` | `/api/v1/issues/{id}/comments/{comment_id}/delete` | Delete comment |
| `POST` | `/api/v1/issues/{id}/requests` | Create request |
| `POST` | `/api/v1/requests/{id}/resolve` | Approve / decline / cancel request |

---

## Gate endpoints (session)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/gates` | List gates |
| `POST` | `/api/v1/gates` | Create gate |
| `GET` | `/api/v1/gates/{id}` | Gate detail |
| `PATCH` | `/api/v1/gates/{id}` | Update gate |
| `DELETE` | `/api/v1/gates/{id}` | Delete gate |
| `POST` | `/api/v1/gates/{id}/conditions` | Add condition |
| `PATCH` | `/api/v1/gates/{id}/conditions/{cond_id}` | Update condition |
| `DELETE` | `/api/v1/gates/{id}/conditions/{cond_id}` | Delete condition |

---

## User/Group endpoints (session, admin only)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/users` | List users |
| `POST` | `/api/v1/users` | Create user |
| `PATCH` | `/api/v1/users/{id}` | Update user |
| `DELETE` | `/api/v1/users/{id}` | Delete user |
| `GET` | `/api/v1/groups` | List groups |
| `POST` | `/api/v1/groups` | Create group |
| `PATCH` | `/api/v1/groups/{id}` | Update group |
| `DELETE` | `/api/v1/groups/{id}` | Delete group |

---

## Inbox endpoints (session)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/notifications` | `{unread, items[]}` — newest first |
| `POST` | `/api/v1/notifications/read` | `{"ids": [int]?}` — mark read; omitted = all |

---

## Health

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/healthz` | none | Liveness + DB check (200/503) |

---

## Payload validation

Every endpoint validates input with Pydantic (extra=forbid). Size limits:
- `POST /api/v1/analyses`: 20 MB gzip
- `POST /api/v1/issues/{id}/comments`: body ≤ 10,000 chars
- `POST /api/v1/issues/{id}/requests`: message ≤ 2,000 chars
- `POST /api/v1/requests/{id}/resolve`: note ≤ 2,000 chars

Errors return `422` with field-level details, or `400` for semantic errors.

---

## Rate limiting

Login attempts: 5/minute per IP, then exponential backoff lockout. Other endpoints: generous default limits, configurable.

---

## Example: upload an analysis

```bash
# In CI after running scanners
wadjet scan
# or manually:
curl -X POST "$WADJET_URL/api/v1/analyses" \
  -H "Authorization: Bearer $WADJET_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @findings.json.gz
```

Response (200):
```json
{
  "analysis_id": 42,
  "gate_passed": false,
  "gate_details": [
    {"condition": "issues_critical > 0", "actual": 3, "threshold": 0, "triggered": true}
  ],
  "dashboard_url": "https://wadjet.example.com/projects/myproj/issues"
}
```
