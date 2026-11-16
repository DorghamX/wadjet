# Writing an adapter

Every scanner in Wadjet is a single Python file under `wadjet_agent/adapters/` (aim < 150 lines) implementing the `Adapter` protocol. The agent discovers adapters from the `ADAPTERS` registry, reads their settings from the server, runs them, and normalizes their output to the server's `Finding` schema.

## The protocol

```python
from typing import Protocol, Any
from pathlib import Path
from dataclasses import dataclass

class Adapter(Protocol):
    name: str                           # registry key, e.g. "bandit"
    def info(self) -> AdapterInfo       # for `wadjet doctor`
    def run(self, ctx: RunContext) -> RawOutput
    def normalize(self, raw: RawOutput, ctx: RunContext) -> list[Finding]
```

### `AdapterInfo`

```python
@dataclass(frozen=True)
class AdapterInfo:
    installed: bool  # is the tool on PATH?
    version: str | None  # what `tool --version` says
    supported: bool  # version within the supported range?
    detail: str  # human note for `doctor`
```

### `RunContext` (read-only, passed to every call)

```python
@dataclass(frozen=True)
class RunContext:
    repo_root: Path  # repository root (resolved)
    include_paths: list[str]  # relative to repo_root
    exclusion_globs: list[str]  # post-filter for tools without native exclude
    python_executable: str  # sys.executable by default
    settings: dict[str, Any]  # structured settings from /api/v1/agent/config
    timeout: float = 120.0  # per-adapter wall-clock limit

    def tool_settings(self, name: str) -> dict[str, Any]:
        """Typed options for one scanner (no free-form CLI args)."""
        return self.settings.get("scanners", {}).get(name, {})
```

### `RawOutput`

```python
@dataclass(frozen=True)
class RawOutput:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
```

### `Finding` (what the server ingests)

```python
@dataclass(frozen=True)
class Finding:
    tool: str  # adapter name
    rule_id: str  # e.g. "B101", "ruff:F401", "pip-audit:requests"
    severity: str  # blocker | critical | high | medium | low | info
    category: str  # vulnerability | dependency | secret | bug | code_smell
    title: str
    message: str
    file_path: str | None  # POSIX, relative to repo_root; None for dependency
    line_start: int | None
    line_end: int | None
    snippet: str  # flagged lines ± 3 context lines
    package: str | None
    installed_version: str | None
    vuln_id: str | None
    aliases: list[str]
    fixed_versions: list[str]
    cwe: list[str]
    raw: dict[str, Any] | None  # free-form extras (e.g., Ruff explanation)
```

**Secrets rule**: a `category="secret"` finding MUST contain only `file_path`, `line_start`, `line_end`, `snippet` (type only, no value), and `raw.hashed_secret`. The server rejects any secret finding with extra keys.

---

## Adapter lifecycle

1. **`info()`** — called by `wadjet doctor`. Checks tool presence and version.
2. **`run(ctx)`** — the agent:
   - Builds the command line from `ctx.tool_settings(name)` (no raw CLI passthrough)
   - Runs the tool with `ctx.timeout` wall-clock limit
   - Captures stdout/stderr/exit_code
   - Returns `RawOutput`
3. **`normalize(raw, ctx)`** — pure function:
   - Parses `raw.stdout` (JSON, XML, etc.)
   - Emits `Finding` objects with normalized paths, severities, categories
   - Applies `ctx.exclusion_globs` as a safety net (agent also post-filters)
   - **Never** mutates state, never does I/O

---

## Adding a new adapter

1. Create `wadjet_agent/adapters/mytool.py` with an `Adapter` implementation.
2. Register it in `wadjet_agent/adapters/__init__.py`:
   ```python
   from .mytool import MyToolAdapter

   ADAPTERS["mytool"] = MyToolAdapter()
   ```
3. Add the supported version range to `agent/SUPPORTED.md`.
3. Record a fixture:
   - Run the tool on a small sample: `tool args > fixtures/mytool/<version>/raw.json`
   - The contract test will parse this fixture and assert the `normalize` output.
4. Write a contract test in `agent/tests/test_adapters.py`:
   ```python
   def test_mytool_normalize():
       raw = read_fixture("mytool", "1.2.3")
       findings = MyToolAdapter().normalize(raw, ctx)
       assert findings[0].rule_id == "EXPECTED"
       ...
   ```
5. If the tool has rule metadata (title, description, CWE, fix, references), add entries to `server/app/kb/mytool.yml`. The server enriches findings at ingest so text can improve without agent updates. **A test must fail if any rule ID seen in fixtures is missing from the KB.**

---

## Supported version ranges (single source of truth)

The file `agent/SUPPORTED.md` lists every adapter's distribution name and supported range. Each adapter's `info()` reads the same range, so `wadjet doctor` and the contract tests can never disagree with the table. Pinning is done in `agent/pyproject.toml` optional-dependencies (`scanners`).

---

## Fixture format

`fixtures/<tool>/<version>/` contains:
- `raw.json` — the exact stdout of a successful run (or `raw.xml` for tools that emit XML)
- `expected.json` (optional) — the normalized `list[Finding]` the contract test asserts against

The contract test loads `raw.json`, calls `normalize`, and compares to `expected.json` (if present) or to inline assertions.

---

## Settings shape (from `/api/v1/agent/config`)

```json
{
  "scanners": {
    "bandit": {"select": ["B101", "..."], "exclude": ["tests/"]},
    "pip_audit": {"requirements_files": ["requirements.txt"]},
    "ruff": {"select": ["F", "B", "C90", "PLE"], "exclude": ["migrations/"]},
    "detect_secrets": {},
    "coverage": {"report_path": "coverage.xml"}
  },
  "exclusions": ["**/migrations/**", "**/vendor/**"],
  "gate_id": 1
}
```

Adapters read their subsection via `ctx.tool_settings("name")`. The agent passes exclusions to each tool's native flag where supported, then post-filters by path (defense in depth).

---

## Failure policy

If a scanner is missing, crashes, or times out:
- `RawOutput` carries `exit_code != 0` or `timed_out=True`
- `normalize` returns `[]` (no findings from a broken run)
- The analysis is marked `status=incomplete` in `scanner_runs`
- The gate fails with the synthetic condition "All enabled scanners completed" (controlled by `fail_on_scanner_error` setting, default `true`)

---

## Knowledge-base enrichment (server side)

`server/app/kb/<tool>.yml` maps `rule_id` → `{title, description, impact, fix, references, cwe}`. The server enriches findings at ingest so text improves without agent updates.

- **Bandit**: hand-write entries for every test ID (B101–B703). A test fails if any is missing.
- **Ruff**: `ruff rule <CODE> --output-format json` provides explanations; upload in `raw.explanation`.
- **pip-audit**: fix text from `fix_versions`.
- **detect-secrets**: type → CWE mapping in KB.

---

## Quick example: a minimal adapter

```python
# wadjet_agent/adapters/example.py
from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any

from .base import Adapter, AdapterInfo, Finding, RawOutput, RunContext


class ExampleAdapter:
    name = "example"

    def info(self) -> AdapterInfo:
        try:
            out = subprocess.run(
                ["example-tool", "--version"], capture_output=True, text=True, timeout=5
            )
            version = out.stdout.strip()
            supported = True  # replace with real range check
        except Exception:
            version = None
            supported = False
        return AdapterInfo(
            installed=version is not None, version=version, supported=supported, detail=""
        )

    def run(self, ctx: RunContext) -> RawOutput:
        cmd = ["example-tool", "--format", "json"] + ctx.include_paths
        try:
            proc = subprocess.run(
                cmd, cwd=ctx.repo_root, capture_output=True, text=True, timeout=ctx.timeout
            )
            return RawOutput(proc.stdout, proc.stderr, proc.returncode, False)
        except subprocess.TimeoutExpired as e:
            return RawOutput(e.stdout or "", e.stderr or "", -1, True)

    def normalize(self, raw: RawOutput, ctx: RunContext) -> list[Finding]:
        if raw.exit_code != 0 or not raw.stdout.strip():
            return []
        data = json.loads(raw.stdout)
        findings = []
        for item in data.get("results", []):
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=item["rule"],
                    severity=item["severity"].lower(),
                    category="vulnerability",
                    title=item["message"],
                    message=item["message"],
                    file_path=item["file"],
                    line_start=item["line"],
                    line_end=item["line"],
                    snippet=item.get("code", ""),
                    package=None,
                    installed_version=None,
                    vuln_id=None,
                    aliases=[],
                    fixed_versions=[],
                    cwe=[],
                    raw={},
                )
            )
        return findings
```

---

## Testing checklist

- [ ] `info()` returns correct `installed`/`version`/`supported`/`detail`
- [ ] `run()` respects `ctx.timeout`, returns `RawOutput` with `timed_out` on timeout
- [ ] `normalize()` handles empty/error output → `[]`
- [ ] All fixture versions parse and produce expected findings
- [ ] Paths are POSIX, relative to repo root
- [ ] Severity/category mapping matches the table in section 5.1
- [ ] Secret findings contain ONLY allowed keys
- [ ] KB has entries for every rule ID seen in fixtures
- [ ] `wadjet doctor` reports the adapter correctly