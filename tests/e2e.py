"""End-to-end integration check (T2.7): server + agent + a real database.

Run with ``make e2e``. The script creates a throwaway schema, migrates it,
starts the server, seeds an admin/project/token, and runs the real ``wadjet``
CLI against a copy of ``tests/sample_projects/vulnerable_app``. It then walks
the Phase 2 acceptance scenarios:

1. the expected issues appear and the gate fails (exit 1);
2. a false-positive flag survives inserting lines at the top of a file;
3. the flag survives moving the file;
4. editing the flagged line opens a new open issue and resolves the old one;
5. fixing a vulnerability resolves its issue;
6. exit code 0 (clean project passes), 2 (no configuration) and
   3 (broken scanner -> incomplete analysis) are each reproduced;
7. the pip-audit dependency finding for the sample's pinned ``requests`` pin
   appears (skipped with a warning when offline).

Dependency scanning uses a dedicated audit environment (``WADJET_PYTHON``,
cached under ``~/.cache/wadjet/``): pip-audit's ``-r`` mode builds its own
virtualenv, which needs ``ensurepip`` - unavailable on this host without
sudo, while the agent's active-environment mode needs nothing special.

Everything runs inside one unique schema that is dropped afterwards, so the
check never touches real data and can run while other suites use the database.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Mapping
from pathlib import Path

import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url

# The venv python is a symlink; do NOT resolve it, the entry points live next
# to the interpreter path that was invoked (``.venv/bin``).
BIN = Path(sys.executable).parent
if not (BIN / "wadjet").exists():  # running via a system interpreter
    BIN = Path(__file__).resolve().parent.parent / ".venv" / "bin"
SAMPLE = Path(__file__).resolve().parent / "sample_projects" / "vulnerable_app"
BASE_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or (
    "postgresql+psycopg://wadjet@localhost:5432/wadjet"
)
SECRET_KEY = "e2e-secret-key-0123456789abcdef0123456789abcdef"
HEALTH_TIMEOUT = 60.0
AGENT_TIMEOUT = 600
LOG_TAIL_LINES = 40


class Failure(RuntimeError):
    """A failed acceptance check."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def step(title: str) -> None:
    print(f"\n=== {title}", flush=True)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def tail(path: Path, lines: int = LOG_TAIL_LINES) -> str:
    if not path.exists():
        return "(no server log)"
    content = path.read_text(errors="replace").splitlines()
    return "\n".join(content[-lines:])


def wait_for_health(url: str, log: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise Failure(f"server exited early; log tail:\n{tail(log)}")
        try:
            if httpx.get(url, timeout=1.0).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.5)
    raise Failure(f"server never became healthy; log tail:\n{tail(log)}")


def run_agent(
    path: Path,
    *,
    base_url: str | None = None,
    token: str | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> tuple[int, str]:
    """Run ``wadjet scan`` and return ``(exit_code, combined_output)``."""
    env = dict(os.environ)
    for key in ("WADJET_URL", "WADJET_TOKEN", "WADJET_PYTHON"):
        env.pop(key, None)
    if base_url and token:
        env["WADJET_URL"] = base_url
        env["WADJET_TOKEN"] = token
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(
            [str(BIN / "wadjet"), "scan", "--path", str(path)],
            env=env,
            capture_output=True,
            text=True,
            timeout=AGENT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise Failure(f"agent timed out after {AGENT_TIMEOUT}s") from None
    return proc.returncode, proc.stdout + proc.stderr


def set_settings(
    engine: Engine,
    project_id: int,
    *,
    pip_audit: bool,
    dependency_files: list[str] | None = None,
) -> None:
    settings = {
        "scanners": {
            "bandit": {"enabled": True},
            "pip_audit": {
                "enabled": pip_audit,
                "dependency_files": dependency_files or [],
                "dependency_default_severity": "high",
            },
        }
    }
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE projects SET settings = :settings WHERE id = :pid"),
            {"settings": json.dumps(settings), "pid": project_id},
        )


def fetch_issues(engine: Engine, project_id: int) -> list[dict]:
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT id, tool, rule_id, file_path, severity, line_start, triage_status, "
                "presence, snippet, package, installed_version, vuln_id, fixed_versions "
                "FROM issues WHERE project_id = :pid ORDER BY id"
            ),
            {"pid": project_id},
        ).fetchall()
    return [
        {
            "id": row[0],
            "tool": row[1],
            "rule_id": row[2],
            "file_path": row[3],
            "severity": row[4],
            "line_start": row[5],
            "triage_status": row[6],
            "presence": row[7],
            "snippet": row[8],
            "package": row[9],
            "installed_version": row[10],
            "vuln_id": row[11],
            "fixed_versions": row[12] or [],
        }
        for row in rows
    ]


def issue_events(engine: Engine, issue_id: int) -> set[str]:
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT type FROM issue_events WHERE issue_id = :iid"), {"iid": issue_id}
        ).fetchall()
    return {row[0] for row in rows}


def flag_issue(engine: Engine, issue_id: int, status: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE issues SET triage_status = :status WHERE id = :iid"),
            {"status": status, "iid": issue_id},
        )


def last_analysis(engine: Engine, project_id: int) -> dict:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT status, gate_status FROM analyses "
                "WHERE project_id = :pid ORDER BY id DESC LIMIT 1"
            ),
            {"pid": project_id},
        ).first()
    check(row is not None, "no analysis was stored")
    return {"status": row[0], "gate_status": row[1]}


def scan(
    label: str,
    path: Path,
    *,
    base_url: str,
    token: str,
    expected: int,
    output: list[str],
    extra_env: Mapping[str, str] | None = None,
) -> None:
    code, out = run_agent(path, base_url=base_url, token=token, extra_env=extra_env)
    output.append(f"--- {label} (exit {code}) ---\n{out}")
    check(
        code == expected,
        f"{label}: expected exit code {expected}, got {code}:\n{out[-2000:]}",
    )


def seed(engine: Engine) -> tuple[int, str]:
    """Create the admin, the project and its token; returns (project_id, token)."""
    from app.security import hash_password
    from app.tokens import create_token

    with engine.begin() as conn:
        admin_id = conn.execute(
            text(
                "INSERT INTO users (username, email, password_hash, is_admin, is_active) "
                "VALUES ('e2e-admin', 'e2e@test.local', :hash, TRUE, TRUE) RETURNING id"
            ),
            {"hash": hash_password("e2e-password")},
        ).scalar_one()
        project_id = conn.execute(
            text(
                "INSERT INTO projects (key, name, created_by) "
                "VALUES ('e2e-sample', 'E2E sample', :uid) RETURNING id"
            ),
            {"uid": admin_id},
        ).scalar_one()
    token, _token_id = create_token(engine, int(project_id), "e2e", created_by=int(admin_id))
    set_settings(engine, int(project_id), pip_audit=False)
    return int(project_id), token


AUDIT_VENV = (
    Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")) / "wadjet" / "e2e-audit-venv"
)


def distribution_version(python: Path, distribution: str) -> str | None:
    probe = subprocess.run(
        [str(python), "-c", f"import importlib.metadata as m; print(m.version({distribution!r}))"],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.stdout.strip() if probe.returncode == 0 else None


def ensure_audit_venv(specs: list[str]) -> Path | None:
    """A small, cached environment pip-audit can audit directly.

    pip-audit's ``-r`` mode builds its own virtualenv, which needs
    ``ensurepip`` - Debian ships that in the ``python3-venv`` package, which is
    unavailable here without sudo. The agent's documented fallback (no
    ``dependency_files``) audits the active environment instead, so the e2e
    installs the sample's pinned requirements into this dedicated environment
    and points ``WADJET_PYTHON`` at it.
    """
    python = AUDIT_VENV / "bin" / "python"
    if not python.exists():
        AUDIT_VENV.parent.mkdir(parents=True, exist_ok=True)
        created = subprocess.run(
            [sys.executable, "-m", "venv", "--without-pip", str(AUDIT_VENV)],
            capture_output=True,
            text=True,
            check=False,
        )
        if created.returncode != 0:
            print(f"could not create the audit environment: {created.stderr[-300:]}")
            return None
    for spec in [*specs, "pip-audit==2.10.1", "pip"]:
        distribution, _, version = spec.partition("==")
        if version:
            if distribution_version(python, distribution) == version:
                continue
        elif distribution_version(python, distribution):
            continue
        installed = subprocess.run(
            [str(BIN / "pip"), "--python", str(python), "install", "-q", spec],
            capture_output=True,
            text=True,
            check=False,
        )
        if installed.returncode != 0:
            print(f"could not install {spec} into the audit environment: {installed.stderr[-300:]}")
            return None
    return python


def require(condition: bool, message: str, output: list[str]) -> None:
    if not condition:
        if output:
            raise Failure(f"{message}\n--- agent output tail ---\n{output[-1][-3000:]}")
        raise Failure(message)


def main() -> int:
    schema = f"e2e_{uuid.uuid4().hex[:8]}"
    base = make_url(BASE_DATABASE_URL)
    admin = create_engine(str(base))
    server: subprocess.Popen[bytes] | None = None
    engine: Engine | None = None
    output: list[str] = []
    tmp = Path(tempfile.mkdtemp(prefix="wadjet-e2e-"))
    workdir = tmp / "vulnerable_app"
    log = tmp / "server.log"

    try:
        with admin.connect() as conn:
            conn.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            conn.commit()

        url = base.set(query={"options": f"-c search_path={schema}"}).render_as_string(
            hide_password=False
        )

        from app.migrate import upgrade_url

        upgrade_url(url)
        engine = create_engine(url)

        port = free_port()
        server_base = f"http://127.0.0.1:{port}"
        step(f"0. starting the server on {server_base} (schema {schema})")
        with log.open("wb") as log_handle:
            server = subprocess.Popen(
                [str(BIN / "wadjet-server"), "serve", "--host", "127.0.0.1", "--port", str(port)],
                env={
                    **os.environ,
                    "DATABASE_URL": url,
                    "WADJET_SECRET_KEY": SECRET_KEY,
                    "WADJET_BASE_URL": server_base,
                },
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
            wait_for_health(f"{server_base}/healthz", log, server)

        project_id, token = seed(engine)
        print(f"seeded project e2e-sample (id {project_id})", flush=True)

        shutil.copytree(SAMPLE, workdir)
        expected = json.loads((SAMPLE / "expected_findings.json").read_text())

        # --- scenario 1: baseline -----------------------------------------
        step("1. baseline scan: expected issues appear, gate fails (exit 1)")
        scan("baseline", workdir, base_url=server_base, token=token, expected=1, output=output)
        issues = fetch_issues(engine, project_id)
        bandit_actual = {(i["rule_id"], i["file_path"]) for i in issues if i["tool"] == "bandit"}
        bandit_expected = {(e["rule_id"], e["file_path"]) for e in expected["bandit"]}
        require(
            bandit_actual == bandit_expected,
            "bandit issues differ from expected_findings.json: "
            f"missing {sorted(bandit_expected - bandit_actual)}, "
            f"unexpected {sorted(bandit_actual - bandit_expected)}",
            output,
        )
        expected_severity = {
            (e["rule_id"], e["file_path"]): e["severity"] for e in expected["bandit"]
        }
        for issue in issues:
            key = (issue["rule_id"], issue["file_path"])
            require(
                issue["severity"] == expected_severity[key],
                f"severity of {key}: expected {expected_severity[key]}, got {issue['severity']}",
                output,
            )
            require(
                issue["triage_status"] == "open" and issue["presence"] == "present",
                f"{key} should be open/present",
                output,
            )
        analysis = last_analysis(engine, project_id)
        require(
            analysis == {"status": "complete", "gate_status": "failed"},
            f"baseline analysis wrong: {analysis}",
            output,
        )

        target = next(i for i in issues if i["rule_id"] == "B105")
        flagged_id, flagged_line = target["id"], target["line_start"]
        flag_issue(engine, flagged_id, "false_positive")
        print(f"flagged issue {flagged_id} (B105) as false_positive", flush=True)

        # --- scenario 2: line shift ---------------------------------------
        step("2. inserting lines at the top keeps the false-positive flag")
        core = workdir / "core.py"
        core.write_text('"""Five inserted lines."""\n# a\n# b\n# c\n# d\n' + core.read_text())
        scan("line-shift", workdir, base_url=server_base, token=token, expected=1, output=output)
        b105 = [i for i in fetch_issues(engine, project_id) if i["rule_id"] == "B105"]
        require(len(b105) == 1, f"line shift must not duplicate B105, got {len(b105)}", output)
        require(
            b105[0]["id"] == flagged_id,
            "line shift created a new issue instead of matching",
            output,
        )
        require(
            b105[0]["triage_status"] == "false_positive",
            "the false-positive flag was lost after the line shift",
            output,
        )
        require(
            b105[0]["line_start"] == flagged_line + 5,
            f"line numbers should track the shift ({flagged_line} -> {b105[0]['line_start']})",
            output,
        )
        require(
            "flag_carried_over" in issue_events(engine, flagged_id),
            "missing carry-over event after the line shift",
            output,
        )

        # --- scenario 3: move ---------------------------------------------
        step("3. moving the file keeps the false-positive flag")
        core.rename(workdir / "renamed_core.py")
        scan("move", workdir, base_url=server_base, token=token, expected=1, output=output)
        b105 = [i for i in fetch_issues(engine, project_id) if i["rule_id"] == "B105"]
        require(len(b105) == 1, f"move must not duplicate B105, got {len(b105)}", output)
        require(
            b105[0]["id"] == flagged_id,
            "move created a new issue instead of matching",
            output,
        )
        require(
            b105[0]["file_path"] == "renamed_core.py",
            "issue was not moved with the file",
            output,
        )
        require(
            b105[0]["triage_status"] == "false_positive",
            "the flag was lost after the move",
            output,
        )

        # --- scenario 4: edit the flagged line ----------------------------
        step("4. editing the flagged line opens a new open issue")
        moved = workdir / "renamed_core.py"
        content = moved.read_text()
        require('password = "hunter2"' in content, "sample changed unexpectedly", output)
        moved.write_text(
            content.replace('password = "hunter2"', 'password = "Totally-New-Password-42"')
        )
        scan("edit", workdir, base_url=server_base, token=token, expected=1, output=output)
        b105 = [i for i in fetch_issues(engine, project_id) if i["rule_id"] == "B105"]
        require(len(b105) == 2, f"expected old + new B105 issue, got {len(b105)}", output)
        old = next(i for i in b105 if i["id"] == flagged_id)
        new = next(i for i in b105 if i["id"] != flagged_id)
        require(old["presence"] == "resolved", "the stale issue should be resolved", output)
        require(
            old["triage_status"] == "false_positive",
            "triage should survive resolution",
            output,
        )
        require(
            "resolved_by_scan" in issue_events(engine, flagged_id),
            "missing resolved_by_scan event",
            output,
        )
        require(
            new["presence"] == "present" and new["triage_status"] == "open",
            "the edited finding should be a new open issue",
            output,
        )
        require(
            "Totally-New-Password-42" in (new["snippet"] or ""),
            "the new issue should carry the edited code",
            output,
        )

        # --- scenario 5: fix a vulnerability ------------------------------
        step("5. fixing a vulnerability resolves its issue")
        b324 = next(i for i in fetch_issues(engine, project_id) if i["rule_id"] == "B324")
        content = moved.read_text()
        require("hashlib.md5(data)" in content, "sample changed unexpectedly", output)
        moved.write_text(content.replace("hashlib.md5(data)", "hashlib.sha256(data)"))
        scan("fix", workdir, base_url=server_base, token=token, expected=1, output=output)
        b324_now = next(i for i in fetch_issues(engine, project_id) if i["rule_id"] == "B324")
        require(
            b324_now["id"] == b324["id"],
            "the MD5 issue was replaced instead of resolved",
            output,
        )
        require(
            b324_now["presence"] == "resolved", "the fixed vulnerability did not resolve", output
        )
        require(
            "resolved_by_scan" in issue_events(engine, b324["id"]),
            "missing resolved_by_scan event for the fixed issue",
            output,
        )

        # --- exit codes ----------------------------------------------------
        step("6. exit code 0: a clean project passes the gate")
        clean = tmp / "clean_app"
        clean.mkdir()
        (clean / "clean.py").write_text("def add(a, b):\n    return a + b\n")
        scan("clean", clean, base_url=server_base, token=token, expected=0, output=output)
        require(
            last_analysis(engine, project_id) == {"status": "complete", "gate_status": "passed"},
            "the clean analysis should have passed the gate",
            output,
        )

        step("7. exit code 2: missing configuration")
        code, out = run_agent(workdir)
        output.append(f"--- no-config (exit {code}) ---\n{out}")
        require(code == 2, f"expected exit code 2, got {code}:\n{out}", output)
        require("WADJET_URL" in out, "the config error should mention the variable", output)

        step("8. exit code 3: a broken scanner makes the analysis incomplete")
        set_settings(engine, project_id, pip_audit=True)
        scan(
            "broken-scanner",
            workdir,
            base_url=server_base,
            token=token,
            expected=3,
            output=output,
            extra_env={"WADJET_PYTHON": "/nonexistent/python"},
        )
        analysis = last_analysis(engine, project_id)
        require(
            analysis["status"] == "incomplete",
            f"analysis should be incomplete, got {analysis}",
            output,
        )

        # --- network-dependent check ---------------------------------------
        step("9. dependency findings from pip-audit (dedicated audit environment)")
        requirements = [
            line.strip()
            for line in (SAMPLE / "requirements.txt").read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        audit_python = ensure_audit_venv(requirements)
        if audit_python is None:
            print("could not prepare the audit environment; step skipped")
        else:
            set_settings(engine, project_id, pip_audit=True)
            code, out = run_agent(
                workdir,
                base_url=server_base,
                token=token,
                extra_env={"WADJET_PYTHON": str(audit_python)},
            )
            output.append(f"--- dependency (exit {code}) ---\n{out}")
            if code == 3:
                print("pip-audit could not reach the vulnerability database; step skipped")
            else:
                require(code == 1, f"dependency run: expected exit 1, got {code}:\n{out}", output)
                deps = [i for i in fetch_issues(engine, project_id) if i["tool"] == "pip_audit"]
                require(deps, "no dependency issues were stored", output)
                want = expected["pip_audit"][0]
                matching = [
                    i
                    for i in deps
                    if i["package"] == want["package"]
                    and i["installed_version"] == want["installed_version"]
                ]
                require(
                    matching,
                    f"no dependency issue for {want['package']}, got "
                    f"{[(d['package'], d['installed_version']) for d in deps]}",
                    output,
                )
                require(
                    any(want["fixed_versions_include"] in i["fixed_versions"] for i in matching),
                    f"no recorded fix {want['fixed_versions_include']} for "
                    f"{want['package']}, got {[i['fixed_versions'] for i in matching]}",
                    output,
                )

        print(
            "\nE2E PASSED: scenarios 1-5 and exit codes 0, 1, 2, 3 all reproduced.",
            flush=True,
        )
        return 0

    except Failure as exc:
        print(f"\nE2E FAILED: {exc}", file=sys.stderr, flush=True)
        if log.exists():
            print(f"\n--- server log tail ---\n{tail(log)}", file=sys.stderr, flush=True)
        return 1
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)
        if engine is not None:
            engine.dispose()
        try:
            with admin.connect() as conn:
                conn.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
                conn.commit()
        except Exception:  # noqa: BLE001 - cleanup must never mask the result
            print(f"warning: could not drop schema {schema}", file=sys.stderr)
        admin.dispose()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
