# vulnerable_app

A deliberately vulnerable Python project used by the Wadjet end-to-end check
(`make e2e`, script in `tests/e2e.py`).

- `core.py` - assert, `shell=True`, `pickle.loads`, MD5, `random` and a
  hardcoded password: eight Bandit findings across severity levels.
- `utils.py` - one more assert.
- `requirements.txt` - `requests==2.31.0`, vulnerable to CVE-2024-35195
  (fixed in 2.32.0), so the pip-audit adapter has a known dependency issue to
  report (requires network access to the vulnerability database).
- `expected_findings.json` - the issues the server must show after the first
  scan. Bandit severities are frozen from bandit 1.9.4 (see
  `agent/SUPPORTED.md`). The dependency expectation matches on package +
  installed version + fix version: the upload carries advisory ids and CVE
  aliases, but the server persists only `vuln_id`, and advisory ids churn
  over time while fix versions do not.

The end-to-end script copies this directory before every mutation, so the
committed sample never changes.
