# Supported scanner versions

One place for the version ranges the Wadjet agent supports. Each adapter's
`probe()` reads the same range, so `wadjet doctor` and the contract tests can
never disagree with this table.

| Adapter           | Distribution   | Supported range | Notes                                  |
| ----------------- | -------------- | --------------- | -------------------------------------- |
| `bandit`          | `bandit`       | `>=1.7.8,<2`    | fixture `fixtures/bandit/1.9.4/`       |
| `pip_audit`       | `pip-audit`    | `>=2.7,<3`      | fixture `fixtures/pip-audit/2.10.1/`   |
| `ruff`            | `ruff`         | `>=0.6,<1`      | fixture `fixtures/ruff/0.16.10/`       |
| `detect_secrets`  | `detect-secrets` | `>=1.4,<2`     | T3.3                                   |
| `coverage`        | `coverage`     | `>=7.4,<8`      | report formats only - see below (T3.1) |

Install them with `pip install "wadjet-agent[scanners]"`, which pins the same
ranges. `wadjet doctor` reports the installed version of every adapter and
flags anything outside its range; each `scanner_runs` entry records the exact
version an analysis ran with.

Coverage is the one entry the agent never executes: it reads `coverage.json`
or `coverage.xml` produced by the project's own test step
(`scanners.coverage.report_path`), so `doctor` shows the report's status
instead of a version. The range documents the coverage.py releases whose
report formats the parser is tested against.

The contract tests parse the recorded fixtures under `fixtures/<tool>/<version>/`,
so a newer scanner release cannot silently change normalization: re-record the
fixture under the new version directory and keep both passing.
