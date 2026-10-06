# Supported scanner versions

One place for the version ranges the Wadjet agent supports. Each adapter's
`probe()` reads the same range, so `wadjet doctor` and the contract tests can
never disagree with this table.

| Adapter     | Distribution | Supported range | Recorded fixture             |
| ----------- | ------------ | --------------- | ---------------------------- |
| `bandit`    | `bandit`     | `>=1.7.8,<2`    | `fixtures/bandit/1.9.4/`     |
| `pip_audit` | `pip-audit`  | `>=2.7,<3`      | `fixtures/pip-audit/2.10.1/` |
| `ruff`      | `ruff`       | `>=0.6,<1`      | added in T3.2                |
| `detect_secrets` | `detect-secrets` | `>=1.4,<2` | added in T3.3                |
| `coverage`  | `coverage`   | `>=7.4,<8`      | added in T3.1                |

Install them with `pip install "wadjet-agent[scanners]"`, which pins the same
ranges. `wadjet doctor` reports the installed version of every adapter and
flags anything outside its range; each `scanner_runs` entry records the exact
version an analysis ran with.

The contract tests parse the recorded fixtures under `fixtures/<tool>/<version>/`,
so a newer scanner release cannot silently change normalization: re-record the
fixture under the new version directory and keep both passing.
