# What Wadjet is, and isn't

An honest comparison against the two closest general-purpose tools.

## Wadjet

- A **quality-gate aggregator**: it runs maintained scanners through thin
  adapters and lets a gate decide pass/fail per run.
- **Scanners are the analysis engine's job** — Wadjet never writes its
  own detection rules. Adapters only normalize a maintained tool's output
  into one Finding schema.
- Everything is attributed: scans, gate results, triage decisions, and
  every state change lands in the audit log with actor, time and reason.
- Focus is the *workflow* around findings: triage, flag memory,
  requests, gate status, and a secure API for agents.

## Curation vs automation

| | SonarQube | DefectDojo | Wadjet |
|---|---|---|---|
| **Primary job** | Aggregate static-analysis findings from one toolset (SonarQube scanners) with measures | Centralize security-test reports (SAST/DAST/IaC/scanner) for a security team | Run a maintained set of scanners through thin adapters and gate them |
| **Scope of findings** | Static analysis of code, plus some SGX/SAST | Security tests: DAST, SCA, SAST, IaC, container | Any adapter output normalized to one Finding schema |
| **Gate / threshold** | Quality Gates per project/profile | Report acceptance & policy, "draft vs validated" workflow | Quality-gate conditions on normalized metrics (single source of truth) |
| **Agent workflow** | Issue triage, annotations, measures | Triage (draft → validated), requester workflow | Request-action workflow, tickets on `/issues`, per-project grants |
| **Attribution** | Reporter + created time; partial activity timeline | Reporter + timestamps; case notes | Full audit trail per state change |
| **Agent integration** | API (auth, issues) | API (report DRL, notes) | First-class agent API: tokens, config, analyses upload |

## Where Wadjet is not

- Not an analysis engine: it never writes detection rules. If a scanner
  doesn't exist as an adapter, Wadjet won't flag it.
- Not a substitute for the scanner: a gate can only evaluate what the
  adapters produce. A project with no enabled scanners passes trivially.
- Not a security tool per se: finding normalization is over, not the
  policy of which findings matter.

## Why run Wadjet

- One place for several scanners, one UI, one gate per project, one audit
  trail across them all.
- The agent is reusable: adapters pin the scanner versions, and the
  server always serves the current configuration, so CI re-runs against
  the same gate instead of the scanner's default.
