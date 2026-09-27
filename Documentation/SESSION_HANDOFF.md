# Member 5 — state of work and how to reproduce it

**Branch:** `feature/spa-support` · 28 September 2026

## Where the work stands

| Task | Tracker | Status | Evidence |
| --- | --- | --- | --- |
| 5.1 Discovery reliability | EVA-004 | **Done (rule-based)**; live Bedrock not measured | `evaluation/reports/discovery-reliability.md`: A 5/5, B 5/5 automatic; C 5/5 guided |
| 5.2 Formal check cases | EVA-005 | **Done**: 44 of 44 | `evaluation/reports/formal-cases.md` |
| 5.3 Failure situations | EVA-006 | **Done**: 7 of 7 | `Documentation/KNOWN_LIMITATIONS.md` §7 |
| 5.4 Offline analysis and reports | EVA-007 | **Done**: 6/6 and 6/6 | `offline-verification.md`, `offline-verification-juiceshop.md` |
| 5.5 Usage, cost, duration | EVA-008 | **Done except live model cost** | `measurements.md` (28 scans); cost envelope in the final report |
| 5.6 Session-check scope | — | **Done** | `KNOWN_LIMITATIONS.md` §1 |
| Feature freeze and limitations | REL-001 | **Done** | `Documentation/KNOWN_LIMITATIONS.md` |
| Generality: OWASP Juice Shop | — | **Done**: 6 of 6 | `evaluation/reports/juiceshop.md` |

The consolidated write-up is `evaluation/reports/final-evaluation-report.md`.

## How to reproduce every number

From the repository root, with the environment from `DEVELOPMENT.md` §1:

```powershell
# EVA-005: all 44 cases across Applications A, B and C
python -m authflowguard.evaluation.case_runner --application A,B,C --run-id my-run
python -m authflowguard.evaluation.tables evaluation/results/my-run/results.json `
  --title "Formal security-check evaluation (Applications A, B, C)"

# Juice Shop (needs Docker; bound to 127.0.0.1 only)
docker run -d --name authflowguard-juiceshop -e NODE_ENV=quiet `
  -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.2.0
python -m authflowguard.evaluation.case_runner `
  --cases evaluation/cases/juiceshop_cases.json --application J --run-id my-j-run

# EVA-004: discovery reliability, five attempts per application
python -m authflowguard.evaluation.discovery_reliability `
  --out evaluation/reports/discovery-reliability.md

# EVA-008: browser requests and durations from saved evidence
python -m authflowguard.evaluation.measurements my-run my-j-run `
  --out evaluation/reports/measurements.md

# EVA-007: offline reanalysis and report regeneration, target stopped
python -m authflowguard.evaluation.offline_verification `
  evaluation/results/my-run/scan-data/A-CHK-006-secure `
  --out evaluation/reports/offline-verification.md

# The AI path, offline: Bedrock discovery with the labelled model double
python -m authflowguard.evaluation.case_runner --application A,B,C `
  --discovery-mode bedrock --run-id my-bedrock-run
```

Add `--confirm-live-calls` to a Bedrock run only with an AWS profile that has
Bedrock access and an agreed budget; `--max-evaluation-cost-usd` caps it.

Raw scan data under `evaluation/results/*/scan-data/` is gitignored; the
`results.json` files and rendered reports are committed.

## Decisions worth not re-deriving

- **The case file is an immutable input.** `evaluation/cases/formal_cases.json`
  is never written to, and expectations are never edited to make a row pass.
  Each run writes its own `results.json`.
- **Each case gets a freshly started fixture.** Sharing one instance lets login
  enumeration's deliberate failed logins trip the secure fixture's lockout.
- **Live cases use an ephemeral port**; the origin used is recorded per result.
- **Juice Shop ground truth came first.** It was established with `curl` and a
  browser before the tool was run, and is recorded per case.
- **Application C was not tuned for.** It is the independently designed
  target; its automatic-discovery result stays a blind measurement.
- **Application B's secure mode was corrected**, because it leaked account
  existence at its first step, contrary to its own rationale. The fixed tool
  detected this before the fixture was changed. See `KNOWN_LIMITATIONS.md` §4.1.

## Outstanding

1. **Live Bedrock measurement.** Discovery reliability, token usage and cost of
   the AI path have not been measured against live AWS. Needs the
   `authflowguard-dev` profile and an agreed budget.
2. **Root `README.md`.** The repository has no landing page (REL-002, Member 3).
3. Kevin's case file still carries unused `actual_result` / `evidence_id` /
   `verdict` placeholder fields.
