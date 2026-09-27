# Member 5 — task status

**Sufian, 28 September 2026.** Branch `feature/spa-support`. Every figure below
was produced on the final code and is in the committed reports.

## Summary

All Member 5 tasks are complete. The only open item is the **live Bedrock**
part of 5.1 and 5.5 (AI reliability and real model cost). It needs AWS
credentials for the `authflowguard-dev` profile and an agreed budget, which
this machine does not have. Everything else about the AI path is verified
offline.

## Tasks

| Task | Tracker | Status | Result | Evidence |
| --- | --- | --- | --- | --- |
| 5.1 Measure login discovery reliability | EVA-004 | ✅ Done (rule-based) · ⏳ live Bedrock needs AWS credentials | A 5/5 and B 5/5 automatic (B was 2/5); C 5/5 via guided fallback | `evaluation/reports/discovery-reliability.md` |
| 5.2 Execute the security-check cases | EVA-005 | ✅ Done | **44 / 44 pass** (was 41 / 44) | `evaluation/reports/formal-cases.md` |
| 5.3 Test failure situations | EVA-006 | ✅ Done | **7 / 7** conditions; no failed test ever reported as a pass | `Documentation/KNOWN_LIMITATIONS.md` §7 |
| 5.4 Confirm offline analysis and reports | EVA-007 | ✅ Done | 6/6 on App A and 6/6 on Juice Shop, target stopped | `evaluation/reports/offline-verification*.md` |
| 5.5 Measure usage, cost and duration | EVA-008 | ✅ Done · ⏳ live model cost needs AWS credentials | 28 live scans measured; AI cost pipeline verified offline; spend hard-capped ($0.001 per call, $0.04 per scan at defaults) | `evaluation/reports/measurements.md`, final report §5 |
| 5.6 Decide the session-check scope | — | ✅ Done | Menu logout and 500-on-signed-out now supported; bearer-token replay deferred | `Documentation/KNOWN_LIMITATIONS.md` §1 |
| 10.2 Freeze features, list limitations | REL-001 | ✅ Done | One consolidated, current list | `Documentation/KNOWN_LIMITATIONS.md` |

## Beyond the plan

| Item | Result | Evidence |
| --- | --- | --- |
| OWASP Juice Shop integration (Peter's request) | **6 / 6** correct; all 4 real vulnerabilities found; 8 of 9 full runs 6/6 | `evaluation/reports/juiceshop.md` |
| Single-page app support | Fixed the bugs that made every Juice Shop scan fail; JavaScript forms, menu logout and two-step logins now handled | PR description |
| Worker hardening | A finished scan can no longer be held open by a lingering worker | `worker_supervisor.py`, `scan_worker.py` |
| Packaging QC | Clean install from `pyproject.toml` works; frontend `npm run check` passes on Windows | — |
| Consolidated report | Everything above in one document | `evaluation/reports/final-evaluation-report.md` |

## To finish the live Bedrock measurement

With the `authflowguard-dev` profile configured on the machine running it:

```bash
aws sso login --profile authflowguard-dev
python -m authflowguard.evaluation.discovery_reliability --discovery-mode bedrock \
  --confirm-live-calls --max-evaluation-cost-usd 1.00
```

Spend is capped by `--max-evaluation-cost-usd`; with Nova Micro the whole run
should cost well under that. The results then replace the "not measured live"
lines in the final report.
