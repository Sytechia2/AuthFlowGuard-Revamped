# EVA-008 — Measured consumption

Generated 2026-09-22 19:05 UTC from saved
evidence. One scan per case, single run each.

## What is measured and what is not

| Quantity | State |
| --- | --- |
| Browser request volume | Measured, from the saved event log |
| Scan duration | Measured, wall clock per case |
| Model input/output tokens | **Not measured** — no Bedrock calls |
| Estimated cost before credits | **Not measured** — no model calls |

Cost accounting is implemented and tested in
`authflowguard.evaluation.cost_model` and `cost_tracking`. It reuses the
production price table and labels every figure as live or mock, so it can
produce a cost table as soon as real model calls exist. No projected
figure appears here, because a projection is not a measurement.

## Per-case measurements

| Case | Check | App | Duration (s) | Browser requests | Responses | Events |
| --- | --- | --- | --- | --- | --- | --- |
| A-CHK-001-secure | login_enumeration | A | 4.79 | 17 | 17 | 103 |
| A-CHK-001-vulnerable | login_enumeration | A | 4.77 | 17 | 17 | 103 |
| A-CHK-002-secure | registration_enumeration | A | 3.95 | 11 | 11 | 59 |
| A-CHK-002-vulnerable | registration_enumeration | A | 4.02 | 11 | 11 | 59 |
| A-CHK-003-secure | reset_request_enumeration | A | 3.93 | 11 | 11 | 55 |
| A-CHK-003-vulnerable | reset_request_enumeration | A | 3.94 | 11 | 11 | 55 |
| A-CHK-004-secure | login_throttling | A | 3.97 | 13 | 13 | 77 |
| A-CHK-004-vulnerable | login_throttling | A | 3.95 | 14 | 14 | 79 |
| A-CHK-005-secure | session_fixation | A | 3.56 | 8 | 8 | 43 |
| A-CHK-005-vulnerable | session_fixation | A | 3.53 | 8 | 8 | 43 |
| A-CHK-006-secure | logout_invalidation | A | 3.71 | 8 | 8 | 42 |
| A-CHK-006-vulnerable | logout_invalidation | A | 3.62 | 8 | 8 | 42 |
| B-CHK-001-secure | login_enumeration | B | 94.63 | 22 | 13 | 114 |
| B-CHK-001-vulnerable | login_enumeration | B | 4.03 | 0 | 0 | 1 |
| C-CHK-001-secure | login_enumeration | C | 6.06 | 17 | 17 | 104 |
| C-CHK-001-vulnerable | login_enumeration | C | 6.32 | 17 | 17 | 104 |
| C-CHK-004-secure | login_throttling | C | 5.61 | 13 | 13 | 78 |
| C-CHK-004-vulnerable | login_throttling | C | 6.10 | 14 | 14 | 80 |
| C-CHK-005-secure | session_fixation | C | 5.18 | 8 | 8 | 44 |
| C-CHK-005-vulnerable | session_fixation | C | 5.45 | 8 | 8 | 44 |
| C-CHK-006-secure | logout_invalidation | C | 5.43 | 8 | 8 | 43 |
| C-CHK-006-vulnerable | logout_invalidation | C | 5.14 | 8 | 8 | 43 |

**Totals across 22 live scans:** 191.7 s, 252 browser requests.

**Averages:** 8.71 s and 11.5 browser requests per scan.
