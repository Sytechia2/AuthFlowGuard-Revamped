# EVA-008 — Measured consumption

Generated 2026-09-27 17:57 UTC from saved
evidence. One scan per case, single run each.

## What is measured and what is not

| Quantity | State |
| --- | --- |
| Browser request volume | Measured, from the saved event log |
| Scan duration | Measured, wall clock per case |
| Model input/output tokens | **Not measured** — rule-based scans make no Bedrock calls |
| Estimated cost before credits | **Not measured** — no live model calls |

Cost accounting is implemented and tested in
`authflowguard.evaluation.cost_model` and `cost_tracking`. It reuses the
production price table and labels every figure as live or mock, so it can
produce a cost table as soon as real model calls exist. No projected
figure appears here, because a projection is not a measurement.

## Per-case measurements

| Case | Check | App | Duration (s) | Browser requests | Responses | Events |
| --- | --- | --- | --- | --- | --- | --- |
| A-CHK-001-secure | login_enumeration | A | 7.02 | 17 | 17 | 103 |
| A-CHK-001-vulnerable | login_enumeration | A | 6.80 | 17 | 17 | 103 |
| A-CHK-002-secure | registration_enumeration | A | 5.33 | 9 | 9 | 51 |
| A-CHK-002-vulnerable | registration_enumeration | A | 5.24 | 9 | 9 | 51 |
| A-CHK-003-secure | reset_request_enumeration | A | 5.23 | 9 | 9 | 47 |
| A-CHK-003-vulnerable | reset_request_enumeration | A | 5.26 | 9 | 9 | 47 |
| A-CHK-004-secure | login_throttling | A | 6.07 | 13 | 13 | 77 |
| A-CHK-004-vulnerable | login_throttling | A | 5.82 | 14 | 14 | 79 |
| A-CHK-005-secure | session_fixation | A | 5.60 | 8 | 8 | 43 |
| A-CHK-005-vulnerable | session_fixation | A | 5.17 | 8 | 8 | 43 |
| A-CHK-006-secure | logout_invalidation | A | 5.49 | 8 | 8 | 42 |
| A-CHK-006-vulnerable | logout_invalidation | A | 5.29 | 8 | 8 | 42 |
| B-CHK-001-secure | login_enumeration | B | 8.98 | 27 | 27 | 151 |
| B-CHK-001-vulnerable | login_enumeration | B | 13.92 | 24 | 24 | 127 |
| C-CHK-001-secure | login_enumeration | C | 10.50 | 17 | 17 | 104 |
| C-CHK-001-vulnerable | login_enumeration | C | 9.75 | 17 | 17 | 104 |
| C-CHK-004-secure | login_throttling | C | 9.68 | 13 | 13 | 78 |
| C-CHK-004-vulnerable | login_throttling | C | 8.86 | 14 | 14 | 80 |
| C-CHK-005-secure | session_fixation | C | 8.88 | 8 | 8 | 44 |
| C-CHK-005-vulnerable | session_fixation | C | 8.41 | 8 | 8 | 44 |
| C-CHK-006-secure | logout_invalidation | C | 8.91 | 8 | 8 | 43 |
| C-CHK-006-vulnerable | logout_invalidation | C | 8.70 | 8 | 8 | 43 |
| J-CHK-001 | login_enumeration | J | 16.36 | 242 | 242 | 554 |
| J-CHK-002 | registration_enumeration | J | 17.43 | 121 | 121 | 288 |
| J-CHK-003 | reset_request_enumeration | J | 13.69 | 117 | 117 | 268 |
| J-CHK-004 | login_throttling | J | 13.82 | 201 | 201 | 454 |
| J-CHK-005 | session_fixation | J | 11.11 | 88 | 88 | 204 |
| J-CHK-006 | logout_invalidation | J | 14.43 | 114 | 114 | 255 |

**Totals across 28 live scans:** 251.8 s, 1156 browser requests.

**Averages:** 8.99 s and 41.3 browser requests per scan.
