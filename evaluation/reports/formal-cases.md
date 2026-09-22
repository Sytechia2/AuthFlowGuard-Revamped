# EVA-005 — Formal security-check evaluation (Application A)

Generated 2026-09-22 18:31 UTC from A-fault-001, A-live-001, A-offline-001.

| Case | Check | Mode | Expected | Actual | Verdict | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| A-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `0823f34e` |
| A-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `105347d5` |
| A-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `0823f34e` |
| A-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `bca94873` |
| A-CHK-002-ambiguous | registration_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `2947a0a6` |
| A-CHK-002-execution-failure | registration_enumeration | fault_injection | execution_error | execution_error | PASS | `c361de09` |
| A-CHK-002-secure | registration_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `2947a0a6` |
| A-CHK-002-vulnerable | registration_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `03e12f4d` |
| A-CHK-003-ambiguous | reset_request_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `2114e8fb` |
| A-CHK-003-execution-failure | reset_request_enumeration | fault_injection | execution_error | execution_error | PASS | `38fb1382` |
| A-CHK-003-secure | reset_request_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `2114e8fb` |
| A-CHK-003-vulnerable | reset_request_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `52d508c1` |
| A-CHK-004-ambiguous | login_throttling | offline_analysis | inconclusive | inconclusive | PASS | `85d89da1` |
| A-CHK-004-execution-failure | login_throttling | fault_injection | execution_error | execution_error | PASS | `0abe800f` |
| A-CHK-004-secure | login_throttling | live_scan | no_issue_observed | no_issue_observed | PASS | `85d89da1` |
| A-CHK-004-vulnerable | login_throttling | live_scan | finding_confirmed | finding_confirmed | PASS | `5f0aed41` |
| A-CHK-005-ambiguous | session_fixation | offline_analysis | inconclusive | inconclusive | PASS | `268bf876` |
| A-CHK-005-execution-failure | session_fixation | fault_injection | execution_error | execution_error | PASS | `4c8b9f71` |
| A-CHK-005-secure | session_fixation | live_scan | no_issue_observed | no_issue_observed | PASS | `268bf876` |
| A-CHK-005-vulnerable | session_fixation | live_scan | finding_confirmed | finding_confirmed | PASS | `c2e9409f` |
| A-CHK-006-ambiguous | logout_invalidation | offline_analysis | inconclusive | inconclusive | PASS | `4fafb840` |
| A-CHK-006-execution-failure | logout_invalidation | fault_injection | execution_error | execution_error | PASS | `78bdc3e9` |
| A-CHK-006-secure | logout_invalidation | live_scan | no_issue_observed | no_issue_observed | PASS | `4fafb840` |
| A-CHK-006-vulnerable | logout_invalidation | live_scan | finding_confirmed | finding_confirmed | PASS | `0ebf7404` |

**Totals:** 24 cases — 24 pass.
