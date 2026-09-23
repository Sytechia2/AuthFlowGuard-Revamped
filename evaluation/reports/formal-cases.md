# Formal security-check evaluation (Applications A, B, C)

Generated 2026-09-22 19:04 UTC from A-fault-001, A-live-001, A-offline-001, B-001, C-002.

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
| B-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | execution_error | FAIL | `f2208df7` |
| B-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `59d0081c` |
| B-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | execution_error | FAIL | `f2208df7` |
| B-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | None | BLOCKED | `-` |
| C-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `84fc54c6` |
| C-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `97f9f893` |
| C-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `84fc54c6` |
| C-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `b3eb5ad0` |
| C-CHK-004-ambiguous | login_throttling | offline_analysis | inconclusive | inconclusive | PASS | `b6d16d77` |
| C-CHK-004-execution-failure | login_throttling | fault_injection | execution_error | execution_error | PASS | `04f587fd` |
| C-CHK-004-secure | login_throttling | live_scan | no_issue_observed | no_issue_observed | PASS | `b6d16d77` |
| C-CHK-004-vulnerable | login_throttling | live_scan | finding_confirmed | finding_confirmed | PASS | `ff50021d` |
| C-CHK-005-ambiguous | session_fixation | offline_analysis | inconclusive | inconclusive | PASS | `7ffeeff8` |
| C-CHK-005-execution-failure | session_fixation | fault_injection | execution_error | execution_error | PASS | `546fc0a6` |
| C-CHK-005-secure | session_fixation | live_scan | no_issue_observed | no_issue_observed | PASS | `7ffeeff8` |
| C-CHK-005-vulnerable | session_fixation | live_scan | finding_confirmed | finding_confirmed | PASS | `d6ec3ab9` |
| C-CHK-006-ambiguous | logout_invalidation | offline_analysis | inconclusive | inconclusive | PASS | `84f180a4` |
| C-CHK-006-execution-failure | logout_invalidation | fault_injection | execution_error | execution_error | PASS | `8c78e1bb` |
| C-CHK-006-secure | logout_invalidation | live_scan | no_issue_observed | no_issue_observed | PASS | `84f180a4` |
| C-CHK-006-vulnerable | logout_invalidation | live_scan | finding_confirmed | finding_confirmed | PASS | `52d34e26` |

**Totals:** 44 cases — 1 blocked, 2 fail, 41 pass.
