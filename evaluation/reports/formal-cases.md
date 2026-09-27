# Formal security-check evaluation (Applications A, B, C)

Generated 2026-09-27 17:01 UTC from ABC-spa-support.

| Case | Check | Mode | Expected | Actual | Verdict | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| A-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `29a75d9c` |
| A-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `5258ab0d` |
| A-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `29a75d9c` |
| A-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `5b53974d` |
| A-CHK-002-ambiguous | registration_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `063f0b72` |
| A-CHK-002-execution-failure | registration_enumeration | fault_injection | execution_error | execution_error | PASS | `1303dcee` |
| A-CHK-002-secure | registration_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `063f0b72` |
| A-CHK-002-vulnerable | registration_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `4c7aeae9` |
| A-CHK-003-ambiguous | reset_request_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `1e5703f4` |
| A-CHK-003-execution-failure | reset_request_enumeration | fault_injection | execution_error | execution_error | PASS | `47fb19c9` |
| A-CHK-003-secure | reset_request_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `1e5703f4` |
| A-CHK-003-vulnerable | reset_request_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `0c8361b9` |
| A-CHK-004-ambiguous | login_throttling | offline_analysis | inconclusive | inconclusive | PASS | `c0c48ffa` |
| A-CHK-004-execution-failure | login_throttling | fault_injection | execution_error | execution_error | PASS | `a04ac0cc` |
| A-CHK-004-secure | login_throttling | live_scan | no_issue_observed | no_issue_observed | PASS | `c0c48ffa` |
| A-CHK-004-vulnerable | login_throttling | live_scan | finding_confirmed | finding_confirmed | PASS | `aa14303d` |
| A-CHK-005-ambiguous | session_fixation | offline_analysis | inconclusive | inconclusive | PASS | `e0f7e0eb` |
| A-CHK-005-execution-failure | session_fixation | fault_injection | execution_error | execution_error | PASS | `7f563240` |
| A-CHK-005-secure | session_fixation | live_scan | no_issue_observed | no_issue_observed | PASS | `e0f7e0eb` |
| A-CHK-005-vulnerable | session_fixation | live_scan | finding_confirmed | finding_confirmed | PASS | `4f324fc1` |
| A-CHK-006-ambiguous | logout_invalidation | offline_analysis | inconclusive | inconclusive | PASS | `e0f434d1` |
| A-CHK-006-execution-failure | logout_invalidation | fault_injection | execution_error | execution_error | PASS | `e36a4a8d` |
| A-CHK-006-secure | logout_invalidation | live_scan | no_issue_observed | no_issue_observed | PASS | `e0f434d1` |
| A-CHK-006-vulnerable | logout_invalidation | live_scan | finding_confirmed | finding_confirmed | PASS | `04580c05` |
| B-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `037dfe4f` |
| B-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `b9cbe05a` |
| B-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `037dfe4f` |
| B-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `c77ad7f0` |
| C-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `037ecf5a` |
| C-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `ca2d2b8c` |
| C-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `037ecf5a` |
| C-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `b178ef0e` |
| C-CHK-004-ambiguous | login_throttling | offline_analysis | inconclusive | inconclusive | PASS | `061ee0f3` |
| C-CHK-004-execution-failure | login_throttling | fault_injection | execution_error | execution_error | PASS | `e17e7ec3` |
| C-CHK-004-secure | login_throttling | live_scan | no_issue_observed | no_issue_observed | PASS | `061ee0f3` |
| C-CHK-004-vulnerable | login_throttling | live_scan | finding_confirmed | finding_confirmed | PASS | `25916bac` |
| C-CHK-005-ambiguous | session_fixation | offline_analysis | inconclusive | inconclusive | PASS | `32b6c4d2` |
| C-CHK-005-execution-failure | session_fixation | fault_injection | execution_error | execution_error | PASS | `3106f14b` |
| C-CHK-005-secure | session_fixation | live_scan | no_issue_observed | no_issue_observed | PASS | `32b6c4d2` |
| C-CHK-005-vulnerable | session_fixation | live_scan | finding_confirmed | finding_confirmed | PASS | `00a789d3` |
| C-CHK-006-ambiguous | logout_invalidation | offline_analysis | inconclusive | inconclusive | PASS | `335d5cda` |
| C-CHK-006-execution-failure | logout_invalidation | fault_injection | execution_error | execution_error | PASS | `9cf316d3` |
| C-CHK-006-secure | logout_invalidation | live_scan | no_issue_observed | no_issue_observed | PASS | `335d5cda` |
| C-CHK-006-vulnerable | logout_invalidation | live_scan | finding_confirmed | finding_confirmed | PASS | `1c95eed4` |

**Totals:** 44 cases — 44 pass.
