# Formal security-check evaluation (Applications A, B, C)

Generated 2026-09-27 17:57 UTC from ABC-spa-support.

| Case | Check | Mode | Expected | Actual | Verdict | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| A-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `54c20316` |
| A-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `b70ccbda` |
| A-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `54c20316` |
| A-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `9960a4e7` |
| A-CHK-002-ambiguous | registration_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `cf7a81b2` |
| A-CHK-002-execution-failure | registration_enumeration | fault_injection | execution_error | execution_error | PASS | `485f143a` |
| A-CHK-002-secure | registration_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `cf7a81b2` |
| A-CHK-002-vulnerable | registration_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `d8561cbd` |
| A-CHK-003-ambiguous | reset_request_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `f377bc07` |
| A-CHK-003-execution-failure | reset_request_enumeration | fault_injection | execution_error | execution_error | PASS | `d065eca5` |
| A-CHK-003-secure | reset_request_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `f377bc07` |
| A-CHK-003-vulnerable | reset_request_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `312371ec` |
| A-CHK-004-ambiguous | login_throttling | offline_analysis | inconclusive | inconclusive | PASS | `1ee688ff` |
| A-CHK-004-execution-failure | login_throttling | fault_injection | execution_error | execution_error | PASS | `ca7023d4` |
| A-CHK-004-secure | login_throttling | live_scan | no_issue_observed | no_issue_observed | PASS | `1ee688ff` |
| A-CHK-004-vulnerable | login_throttling | live_scan | finding_confirmed | finding_confirmed | PASS | `e0ce7bfe` |
| A-CHK-005-ambiguous | session_fixation | offline_analysis | inconclusive | inconclusive | PASS | `4cebb290` |
| A-CHK-005-execution-failure | session_fixation | fault_injection | execution_error | execution_error | PASS | `2890fd90` |
| A-CHK-005-secure | session_fixation | live_scan | no_issue_observed | no_issue_observed | PASS | `4cebb290` |
| A-CHK-005-vulnerable | session_fixation | live_scan | finding_confirmed | finding_confirmed | PASS | `0b3269fe` |
| A-CHK-006-ambiguous | logout_invalidation | offline_analysis | inconclusive | inconclusive | PASS | `4fca0342` |
| A-CHK-006-execution-failure | logout_invalidation | fault_injection | execution_error | execution_error | PASS | `c2c87888` |
| A-CHK-006-secure | logout_invalidation | live_scan | no_issue_observed | no_issue_observed | PASS | `4fca0342` |
| A-CHK-006-vulnerable | logout_invalidation | live_scan | finding_confirmed | finding_confirmed | PASS | `ac099f78` |
| B-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `b671ce3d` |
| B-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `56b3d0b8` |
| B-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `b671ce3d` |
| B-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `71e1cc14` |
| C-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `1805b317` |
| C-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `a80ac200` |
| C-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `1805b317` |
| C-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `2b6a26d8` |
| C-CHK-004-ambiguous | login_throttling | offline_analysis | inconclusive | inconclusive | PASS | `af3b1d13` |
| C-CHK-004-execution-failure | login_throttling | fault_injection | execution_error | execution_error | PASS | `3f0f4871` |
| C-CHK-004-secure | login_throttling | live_scan | no_issue_observed | no_issue_observed | PASS | `af3b1d13` |
| C-CHK-004-vulnerable | login_throttling | live_scan | finding_confirmed | finding_confirmed | PASS | `eb199c57` |
| C-CHK-005-ambiguous | session_fixation | offline_analysis | inconclusive | inconclusive | PASS | `0e38c69c` |
| C-CHK-005-execution-failure | session_fixation | fault_injection | execution_error | execution_error | PASS | `b64601c4` |
| C-CHK-005-secure | session_fixation | live_scan | no_issue_observed | no_issue_observed | PASS | `0e38c69c` |
| C-CHK-005-vulnerable | session_fixation | live_scan | finding_confirmed | finding_confirmed | PASS | `c3a472fd` |
| C-CHK-006-ambiguous | logout_invalidation | offline_analysis | inconclusive | inconclusive | PASS | `dc1d6986` |
| C-CHK-006-execution-failure | logout_invalidation | fault_injection | execution_error | execution_error | PASS | `492d904c` |
| C-CHK-006-secure | logout_invalidation | live_scan | no_issue_observed | no_issue_observed | PASS | `dc1d6986` |
| C-CHK-006-vulnerable | logout_invalidation | live_scan | finding_confirmed | finding_confirmed | PASS | `5b1c28aa` |

**Totals:** 44 cases — 44 pass.
