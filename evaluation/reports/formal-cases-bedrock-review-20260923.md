# Formal security-check evaluation

Generated 2026-09-23 09:12 UTC from bedrock-review-20260923.

| Case | Check | Mode | Expected | Actual | Verdict | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| A-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `7b130231` |
| A-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `55fb144b` |
| A-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `7b130231` |
| A-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `98e9e413` |
| A-CHK-002-ambiguous | registration_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `6663024a` |
| A-CHK-002-execution-failure | registration_enumeration | fault_injection | execution_error | execution_error | PASS | `2288a21c` |
| A-CHK-002-secure | registration_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `6663024a` |
| A-CHK-002-vulnerable | registration_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `db6c5587` |
| A-CHK-003-ambiguous | reset_request_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `ac7ccdc5` |
| A-CHK-003-execution-failure | reset_request_enumeration | fault_injection | execution_error | execution_error | PASS | `f9167a2c` |
| A-CHK-003-secure | reset_request_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `ac7ccdc5` |
| A-CHK-003-vulnerable | reset_request_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `a89d22cd` |
| A-CHK-004-ambiguous | login_throttling | offline_analysis | inconclusive | inconclusive | PASS | `e591abc4` |
| A-CHK-004-execution-failure | login_throttling | fault_injection | execution_error | execution_error | PASS | `ea46597d` |
| A-CHK-004-secure | login_throttling | live_scan | no_issue_observed | no_issue_observed | PASS | `e591abc4` |
| A-CHK-004-vulnerable | login_throttling | live_scan | finding_confirmed | finding_confirmed | PASS | `20ada7fe` |
| A-CHK-005-ambiguous | session_fixation | offline_analysis | inconclusive | inconclusive | PASS | `e51b6468` |
| A-CHK-005-execution-failure | session_fixation | fault_injection | execution_error | execution_error | PASS | `60645bce` |
| A-CHK-005-secure | session_fixation | live_scan | no_issue_observed | no_issue_observed | PASS | `e51b6468` |
| A-CHK-005-vulnerable | session_fixation | live_scan | finding_confirmed | finding_confirmed | PASS | `4f9a038e` |
| A-CHK-006-ambiguous | logout_invalidation | offline_analysis | inconclusive | inconclusive | PASS | `916b9dd5` |
| A-CHK-006-execution-failure | logout_invalidation | fault_injection | execution_error | execution_error | PASS | `a83bf0e2` |
| A-CHK-006-secure | logout_invalidation | live_scan | no_issue_observed | no_issue_observed | PASS | `916b9dd5` |
| A-CHK-006-vulnerable | logout_invalidation | live_scan | finding_confirmed | finding_confirmed | PASS | `cb409beb` |
| B-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | execution_error | FAIL | `53cc3011` |
| B-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `5cf156fa` |
| B-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | execution_error | FAIL | `53cc3011` |
| B-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | execution_error | FAIL | `876fe11a` |
| C-CHK-001-ambiguous | login_enumeration | offline_analysis | inconclusive | inconclusive | PASS | `f1d32d01` |
| C-CHK-001-execution-failure | login_enumeration | fault_injection | execution_error | execution_error | PASS | `b0db671f` |
| C-CHK-001-secure | login_enumeration | live_scan | no_issue_observed | no_issue_observed | PASS | `f1d32d01` |
| C-CHK-001-vulnerable | login_enumeration | live_scan | finding_confirmed | finding_confirmed | PASS | `085c2ce6` |
| C-CHK-004-ambiguous | login_throttling | offline_analysis | inconclusive | inconclusive | PASS | `1d7d7a27` |
| C-CHK-004-execution-failure | login_throttling | fault_injection | execution_error | execution_error | PASS | `404b9d9c` |
| C-CHK-004-secure | login_throttling | live_scan | no_issue_observed | no_issue_observed | PASS | `1d7d7a27` |
| C-CHK-004-vulnerable | login_throttling | live_scan | finding_confirmed | finding_confirmed | PASS | `3a63e5f8` |
| C-CHK-005-ambiguous | session_fixation | offline_analysis | inconclusive | inconclusive | PASS | `ab51c006` |
| C-CHK-005-execution-failure | session_fixation | fault_injection | execution_error | execution_error | PASS | `57d43f20` |
| C-CHK-005-secure | session_fixation | live_scan | no_issue_observed | no_issue_observed | PASS | `ab51c006` |
| C-CHK-005-vulnerable | session_fixation | live_scan | finding_confirmed | finding_confirmed | PASS | `c2aadc9d` |
| C-CHK-006-ambiguous | logout_invalidation | offline_analysis | inconclusive | inconclusive | PASS | `63775ea2` |
| C-CHK-006-execution-failure | logout_invalidation | fault_injection | execution_error | execution_error | PASS | `2da66a86` |
| C-CHK-006-secure | logout_invalidation | live_scan | no_issue_observed | no_issue_observed | PASS | `63775ea2` |
| C-CHK-006-vulnerable | logout_invalidation | live_scan | finding_confirmed | finding_confirmed | PASS | `752ddfbe` |

**Totals:** 44 cases — 3 fail, 41 pass.
