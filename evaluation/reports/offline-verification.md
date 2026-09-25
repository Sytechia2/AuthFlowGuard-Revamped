# EVA-007 — Offline analysis and reporting

Generated 2026-09-22 18:32 UTC.

No evaluation target was running, no browser was launched, and no AWS
credentials were used. Saved evidence was the only input.

Scan re-analysed: `9320c3f7-1b9e-46a5-a8c7-dfe14140288c`

| Check | Result | Detail |
| --- | --- | --- |
| Reanalysis endpoint responds with the target stopped | PASS | HTTP 200 |
| Reanalysis returns one result per stored evidence record | PASS | 1 result(s) returned |
| A new result version is saved and earlier versions are kept | PASS | ['result-v1.json'] then ['result-v1.json', 'result-v2.json'] |
| Offline reanalysis reproduces the original outcome | PASS | {'logout_invalidation': 'no_issue_observed'} then {'logout_invalidation': 'no_issue_observed'} |
| The JSON report regenerates offline | PASS | HTTP 200, 5203 bytes |
| The HTML report regenerates offline | PASS | HTTP 200, 1066 bytes |

**Totals:** 6 of 6 checks passed.
