# EVA-007 — Offline analysis and reporting

Generated 2026-09-27 17:34 UTC.

No evaluation target was running, no browser was launched, and no AWS
credentials were used. Saved evidence was the only input.

Scan re-analysed: `bc32de5e-f564-4380-8618-b259d5265c7f`

| Check | Result | Detail |
| --- | --- | --- |
| Reanalysis endpoint responds with the target stopped | PASS | HTTP 200 |
| Reanalysis returns one result per stored evidence record | PASS | 1 result(s) returned |
| A new result version is saved and earlier versions are kept | PASS | ['result-v1.json', 'result-v2.json'] then ['result-v1.json', 'result-v2.json', 'result-v3.json'] |
| Offline reanalysis reproduces the original outcome | PASS | {'registration_enumeration': 'finding_confirmed'} then {'registration_enumeration': 'finding_confirmed'} |
| The JSON report regenerates offline | PASS | HTTP 200, 23292 bytes |
| The HTML report regenerates offline | PASS | HTTP 200, 2013 bytes |

**Totals:** 6 of 6 checks passed.
