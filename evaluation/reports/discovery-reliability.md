# EVA-004 — Login discovery reliability (Rule-based)

Generated 2026-09-27 17:37 UTC.

Each application's login flow was attempted 5 times, each against a freshly started fixture.

These scans used rule-based discovery, the default, which makes no AWS
calls. Bedrock discovery is also available to web scans, but is **not**
measured here: that needs AWS credentials and billable model calls.

## Summary

| Application | Automatic | Guided | Failed | Meets 4/5 automatic target |
| --- | --- | --- | --- | --- |
| A | 4/5 | 0/5 | 1/5 | Yes |
| B | 5/5 | 0/5 | 0/5 | Yes |
| C | 0/5 | 5/5 | 0/5 | No |

The 4-of-5 automatic target comes from the project plan and applies to
the development applications. Application C was designed independently,
so a guided completion there is an expected outcome, not a regression.

## Every attempt

| Application | Attempt | Route | Duration (s) | Detail |
| --- | --- | --- | --- | --- |
| A | 1 | automatic | 6.78 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| A | 2 | automatic | 6.89 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| A | 3 | failed | 180.05 | The scan raised before finishing: TimeoutError() |
| A | 4 | automatic | 6.95 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| A | 5 | automatic | 6.92 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| B | 1 | automatic | 8.84 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| B | 2 | automatic | 8.59 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| B | 3 | automatic | 8.78 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| B | 4 | automatic | 8.81 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| B | 5 | automatic | 8.93 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| C | 1 | guided | 10.33 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
| C | 2 | guided | 10.42 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
| C | 3 | guided | 10.61 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
| C | 4 | guided | 10.07 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
| C | 5 | guided | 10.76 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
