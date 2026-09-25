# EVA-004 — Login discovery reliability

Generated 2026-09-22 19:21 UTC.

Each application's login flow was attempted 5 times, each against a freshly started fixture.

Discovery in a scan started from the web interface is rule-based and does
not call Bedrock, so these figures need no AWS access. They do **not**
measure the terminal Bedrock agent, which stays unmeasured.

## Summary

| Application | Automatic | Guided | Failed | Meets 4/5 automatic target |
| --- | --- | --- | --- | --- |
| A | 5/5 | 0/5 | 0/5 | Yes |
| B | 2/5 | 0/5 | 3/5 | No |
| C | 0/5 | 5/5 | 0/5 | No |

The 4-of-5 automatic target comes from the project plan and applies to
the development applications. Application C was designed independently,
so a guided completion there is an expected outcome, not a regression.

## Every attempt

| Application | Attempt | Route | Duration (s) | Detail |
| --- | --- | --- | --- | --- |
| A | 1 | automatic | 4.79 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| A | 2 | automatic | 4.80 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| A | 3 | automatic | 4.77 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| A | 4 | automatic | 4.71 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| A | 5 | automatic | 4.76 | No observable page, title, URL, or control-state difference was found across the three paired comparisons. |
| B | 1 | failed | 4.08 | Guided fallback could not identify a username, password and submit control among 4 observed controls. |
| B | 2 | automatic | 0.89 | The scan finished in state failed with no result for login_enumeration. Scan error: Error |
| B | 3 | failed | 4.00 | Guided fallback could not identify a username, password and submit control among 4 observed controls. |
| B | 4 | automatic | 94.49 | One or more login enumeration attempts failed before comparison. |
| B | 5 | failed | 3.96 | Guided fallback could not identify a username, password and submit control among 4 observed controls. |
| C | 1 | guided | 6.23 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
| C | 2 | guided | 6.27 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
| C | 3 | guided | 6.22 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
| C | 4 | guided | 6.14 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
| C | 5 | guided | 6.12 | Automatic discovery paused; completed through the guided fallback. No observable page, title, URL, or control-state difference was found across the three paired |
