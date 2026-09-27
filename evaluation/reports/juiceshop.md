# OWASP Juice Shop evaluation

**Prepared by Member 5, 27 September 2026.** Branch `feature/spa-support`.

Juice Shop is a widely used, deliberately vulnerable Angular application. It was
never shown to the discovery implementation, which makes it a fair test of
whether AuthFlowGuard generalises beyond the three purpose-built targets.

## Summary

| | `main` | This branch |
| --- | --- | --- |
| Scans that ran their security check | **0 of 6** | **6 of 6** |
| Correct outcomes | 0 of 6 | **2 of 6** |
| Real vulnerabilities detected | 0 of 4 | **1 of 4** (no login throttling) |
| Vulnerabilities reported as "no issue" (false pass) | 0 | **0** |

On `main`, every scan failed before any security check ran. This branch fixes
the four platform defects responsible, and every scan now reaches its check.
The four remaining cases stop with `execution_error` for known, specific
reasons (below). None is reported as a pass: the safety property the project
depends on held throughout.

## Setup

Reproducible on any machine with Docker:

```powershell
docker run -d --name authflowguard-juiceshop -e NODE_ENV=quiet `
  -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.2.0

python -m authflowguard.evaluation.case_runner `
  --cases evaluation/cases/juiceshop_cases.json --application J --run-id my-run
```

- **Pinned to v20.2.0** (digest `sha256:73c53fbf…430e`) so results are comparable.
- **Bound to 127.0.0.1 only.** Juice Shop is intentionally vulnerable and must
  not be reachable from a campus or home network.
- **`quiet` profile.** Official Juice Shop configuration that changes
  presentation only: welcome banner, challenge-solved pop-ups, hints and the
  tutorial. It touches no authentication or session behaviour, and the ground
  truth below was re-verified under it with identical results. Without it,
  pop-ups appear mid-scan and change the page's controls.

## Ground truth

Established by probing Juice Shop directly with `curl` and a plain browser,
**before** AuthFlowGuard was run, so that expected outcomes come from the
application rather than from the tool being evaluated.

| Check | Observed behaviour | Truth |
| --- | --- | --- |
| CHK-001 login enumeration | Known and unknown email both return `401 "Invalid email or password."` | Secure |
| CHK-002 registration enumeration | Existing email → `400 "email must be unique"`; new email → `201` | **Vulnerable** |
| CHK-003 reset-request enumeration | Known email → its security question; unknown → `{}` | **Vulnerable** |
| CHK-004 login throttling | Six wrong passwords, then the correct one → `200` | **Vulnerable** |
| CHK-005 session fixation | No session cookie exists before login; a new JWT is issued at login | Secure |
| CHK-006 logout invalidation | Logout sends no request; the old token cookie still opens `/profile` | **Vulnerable** |

## Results

| Case | Truth | `main` | This branch | Why |
| --- | --- | --- | --- | --- |
| J-CHK-001 | Secure | Scan failed | **`no_issue_observed` ✓** | |
| J-CHK-002 | Vulnerable | Scan failed | `execution_error` | Needs a native HTML form (limit A) |
| J-CHK-003 | Vulnerable | Scan failed | `execution_error` | Needs a native HTML form (limit A) |
| J-CHK-004 | Vulnerable | Scan failed | **`finding_confirmed` ✓** | |
| J-CHK-005 | Secure | Scan failed | `execution_error` | Anonymous control returns `500` (limit B) |
| J-CHK-006 | Vulnerable | Scan failed | `execution_error` | Logout is a menu button, not a form (limits B, C) |

Runs: `evaluation/results/J-baseline-main` and `evaluation/results/J-spa-support`.
Automatic discovery paused on all six; each continued through the guided
fallback.

## Defects fixed on this branch

Each was isolated by reproducing it directly, confirmed by removing it in
memory, then fixed with a test that fails on the old code.

### 1. Guided flows lost hash routes — `authentication.py`, `evidence.py`

Navigate steps were stripped of their query **and fragment before execution**,
and again when a profile was saved.

```
input : http://127.0.0.1:3000/#/login
saved : http://127.0.0.1:3000/
```

On a hash-routed app the fragment *is* the route, so the replay opened the
product listing, and positional control references then pointed at unrelated
elements (the username fill targeted an "Add to Basket" button).

**Fix:** `scope.url_without_query_keeping_route` keeps a fragment only when it
looks like a route: starts with `/`, at most six short lowercase segments with
at most two digits each. Anything else — `#access_token=…`, `#/reset?token=…`,
`#/reset/<hex or base64 token>` — is still stripped. Queries are always
stripped.

### 2. Reading page controls raced the page — `playwright_worker.py`

`read_controls` counted the controls, then read each with separate calls. When
the app re-rendered mid-loop, a counted element vanished and Playwright waited
its full 30-second timeout. **Fix:** one atomic `page.evaluate` snapshot, the
approach `action_executor.py` already used for its own page snapshots.

### 3. Actions ran before the app was ready — `action_executor.py`, session checks

- Navigation waited only for `domcontentloaded`, before Angular had built the
  form, so fills landed on nothing and the Login button stayed disabled.
- A click returned before the background login request it started had
  finished, so the session cookie was not yet set when the protected page was
  opened.

**Fix:** new `page_settling.py`. Navigations, clicks and key presses wait for
the background (`fetch`/`xhr`) requests *they* started to finish, followed by
a 100 ms quiet window, capped at 5 s. Navigation also waits for `load` rather
than `domcontentloaded`. Server-rendered pages make no background requests, so
they pay only the quiet window. The session checks' own page loads use the
same helper.

A first version waited for general network quiet (`networkidle`) after every
navigation. It fixed Juice Shop but doubled live-scan time on Applications A
and C, so it was replaced before this branch was proposed.

### 4. Scan failures recorded no cause — `scan_manager.py`

`_finalize_failed` discarded the exception, so every Juice Shop failure read
only "Scan execution failed". **Fix:** the public error now includes the
exception *type* (e.g. `Scan execution failed (TimeoutError)`), which is safe;
the message, which could contain secrets, is still withheld.

## Remaining limits

These are feature gaps and target properties, not defects, and each fails
safely as `execution_error`.

**A. Registration and reset checks need native HTML forms (CHK-002, CHK-003).**
`form_enumeration.py` submits a `<form method="post">` and waits for the page
navigation. Juice Shop's screens send JSON in the background, its registration
needs a security-question dropdown, and its reset form reveals the result
*while the email is typed*. Supporting this needs a new interaction model that
observes background responses; it is feature work, estimated at 3–5 hours
with uncertain results, and was out of scope before submission.

**B. Juice Shop's only cookie-protected page returns `500` when signed out
(CHK-005, CHK-006).** Every other Juice Shop endpoint authenticates with an
`Authorization` header, which these checks deliberately do not replay (a
documented limitation). `/profile` accepts the cookie but answers anonymous
visitors with `500 "Blocked illegal activity"` rather than `401`. Both
analysers treat any `5xx` as `execution_error`, because a server error cannot
be distinguished from a rejected session. That rule was left unchanged:
loosening it to make these rows pass would risk false passes elsewhere. Note
that on this branch CHK-005 logged in, captured the sessions and completed all
three controls; only the verdict was withheld.

**C. Logout must be a form that sends a request (CHK-006).** The check looks for
a logout `<form>` and records the server's response. Juice Shop logs out from
a menu button and sends no request at all; the vulnerability *is* that logout
happens only in the browser. Representing that needs a change to the check's
model, not just its button-finding.

**Recommendation, not yet implemented.** Guided replays fill controls by
position. If a page's layout differs from when the flow was recorded, a
credential could be typed into an unrelated field. Checking that a fill's
target still matches the recorded control description before typing a secret
would close this.

## Regression

Full backend suite: 291 passed; `ruff`, `ruff format --check` and `mypy` clean.
New tests fail on the old code and pass on the new:

- hash routes kept, token-like fragments stripped (`test_scope.py`,
  `test_authentication.py`, `test_evidence_reports.py`)
- consistent control reads while the page re-renders (`test_playwright_worker.py`)
- sign-in on a client-rendered page with a delayed background login
  (`test_action_executor.py`)
- failure type recorded (`test_scan_lifecycle.py`)

Formal cases on Applications A, B and C: see run `ABC-spa-support`, compared
below with the submitted results.

| Application | Submitted results (`formal-cases.md`) | This branch | Average live scan, same machine (`main` → branch) |
| --- | --- | --- | --- |
| A | 24 / 24 pass | 24 / 24 pass | 5.1 s → 5.8 s |
| B | 1 pass, 2 fail, 1 blocked | 1 pass, 3 fail | — |
| C | 16 / 16 pass | 16 / 16 pass | 8.9 s → 9.4 s |

No verdict on A or C changed. The one change on B is an improvement:
`B-CHK-001-vulnerable` was blocked because the guided fallback observed the
React page before its form had rendered (4 controls). It now observes the full
form, logs in, and stops at the same enumeration error that `B-CHK-001-secure`
already reported on `main`. That error is separate from this work and was not
investigated here.

Timings were measured by running `main` and this branch back to back on the
same machine; the submitted runs were recorded on a different machine and are
not comparable for time.

## Harness changes

In `authflowguard.evaluation.case_runner`, which is evaluation code rather than
product code:

- External targets: an application that runs as its own process, checked for
  reachability and never started or stopped by the runner.
- `{run}` in case setup values is replaced per run, so a registration case stays
  repeatable against a long-lived container.
- The guided fallback took the first button on the page as the submit control.
  On Juice Shop that is a cookie-banner link. It now prefers a submit button
  with a login-like label, verified against Juice Shop and Application C.
