# OWASP Juice Shop evaluation

**Prepared by Member 5, 27 September 2026.** Branch `feature/spa-support`.

Juice Shop is a widely used, deliberately vulnerable Angular application. It was
never shown to the discovery implementation, which makes it a fair test of
whether AuthFlowGuard generalises beyond the three purpose-built targets.

## Summary

| | `main` | This branch |
| --- | --- | --- |
| Scans that ran their security check | **0 of 6** | **6 of 6** |
| Correct outcomes | 0 of 6 | **6 of 6** |
| Real vulnerabilities detected | 0 of 4 | **4 of 4** |
| Secure behaviours correctly reported secure | 0 of 2 | **2 of 2** |
| False passes | 0 | **0** |

On `main`, every scan failed before any security check ran. This branch fixes
the four platform defects responsible and extends three checks to handle how
single-page applications work. Every verdict now matches ground truth that was
established independently, before the tool was run.

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

| Case | Truth | `main` | This branch | How the branch reached it |
| --- | --- | --- | --- | --- |
| J-CHK-001 | Secure | Scan failed | **`no_issue_observed` ✓** | Defects 1–3 fixed |
| J-CHK-002 | Vulnerable | Scan failed | **`finding_confirmed` ✓** | Client-rendered forms (7) |
| J-CHK-003 | Vulnerable | Scan failed | **`finding_confirmed` ✓** | Client-rendered forms (7) |
| J-CHK-004 | Vulnerable | Scan failed | **`finding_confirmed` ✓** | Defects 1–3 fixed |
| J-CHK-005 | Secure | Scan failed | **`no_issue_observed` ✓** | Signed-out baseline (5) |
| J-CHK-006 | Vulnerable | Scan failed | **`finding_confirmed` ✓** | Signed-out baseline (5), menu logout (6) |

Runs: `evaluation/results/J-baseline-main` and `evaluation/results/J-spa-support`.
Automatic discovery paused on all six; each continued through the guided
fallback.

## Defects fixed

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
they pay only the quiet window.

A first version waited for general network quiet (`networkidle`) after every
navigation. It fixed Juice Shop but doubled live-scan time on Applications A
and C, so it was replaced before this branch was proposed.

### 4. Scan failures recorded no cause — `scan_manager.py`

`_finalize_failed` discarded the exception, so every Juice Shop failure read
only "Scan execution failed". **Fix:** the public error now includes the
exception *type* (e.g. `Scan execution failed (TimeoutError)`), which is safe;
the message, which could contain secrets, is still withheld.

## Checks extended

These change how checks reach verdicts, so each was designed to keep the
project's rule that an unexercised or failed test is never reported as a pass,
and each is covered by tests of both the new verdicts and the cases that must
stay inconclusive or errors.

### 5. Session replays judged against the signed-out baseline — CHK-005, CHK-006

Both analysers treated any `5xx` as a failed procedure. Juice Shop's only
cookie-protected page, `/profile`, answers **every** signed-out visitor with
`500 "Blocked illegal activity"`, so neither check could reach a verdict.

A server error now counts as a failure only when it **differs** from the
anonymous control. When the replay receives exactly what a signed-out visitor
receives, that is how this application rejects unauthenticated requests. A
replay that shows the account marker proves authentication regardless of the
anonymous status. Kept as errors: a `5xx` on the authenticated control, a
`5xx` on the replay only (`A-CHK-005-execution-failure`), and differing server
errors.

### 6. Logout through an account menu — CHK-006

The check needed a logout `<form>`. When there is none, it now looks for a
visible control labelled "log out" / "sign out", opening up to three
account-menu toggles to find one, and clicks it. It records whether the click
sent any logout request.

A logout that sends **no request** is accepted as performed only when the
runner positively recorded it and the page was then signed out. Evidence that
merely lacks a logout status still yields `inconclusive`, as
`A-CHK-006-ambiguous` requires. On Juice Shop the result explains the finding:
logout only cleared the browser, and the server still accepted the session.

### 7. Client-rendered registration and reset forms — CHK-002, CHK-003

The check needed a `<form method="post">` that loads a new page. Juice Shop's
reset page has no form at all: about one second after the email is typed, it
looks the email up in the background and, for a real account, unlocks the
answer field with that account's security question. Its registration page
submits JSON and needs a custom (non-native) dropdown.

When there is no native POST form, the check now:

1. enters the identifier and waits up to 2 s for background requests that
   **carry that identifier** (unrelated traffic is ignored), then records the
   page's reaction;
2. for registration only, fills the rest of the form with disposable values,
   opens custom dropdowns from the keyboard, and submits;
3. never submits a reset form, since completing one could change a real
   account's password.

Only hashes are stored. JSON bodies keep their keys and text, but every
number becomes a placeholder, because record ids differ between any two
requests.

Two safeguards stop an unexercised form from reading as secure: a
registration whose disposable account was **not accepted** is `inconclusive`,
and a reset page that **did not react** to either identifier is
`inconclusive`.

**Null control.** Each check was also run against Juice Shop with two
different non-existent emails, where a correct tool must find no difference.
Both reported no difference. The first version failed this for registration,
because each new account returned a new id; that led to the number
normalization above.

## Remaining limits

- **Bearer tokens are not replayed.** Session checks replay browser cookies
  only. Most Juice Shop endpoints authenticate with an `Authorization` header;
  the cases use `/profile`, the one cookie-protected page.
- **Reset forms are compared before submission only** in client-rendered mode.
  An app that leaks only after a full reset submission would read as secure
  for this check.
- **Menu logout depends on labels.** A logout control without "log out" or
  "sign out" in its text, `aria-label`, title or id is not found; the check
  then reports `execution_error`, not a pass.
- **Registration may create the disposable account**, as the native path
  already documents; `{run}` keeps the case repeatable.
- **Numeric-only differences in background responses are not detected**, a
  consequence of normalizing record ids. Differences in keys, text, status or
  page state still are.
- **Recommendation, not yet implemented.** Guided replays fill controls by
  position. If a page's layout differs from when the flow was recorded, a
  credential could be typed into an unrelated field. Checking that a fill's
  target still matches the recorded control description before typing a
  secret would close this.

## Regression

Full backend suite: 311 passed; `ruff`, `ruff format --check` and `mypy` clean.
Every change has tests that fail on the old code, including tests for the
cases that must stay `inconclusive` or `execution_error`, and a secure
single-page app that must come back clean.

Formal cases on Applications A, B and C (run `ABC-spa-support`), compared with
the submitted results:

| Application | Submitted results (`formal-cases.md`) | This branch | Average live scan, same machine (`main` → branch) |
| --- | --- | --- | --- |
| A | 24 / 24 pass | 24 / 24 pass | 5.1 s → 5.6 s |
| B | 1 pass, 2 fail, 1 blocked | 1 pass, 3 fail | — |
| C | 16 / 16 pass | 16 / 16 pass | 8.9 s → 9.1 s |

No verdict on A or C changed. The one change on B is an improvement:
`B-CHK-001-vulnerable` was blocked because the guided fallback observed the
React page before its form had rendered (4 controls). It now observes the full
form, logs in, and stops at the same enumeration error that `B-CHK-001-secure`
already reported on `main`. That error is separate from this work and was not
investigated here.

Timings were measured by running `main` and this branch on the same machine;
the submitted runs were recorded on a different machine and are not
comparable for time.

## Harness changes

In `authflowguard.evaluation.case_runner`, which is evaluation code rather than
product code:

- External targets: an application that runs as its own process, checked for
  reachability and never started or stopped by the runner.
- `{run}` in case setup values is replaced per run, so a registration case stays
  repeatable against a long-lived container.
- Optional `registration_url` / `reset_request_url` in case setup are passed to
  the scan, as the product API already allows. J-CHK-002 uses it because Juice
  Shop's registration link reads "Not yet a customer?"; matching that wording
  would overfit. J-CHK-003 finds its form from the login page's link.
- The guided fallback took the first button on the page as the submit control.
  On Juice Shop that is a cookie-banner link. It now prefers a submit button
  with a login-like label, verified against Juice Shop and Application C.
- Results record the case file actually used.
