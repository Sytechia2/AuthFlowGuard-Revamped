# OWASP Juice Shop evaluation

**Prepared by Member 5, 27 September 2026.** Branch `evaluation/juiceshop`.

Juice Shop is a widely used, deliberately vulnerable Angular application. It was
never shown to the discovery implementation, which makes it a fair test of
whether AuthFlowGuard generalises beyond the three purpose-built targets.

## Summary

| | Result |
| --- | --- |
| Scans completed on current `main` | **0 of 6** — every scan fails before any security check runs |
| Real vulnerabilities in Juice Shop, verified independently | **4 of 6** checks |
| Vulnerabilities AuthFlowGuard reported as "no issue" | **0** — no false pass |
| Vulnerabilities AuthFlowGuard detected | **0** |
| Product defects found | **4**, each with file, line and evidence below |
| With three of them fixed in memory | 5 of 6 scans log in and pass login proof; every check then reports `execution_error` |

The safety property the project depends on held throughout: a failed or
unsupported test was never reported as a security pass. But on a real
single-page application, AuthFlowGuard currently tests nothing.

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

| Case | Truth | `main` | With fixes 1–3 in memory |
| --- | --- | --- | --- |
| J-CHK-001 | Secure | Scan failed | Scan failed |
| J-CHK-002 | Vulnerable | Scan failed | `execution_error` |
| J-CHK-003 | Vulnerable | Scan failed | `execution_error` |
| J-CHK-004 | Vulnerable | Scan failed | `execution_error` |
| J-CHK-005 | Secure | Scan failed | `execution_error` |
| J-CHK-006 | Vulnerable | Scan failed | `execution_error` |

Automatic discovery paused on all six; each continued through the guided
fallback.

## Defects found

Each was isolated by reproducing it directly, then confirmed by removing it in
memory and observing the next failure. No product file was changed.

### 1. Guided flows lose hash routes — `authentication.py:128`

`_sanitize_recorded_action` strips the query and fragment from every navigate
step **before the step is executed**, not only before it is stored.

```
input : http://127.0.0.1:3000/#/login
saved : http://127.0.0.1:3000/
```

On a hash-routed application the fragment is the route, so the replay opens the
product listing instead of the login page. Positional control references
recorded on the login page then resolve to unrelated elements: the username
fill was aimed at an "Add to Basket" button.

The stripping is well motivated — fragments can carry tokens, as in OAuth's
`#access_token=` — so the fix is to keep route-like fragments (`#/login`) and
still strip anything containing `=`, `&` or `?`.

**Secret-handling risk.** Because a fill targets whatever element occupies the
recorded position, a replay on the wrong page can type a credential into an
unrelated field. Here it hit a button and failed safely; Juice Shop's product
page also has a search box. Checking that a fill's target still matches the
observed control before typing a secret would close this.

### 2. Reading page controls races the page — `playwright_worker.py:182`

`read_controls` counts the controls once, then fetches each with a separate
call. When a single-page application re-renders mid-loop, a counted element
disappears and Playwright waits the full 30 seconds for it before failing the
scan. `action_executor.py:275` already solved this with one atomic
`page.evaluate` snapshot; `read_controls` never received the same fix.

### 3. Actions run before the application is ready — `action_executor.py:398`

Two related problems with JavaScript applications:

- **Navigate waits only for `domcontentloaded`.** Angular has not started at
  that point, so the fills land before the form exists in Angular's model. The
  form initialises empty and the Login button stays disabled; the click then
  times out. Waiting for `load` succeeded 4 of 4 times.
- **A click does not wait for the requests it starts.** Juice Shop logs in with
  a background request and sets its session cookie on the response. Opening
  the protected page immediately afterwards found no cookie 3 of 3 times. A
  bounded wait for the click's own in-flight requests fixes it. Note that
  `wait_for_load_state("networkidle")` does not help here: it returns at once
  if the page was already idle.

### 4. Scan failures record no cause — `scan_manager.py:1703`

`_finalize_failed` receives the exception and discards it entirely. Hiding the
message is right, since it could contain secrets, but the earlier code recorded
the exception type, which is safe and is what made failures diagnosable. Every
Juice Shop failure appeared only as "Scan execution failed"; diagnosing them
required running scans in-process with a hook.

## What remains after fixes 1–3

With the three fixes applied in memory, five scans log in and pass the
authenticated/anonymous proof. Every check then stops:

| Check | Stopped at | Reason |
| --- | --- | --- |
| CHK-002, CHK-003 | Finding the form | Runner requires a native HTML `POST` form; Juice Shop's screens send JSON |
| CHK-004, CHK-005, CHK-006 | Replaying the login | Runner waits for a form-submission navigation that never happens |

All six runners assume server-rendered forms. Supporting single-page
applications is feature work in each runner, and is recorded here as the main
limitation on generality.

## Harness changes made

In `authflowguard.evaluation.case_runner`, which is evaluation code rather than
product code:

- External targets: an application that runs as its own process, checked for
  reachability and never started or stopped by the runner.
- `{run}` in case setup values is replaced per run, so a registration case stays
  repeatable against a long-lived container.
- The guided fallback took the first button on the page as the submit control.
  On Juice Shop that is a cookie-banner link. It now prefers a submit button
  with a login-like label, verified against Juice Shop and Application C.
