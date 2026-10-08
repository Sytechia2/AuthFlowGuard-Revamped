# Local Development

AuthFlowGuard AI runs entirely on the developer's computer. During development,
run the Python backend and React interface in separate terminals.

For diagrams of the current backend and a walkthrough of a scan, read
[ARCHITECTURE.md](ARCHITECTURE.md). It also explains the separate command-line
Bedrock agent and which connections remain to be implemented.

## 1. Backend

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m playwright install chromium
.\.venv\Scripts\python -m uvicorn authflowguard.app:app --app-dir backend --port 8080 --reload
```

The backend is available at `http://127.0.0.1:8080`. Its health endpoint is
`http://127.0.0.1:8080/api/health`.

## 2. Interface

From a second terminal:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

Open `http://127.0.0.1:5173`. Vite forwards `/api` requests to the local
backend, and the lower-left status indicator shows whether the connection is
working.

To open the interface from another computer on the same network, start it
with `npm.cmd run dev:lan` instead and browse to `http://<this-computer's-IP>:5173`
(`ipconfig` shows the IPv4 address). The backend stays on `127.0.0.1`; only the
interface listens on the network and forwards API calls locally. Windows
Firewall must allow inbound TCP 5173 on a Private network, for example from an
administrator PowerShell:

```powershell
New-NetFirewallRule -DisplayName "AuthFlowGuard interface 5173" -Direction Inbound -Protocol TCP -LocalPort 5173 -Action Allow -Profile Private
```

AuthFlowGuard has no sign-in of its own: anyone who can reach this address can
read results, start scans from this computer, and delete scans. Use it only on
a trusted network, or limit the rule with `-RemoteAddress <other-computer-IP>`.
Remove it afterwards with
`Remove-NetFirewallRule -DisplayName "AuthFlowGuard interface 5173"`.

## 3. Verification

Run the backend tests from the repository root:

```powershell
.\.venv\Scripts\python -m pytest
```

Run the interface behavior tests and build it from `frontend`:

```powershell
npm.cmd test
npm.cmd run build
```

These suites cover the implemented foundation, guided discovery, authentication
proof, scan lifecycle, the login-enumeration slice, reporting, and cancellation.
They do not establish support for the not-yet-implemented authentication styles
or security checks listed in the execution plan.

## 4. Code Quality

Check Python formatting, linting, and types from the repository root:

```powershell
.\.venv\Scripts\python -m ruff format --check backend
.\.venv\Scripts\python -m ruff check backend
.\.venv\Scripts\python -m mypy
```

Check frontend formatting, linting, types, tests, and the production build from
`frontend`:

```powershell
npm.cmd run check
```

To apply standard formatting while editing, run:

```powershell
.\.venv\Scripts\python -m ruff format backend
cd frontend
npm.cmd run format
```

After a frontend build, FastAPI serves `frontend/dist` at
`http://127.0.0.1:8080` as the packaged local interface.

## 5. Bedrock Smoke Test

Sign in with the named development profile before running the test:

```powershell
aws login --profile authflowguard-dev --region us-east-1
```

The smoke command makes one live, billable request. It requires an explicit
confirmation flag and reserves a maximum estimated cost before contacting AWS:

```powershell
.\.venv\Scripts\python -m authflowguard.bedrock_smoke `
  --profile authflowguard-dev `
  --region us-east-1 `
  --model-id amazon.nova-micro-v1:0 `
  --confirm-live-call
```

If AWS returns `ThrottlingException: Too many tokens per day`, inspect the
Bedrock quotas for the selected region in the AWS Service Quotas console. A
zero requests-per-minute, tokens-per-minute, or daily-token quota prevents the
smoke request from running. Changing models does not help unless that model has
nonzero on-demand quotas for the account and region.

For a zero Nova quota, open **AWS Console > Service Quotas > AWS services >
Amazon Bedrock** in `us-east-1`. Search for **Cross-region model inference
tokens per minute for Amazon Nova Micro**, select it, and request an increase.
AWS uses that adjustable quota request to review the related on-demand
tokens-per-minute and daily-token quotas as well. Repeat the smoke test only
after the applied quota values are nonzero.

## 6. Controlled Evaluation Application

Run the server-rendered form/cookie fixture in secure mode:

```powershell
.\.venv\Scripts\python -m authflowguard.evaluation_targets.controlled_app --mode secure --port 8001
```

Use `--mode vulnerable` on a different port to expose the intentionally weak
comparison behaviours. The fixture includes changing, single-use CSRF tokens;
login redirects; cookie sessions; authenticated and anonymous account views;
registration and reset forms; login throttling; session rotation; and logout
invalidation. Its built-in credentials are test data only:

- Email: `developer@example.test`
- Password: `correct-horse-battery-staple`

This application binds to `127.0.0.1` by default and must not be deployed as a
production service.

## 7. Live Bedrock Browser Agent

Start the controlled application in one terminal using the command in Section
6. Sign in to AWS with the development profile, then run the bounded live agent
from a second terminal:

```powershell
aws login --profile authflowguard-dev --region us-east-1

.\.venv\Scripts\python -m authflowguard.agent_cli `
  --target-url http://127.0.0.1:8001/login `
  --account-marker-selector '[data-testid="account-marker"]' `
  --profile authflowguard-dev `
  --region us-east-1 `
  --model-id amazon.nova-micro-v1:0 `
  --maximum-ai-decisions 8 `
  --maximum-cost-usd 0.01 `
  --headed `
  --confirm-live-calls
```

The CLI prompts for the username and password instead of accepting them as
command-line arguments. Values remain in worker memory and are discarded when
the session ends. Each successful model decision prints its action type,
control reference, sanitized resulting page URL, token use, and estimated cost.
The command exits with code 0 only when the account-marker selector becomes
visible; limits and guidance-required outcomes exit with code 2.

## 8. Run a Scan from the Interface

Start the controlled application from Section 6, then start the backend and
interface from Sections 1 and 2. In the browser, use **Setup** and enter the
controlled application's values:

- Target URL: `http://127.0.0.1:8001/login`
- Permitted origins: `http://127.0.0.1:8001`
- Known account username: `developer@example.test`
- Known account password: `correct-horse-battery-staple`
- Nonexistent account username: `missing@example.test`
- Invalid password: `wrong-password`
- Protected resource URL: `http://127.0.0.1:8001/account`
- Authenticated marker selector: `[data-testid="account-marker"]`

Select **Start local scan**. The interface switches to **Testing**, polls the
scan, and shows the generated scan ID. When the state is `completed`, choose
**Open results** to see the findings and download the offline JSON or HTML
report. You can choose **Cancel scan** while execution is still running. The
implemented CHK-001 through CHK-006 selections are executed and each completed
check produces a persisted evidence package and result.

The **Results** view lists saved local runs automatically. Select any listed
run to load it, or continue using the Scan ID search field when you already
have a specific ID. The list is restored from `.authflowguard-data` when the
backend restarts.

The username, passwords, and disposable identifier are sent only in the local
start request. They are runtime inputs and are discarded by the backend after
the scan; do not use production credentials.

## 9. Guided Discovery Fallback

This walkthrough describes the current interface. Discovery uses focused
questions and recognizable choices instead of asking the user to type technical
control IDs. The backend still receives safe structured references.

The normal controlled `/login` page is discovered automatically. To exercise the
guided fallback, use a page without conventional login controls as the scan
target, then observe the actual login page from Discovery.

Use these Setup values:

- Target URL: `http://127.0.0.1:8001/account`
- Permitted origin: `http://127.0.0.1:8001`
- Known account username: `developer@example.test`
- Known account password: `correct-horse-battery-staple`
- Nonexistent account username: `missing@example.test`
- Invalid password: `wrong-password`
- Protected resource URL: `http://127.0.0.1:8001/account`
- Authenticated marker selector: `[data-testid="account-marker"]`

Select **Login account enumeration** and start the scan. When Testing shows
`awaiting_guidance`, open **Discovery**. Set **Login page address** to
`http://127.0.0.1:8001/login`, then choose **Find login fields**.

For the bundled controlled application, the visible login controls are currently:

```text
control-5  username/email field
control-6  password field
control-7  submit button
```

Choose the username/email field, password field, and sign-in button from the
dropdowns. The backend records this four-step flow using the selected references:

```text
Navigate → http://127.0.0.1:8001/login
Fill     → control-5 → username
Fill     → control-6 → password
Click    → control-7
```

Choose **Save and verify guided flow**. AuthFlowGuard replays the actions in a
fresh authenticated context, checks the account marker on `/account`, repeats
the protected-resource request in a separate anonymous context, and then runs
the selected check. Use port `8002` and vulnerable mode to expect
`finding_confirmed` instead of `no_issue_observed`.

Control IDs are generated from the page's current control order; they are not
universal HTML IDs. Observe the page again if its layout changes. The current
Discovery UI records structured actions and references rather than providing a
live click-through browser recorder.

## 10. React/JSON Two-Step Evaluation

The second controlled application models a single-page login that requests a
verification code through JSON, receives a bearer token through JSON, and stores
that token in browser localStorage. Start it separately from the form fixture:

```powershell
.\.venv\Scripts\python -m authflowguard.evaluation_targets.react_json_app --mode secure --port 8003
```

Use these Setup values:

- Target URL: `http://127.0.0.1:8003/login`
- Permitted origin: `http://127.0.0.1:8003`
- Known account username: `developer@example.test`
- Known account password: `unused-for-json-login`
- One-time verification code: `246810`
- Nonexistent account username: `missing@example.test`
- Invalid password: `wrong-password`
- Protected resource URL: `http://127.0.0.1:8003/account`
- Authenticated marker selector: `[data-testid="account-marker"]`

The automatic discovery path identifies the username, first-step button,
hidden one-time-code control, and second-step button. It executes the JSON
requests through the page, then verifies the marker in an authenticated context
and confirms its absence in a fresh anonymous context. The bearer token itself
is never included in evidence; only a local-storage fingerprint is retained.

Use this command for the intentionally vulnerable variant:

```powershell
.\.venv\Scripts\python -m authflowguard.evaluation_targets.react_json_app --mode vulnerable --port 8004
```

Then change the Setup target, permitted origin, and protected-resource URL to
port `8004`. The app's unknown-account response should disclose
`No account exists`, while the secure mode uses a generic response.

## 11. Saved-Flow Revalidation

When a completed scan has a verified profile, a later scan with the same target
and protected resource attempts to reuse that profile. Before replaying it,
AuthFlowGuard observes the current login page and compares nonsecret control
signatures. Changing CSRF values are allowed, while renamed, reordered, removed,
or newly inserted controls are treated as stale.

If the profile is stale—or was created by an older version without control
signatures—the new scan pauses in `awaiting_guidance`. Open Discovery, find the
current login fields, choose the controls again, and submit the guided flow. The
stale profile is never replayed.

## 12. Registration and Reset-Request Enumeration

CHK-002 (`registration_enumeration`) and CHK-003
(`reset_request_enumeration`) use WSTG-IDNT-04. Both execute native HTML POST
forms through Playwright, then analyse the captured evidence offline. Each check
submits one known identifier and one nonexistent identifier in separate, fresh
browser contexts. Each form GET obtains its own CSRF token and cookie session;
neither is replayed between attempts. These checks do not assess timing or
establish repeatability beyond the single captured pair.

Registration can create an account, including in the secure evaluation fixture.
Use a **fresh disposable nonexistent identifier for each scan**, or restart the
controlled application to reset its in-memory state. Tests create an isolated
application instance per scenario. Within a scan, login enumeration runs first,
reset-request enumeration next, and registration last, regardless of the order
selected. This prevents registration from changing the nonexistent account used
by the earlier checks. The runner does not delete accounts from arbitrary targets.

The runner finds an unambiguous visible registration/reset link on the saved
login page; it does not assume fixed endpoint paths. The bundled fixture links
to `GET/POST /register` and `GET/POST /reset`. Only a single visible native POST
form with an identifiable username/email control and submit button is supported;
registration additionally requires one password field. Missing/ambiguous forms,
blocked navigation, timeouts, unexpected HTTP errors, and cancellation produce
`execution_error`, not a secure result. Custom JSON/SPA registration and reset
flows are outside this implementation.

For API callers, the start request optionally accepts `registration_url` and
`reset_request_url` to identify an in-scope form explicitly. An optional
`registration_password_reference` resolves a disposable registration password
from `runtime_secrets`; otherwise `failure_password_reference` is reused. In
Setup, the **Invalid password** field therefore also supplies the disposable
registration password. Choose a value satisfying the target's registration rules.

### Evidence and outcomes

Both checks use the existing `TestRunEvidence` format with labelled
`known_identifier_attempt` and `nonexistent_identifier_attempt` observations.
They retain POST/final status codes, normalized body/title/redirect-path and
control-state fingerprints, fixed message categories, event references,
completed/attempted steps, errors, and coverage limitations. Raw response text,
usernames, passwords, CSRF values, cookies, and authorization headers are not
stored. Hidden form values, labelled tokens/request IDs, UUIDs and timestamps
are normalized before hashing. Arbitrary unrecognized dynamic content remains
a stated limitation.

| Check | Vulnerable fixture | Secure fixture |
| --- | --- | --- |
| CHK-002 | Known: 409/already registered; nonexistent: 202/check email → `finding_confirmed` | Both: 202/check email → `no_issue_observed` |
| CHK-003 | Known: generic reset instructions; nonexistent: no account exists → `finding_confirmed` | Both: generic reset instructions → `no_issue_observed` |

Incomplete or malformed evidence is `inconclusive`. Captured browser failures or
unexpected HTTP error statuses are `execution_error`. With account-existence
privacy disabled in policy, successful comparisons produce `no_issue_observed`.
Both new analysers produce identical full results for identical evidence, policy,
and analyser version, including stable result IDs and evidence capture timestamps.

### Manual walkthrough

1. Start the secure controlled app on port 8001, the backend on port 8080, and
   the frontend as described above. Use the normal `/login` Setup values with
   `developer@example.test` / `correct-horse-battery-staple`, protected resource
   `/account`, and marker `[data-testid="account-marker"]`.
2. Supply a fresh nonexistent identifier such as `scan-001@example.test` and a
   disposable registration password in **Invalid password**.
3. Select **Registration account enumeration** and **Reset-request account
   enumeration** only. Start the scan and open Results after completion. Both
   checks should show `no_issue_observed`; JSON and HTML reports include both.
4. Repeat on a fresh vulnerable fixture on port 8002, changing all three URLs
   (target, permitted origin, protected resource). Both should show
   `finding_confirmed` with the differences listed above.
5. The same checks run after guided login verification. Follow Section 9 to
   exercise that route. A stale saved login profile still pauses for guidance
   before any check executes.

### Offline reanalysis API

`POST /api/scans/{scan_id}/reanalyse` now processes **every stored evidence
record**, dispatching by check ID for CHK-001 through CHK-006. Its response
has changed from a single result to:

```json
{"scan_id": "<scan UUID>", "results": ["<one result object per evidence record>"]}
```

No browser, network, runtime credentials, or model service is used. Each result
is saved as a new version; existing evidence and result-version files are retained.
Scan status and reports expose the latest result for each evidence record rather
than accumulating duplicate current results. This remains true after a backend
restart. Reanalysis is rejected while the scan is running or awaiting guidance.

`test_form_enumeration.py` covers both browser/analyser matrices, fresh CSRF and
session isolation, dynamic normalization, redaction, nonstandard routes, failures,
cancellation, and deterministic offline analysis. `test_enumeration_scans.py`
covers check selection, automatic/guided secure/vulnerable scans, ordering,
persisted reports, stale flows, and reanalysis of multiple checks/evidence records.

The full regression run also exposed a shared snapshot race during the existing
two-step login: navigation could replace controls between individual reads.
`BrowserActionExecutor` now captures one DOM revision per snapshot, with a bounded
retry if navigation destroys the execution context. `test_action_executor.py`
checks snapshot consistency while the page repeatedly replaces its controls.

Final verification for this batch: **177 backend tests and 10 frontend tests
passed**. Ruff formatting/lint, mypy, Prettier, ESLint, TypeScript, the production
build, and `git diff --check` passed. The backend retains the existing
Starlette/TestClient anyio deprecation warning.

## 13. Login Throttling and Lockout (CHK-004)

CHK-004 follows WSTG-ATHN-03. After login has been verified, the browser runner
performs a bounded sequence of failed-password attempts, creating a fresh
browser context for every attempt. It then submits the known password as a
valid-login control. The runner records status codes, normalized URL/title/body
fingerprints, safe indicators such as `rate_limited` and `signed_in`, attempted
and completed steps, and execution errors. Passwords, response bodies, cookies,
and authorization data are never saved.

The default sequence contains three failed attempts and one valid control. A
`SecurityPolicy.expected_lockout_threshold` can lower or raise the attempt count,
with a hard cap of five attempts. A restricted valid control (401, 403, 423, or
429, or a rate-limit indicator) is `no_issue_observed`; a successful control
after all bounded failures is `finding_confirmed`. Missing or malformed attempt
records are `inconclusive`, while browser failures, cancellation, and unexpected
server-error statuses are `execution_error`. The analyser is offline and
deterministic, including its result ID and evidence capture timestamp.

For a manual run, start the secure controlled app and select **Login throttling
and lockout** in Setup. Use the verified login credentials and the existing
Invalid password reference. The secure fixture should restrict the valid
control after three failed attempts. Repeat against the vulnerable fixture; the
valid control succeeds and the result should be `finding_confirmed`. JSON and
HTML reports include CHK-004, its WSTG reference, attempt coverage, and any
limitations. Reanalysis of the saved scan does not launch a browser or resolve
runtime credentials.

## 14. Session Fixation and Logout Invalidation (CHK-005/CHK-006)

CHK-005 captures the browser cookie state before login, verifies authenticated
access, and replays the original state in a separate browser context. A replay
that still reaches the protected account marker confirms session fixation;
rejection matching the anonymous control produces `no_issue_observed`.
The analyser records whether the cookie fingerprint changed, but an unchanged
cookie alone is not treated as a finding.

CHK-006 verifies login, captures the active session, submits the logout form
discovered on the protected page, and replays the pre-logout session in a fresh
context. A replay that retains the account marker confirms logout invalidation
failure. Rejection matching the anonymous control produces `no_issue_observed`.
Both runners keep cookie values and response bodies in memory only, record
status and marker controls, and return `execution_error` for browser failures or
server-error responses. Missing controls are `inconclusive`.

### Current support boundary

CHK-005 and CHK-006 currently support saved login flows whose fill actions are
a username followed by a password, with authentication state held in browser
cookies. The session-check adapter assigns the username reference to the first
fill action and the password reference to every later fill action. It therefore
cannot yet replay login flows containing a one-time verification code or another
additional fill step. Although authentication discovery and proof support the
React/JSON bearer-token fixture, these two checks do not copy or replay bearer
tokens stored in local or session storage.

CHK-006 currently discovers logout only when the protected page contains an
identifiable HTML form whose action or visible text indicates logout, whose
submit control produces a POST response. Logout links, client-side navigation,
and JavaScript requests using another HTTP method are not yet supported.

An unsupported saved-login shape can fail before check evidence is created and
therefore fail the scan. Unsupported logout discovery is captured as
`execution_error`; an analyser given incomplete saved evidence returns
`inconclusive`. None of these outcomes means that the target passed the check,
and an unsupported pattern must never be reported as `no_issue_observed`.

The controlled application demonstrates both scenarios: secure mode rotates the
session at login and removes it at logout, while vulnerable mode reuses the
pre-login session and leaves the logged-out session valid. The browser and
offline tests cover secure and vulnerable outcomes, deterministic reanalysis,
malformed evidence, execution failures, scan persistence, and report code
mapping.

## 15. Independent Evaluation Application (Application C)

Run the independently-designed workshop-desk fixture in secure mode:

```powershell
.\.venv\Scripts\python -m authflowguard.evaluation_targets.site_app --mode secure --port 8005
```

Use `--mode vulnerable` on a different port to expose the intentionally weak
comparison behaviours. Unlike the controlled application, this fixture was
built without reusing its labels, routes, or page layout, to give discovery an
unfamiliar target. It has a login page at `/desk/entry` and a protected page
at `/desk/bookings`; it deliberately has no registration or password-reset
forms, so CHK-002 and CHK-003 are not applicable to it. It targets CHK-001
(login enumeration), CHK-004 (login throttling), CHK-005 (session fixation),
and CHK-006 (logout invalidation) instead. Its built-in credentials are test
data only:

- Member ID: `MBR-40817`
- Passphrase: `lantern-orchard-47`

All state is held in memory, so restarting the process resets it — there is no
separate reset command. This application binds to `127.0.0.1` by default and
must not be deployed as a production service.

## 16. Bedrock Web Integration & Offline Evaluation (Task 2.6 / INT-011)

Task 2.6 connects Bedrock browser discovery directly to web scans initiated from
the React interface or FastAPI backend.

### Running Bedrock Integration Tests

The integration test suite (`test_bedrock_web_integration.py`) tests the complete
end-to-end pipeline offline using `DeterministicModelDouble`:

```powershell
.\.venv\Scripts\python -m pytest backend/tests/test_bedrock.py backend/tests/test_bedrock_web_integration.py
```

Scenarios covered:
1. Full API scan using Bedrock discovery against Application A, check runner execution, evidence capture, results, and report download.
2. Multi-page navigation discovery (navigating link on landing page to login) with `step_control_signatures` and fresh-context replay.
3. Form disambiguation on Application C (search form vs login form).
4. Dual-context proof rejection halting the scan when an account marker is visible anonymously.
5. Replay control signature validation rejecting tampered controls with `StaleAuthProfileError`.
6. Durable accounting persistence surviving restart and halting immediately on ledger store write failure before model dispatch.
7. Secret redaction verifying that raw passwords/secrets never appear in model observations or events.
8. Synchronous validation failure returning clean error responses when Bedrock is unconfigured without hanging.
9. Scan persistence reload verifying that `cost-ledger.ndjson`, exploration metrics, and provenance records survive restarts.

### Running Scans with AI Discovery in the Interface

1. In the **Setup** view, under **Discovery engine**, **Bedrock AI agent** is selected by default. Select **Deterministic rules** explicitly for the offline baseline.
2. The capability banner reports local backend configuration; it does not verify live AWS access or quota.
3. Expand **Bounded execution limits** to configure:
   - Maximum model decisions (default: 40; server cap: 100)
   - Maximum exploration seconds (default: 900s; server cap: 1800s)
   - Maximum inference budget (default: $0.25; server cap: $1.00)
4. For live Bedrock calls against AWS, ensure you have an active AWS session:
   ```powershell
   aws login --profile authflowguard-dev --region us-east-1
   ```
5. In automated tests and offline development, tests inject `DeterministicModelDouble` to simulate Bedrock responses without incurring AWS costs or requiring credentials.

Offline integration tests exercise the API, controller, proof, and selected checks. A real frontend-to-AWS scan has not been validated in this review; model access, quota, and live discovery reliability remain unverified.

`discovery_reliability.py --discovery-mode bedrock` uses an offline model double by default. `--confirm-live-calls` explicitly permits AWS calls. `--max-evaluation-cost-usd` is shared across all attempts in that evaluation; observed usage and unresolved reservations both reduce the remaining allowance.
