# Local Development

AuthFlowGuard AI runs entirely on the developer's computer. During development,
run the Python backend and React interface in separate terminals.

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
.\.venv\Scripts\python -m authflowguard.controlled_app --mode secure --port 8001
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
**Open results** to see the finding and download the offline JSON or HTML
report. You can choose **Cancel scan** while execution is still running. Only the implemented login-account-enumeration check produces a result
in this release; the other check selections are retained in the scan request
but are not yet executed.

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
`awaiting_guidance`, open **Discovery**. Set **Page to observe** to
`http://127.0.0.1:8001/login`, then choose **Observe target controls**.

For the bundled controlled application, the visible login controls are currently:

```text
control-5  username/email field
control-6  password field
control-7  submit button
```

Enter this four-step flow:

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
.\.venv\Scripts\python -m authflowguard.react_json_app --mode secure --port 8003
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
.\.venv\Scripts\python -m authflowguard.react_json_app --mode vulnerable --port 8004
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
