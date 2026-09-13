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

These suites verify the foundation that currently exists. They do not count as
evidence for authentication discovery, full scans, security checks, reporting,
or cancellation until those features and their end-to-end tests are added.

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
