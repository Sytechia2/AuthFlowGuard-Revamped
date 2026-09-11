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
