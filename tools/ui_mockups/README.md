# UI mockups with Gemini (Vertex AI)

A design aid for exploring interface changes before building them. It asks a
Gemini image model on Vertex AI for a mockup that follows [DESIGN.md](../../DESIGN.md).
You can attach screenshots of the current screens so the model changes only
what you describe.

This tool is not part of AuthFlowGuard. The scanner uses Amazon Bedrock only,
and nothing in `backend/` or `frontend/` imports this folder.

## One-time setup

```powershell
.\.venv\Scripts\python -m pip install -e ".[mockups]"
gcloud auth application-default login
gcloud config set project <your-project-id>
```

The Google Cloud project needs the Vertex AI API (`aiplatform.googleapis.com`)
enabled and billing turned on.

## Use

Start the interface (`cd frontend; npm.cmd run dev`) if you want the tool to
capture current screens, then run from the repository root:

```powershell
# Redesign the Results screen, starting from a real saved scan
.\.venv\Scripts\python tools\ui_mockups\generate_mockup.py --screen results `
  --scan-id <scan-id> --count 2 `
  "Show a summary strip with finding counts, then one row per check (CHK-001 to CHK-006, in order) with a text-labelled status badge and severity"

# Check what would be sent, without calling Vertex AI
.\.venv\Scripts\python tools\ui_mockups\generate_mockup.py --screen setup --dry-run "..."

# Start from your own sketch or screenshot
.\.venv\Scripts\python tools\ui_mockups\generate_mockup.py --image sketch.png "..."
```

| Option | Default | Meaning |
|---|---|---|
| `--screen` | none | `setup`, `discovery`, `testing` or `results`; captured from the running interface. Repeatable. |
| `--scan-id` | none | With `--screen results`, load this saved scan before capturing. |
| `--image` | none | Attach your own image. Repeatable. |
| `--count` | 1 | Number of variations (1–4). Each one is a separate, billed request. |
| `--aspect` | `16:9` | Image aspect ratio. |
| `--model` | `gemini-3-pro-image` | `gemini-3.1-flash-image` is cheaper, but renders small text less accurately. |
| `--location` | `global` | Vertex AI location. |

Each run writes a folder under `tools/ui_mockups/output/` (ignored by Git)
with the captured screenshots, the prompt, the mockups, any notes from the
model and token usage in `request.json`.

## Before you send anything

Screenshots are uploaded to Google. Capture screens with no real target data
or credentials on them; the evaluation apps' built-in test accounts are fine.
A mockup is a picture to discuss, not a specification: check the wording and
the status meanings against the real data before building it.
