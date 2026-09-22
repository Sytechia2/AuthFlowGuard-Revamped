# Member 5 — state of work and how to resume

**Branch:** `evaluation/formal-results` · **Last commit:** `bb805a6` · 23 September 2026

This file travels with the repository, so the context below survives whatever
happens to any single machine's session history.

## Where the work stands

| Task | Tracker | Status | Evidence |
| --- | --- | --- | --- |
| Execute the formal check cases | EVA-005 | **Done, Application A** | `evaluation/reports/formal-cases.md` — 24/24 pass |
| Test failure situations | EVA-006 | **Done, in part** | 6 fault-injection and 6 degraded-evidence cases, included in the 24 |
| Confirm offline analysis and reports | EVA-007 | **Done** | `evaluation/reports/offline-verification.md` — 6/6 pass |
| Decide session-check scope | Task 5.6 | **Done — all three deferred** | `Documentation/KNOWN_LIMITATIONS.md` §1 |
| Freeze features, list limitations | REL-001 | **Done** | `Documentation/KNOWN_LIMITATIONS.md` |
| Discovery reliability | EVA-004 | **Blocked** | Needs live Bedrock; web scans do not call it. Limitations §5 |
| Usage, cost, duration | EVA-008 | **Blocked for live figures** | Infrastructure built and tested; live numbers need Bedrock. Limitations §5 |

## How to reproduce every number

From the repository root, with the environment from `DEVELOPMENT.md` §1:

```powershell
# 24 formal cases (live, degraded-evidence, and fault-injection)
python -m authflowguard.evaluation.case_runner --run-id my-run

# Render the submission table
python -m authflowguard.evaluation.tables evaluation/results/my-run/results.json

# EVA-007: offline analysis and report regeneration, target stopped
python -m authflowguard.evaluation.offline_verification `
  evaluation/results/my-run/scan-data/A-CHK-006-secure `
  --out evaluation/reports/offline-verification.md
```

Raw scan data under `evaluation/results/*/scan-data/` is gitignored; the
`results.json` files and rendered reports are committed.

## Decisions worth not re-deriving

- **The case file is an immutable input.** `evaluation/cases/formal_cases.json`
  is never written to. Each run writes its own `results.json` keyed by
  `case_id`, so two runs can be compared. Kevin's file still carries
  `actual_result` / `evidence_id` / `verdict` placeholder fields; the runner
  ignores them and they should be removed.
- **Each case gets a freshly started fixture.** Sharing one instance lets login
  enumeration's deliberate failed logins trip the secure fixture's lockout
  (threshold 3), after which every later case fails login verification and
  reports `awaiting_guidance`. This cost an hour; do not undo it.
- **Live cases use an ephemeral port**, not the fixed ports in the case file, so
  a run cannot fail because a port was busy. The origin used is recorded per
  result.
- **`httpx2` is a real package**, required by Starlette 1.6. `pyproject.toml`
  wrongly lists `httpx` in its dev extras. Kevin's branch changed the import to
  `httpx` instead; the dependency is the thing that should change.
- **The `test_react_json_app` full-suite failure is pre-existing**, not caused
  by Kevin's branch or this work. Confirmed on `main` with `httpx2` installed.

## Outstanding, for whoever picks this up

1. Applications B (4 cases) and C (16 cases) are authored but not executed. The
   runner's `fixture_for()` only wires Application A; add `react_json_app` and
   `site_app` to execute them.
2. Correct `pyproject.toml` to depend on `httpx2`.
3. Assign the `test_react_json_app` fixture-isolation defect (Member 2).
4. EVA-004 and EVA-008 unblock only when Bedrock is wired into web scans.

## Resuming the Claude Code session on another machine

The repository carries the work; this section only restores the *chat history*.

Claude Code stores sessions in `~/.claude/projects/<slug>/`, where `<slug>` is
the repository's absolute path with separators replaced by dashes — here
`c--Users-sufia-Documents-Github-AuthFlowGuard-Revamped`. A packaged copy is at
`Documents/authflowguard-claude-session-20260923.zip`, containing the session
transcript and the `memory/` directory.

To restore:

1. Copy the zip to the other machine and extract it into `~/.claude/projects/`.
2. **If the repository sits at a different path there**, rename the extracted
   folder to match that path's slug, or the session will not be found. Clone to
   the same path to avoid this.
3. Run `claude --resume` from inside the repository and pick the session.

Do not commit the transcript to the team repository: it is large and contains
the whole working conversation.
