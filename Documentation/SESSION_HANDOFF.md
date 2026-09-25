# Member 5 — state of work and how to resume

**Branch:** `evaluation/formal-results` · **Last commit:** `bb805a6` · 23 September 2026

This file travels with the repository, so the context below survives whatever
happens to any single machine's session history.

## Where the work stands

| Task | Tracker | Status | Evidence |
| --- | --- | --- | --- |
| Execute the formal check cases | EVA-005 | **Done, all three applications** | `evaluation/reports/formal-cases.md` — 44 cases, 41 pass |
| Test failure situations | EVA-006 | **6 of 7 — as complete as possible** | Only worker failure remains, blocked on RUN-002. `KNOWN_LIMITATIONS.md` §5 |
| Confirm offline analysis and reports | EVA-007 | **Done** | `evaluation/reports/offline-verification.md` — 6/6 pass |
| Decide session-check scope | Task 5.6 | **Done — all three deferred** | `Documentation/KNOWN_LIMITATIONS.md` §1 |
| Freeze features, list limitations | REL-001 | **Done** | `Documentation/KNOWN_LIMITATIONS.md` |
| Discovery reliability | EVA-004 | **Measured for web scans** | `evaluation/reports/discovery-reliability.md` — A 5/5, B 2/5, C 0/5 automatic |
| Usage, cost, duration | EVA-008 | **Measured except model cost** | `evaluation/reports/measurements.md` — 22 scans, requests and durations |
| Connect Bedrock discovery to web scans | INT-011 / Task 2.6 | **In progress** | Offline integration under review; live UI-to-Bedrock validation outstanding. |

## How to reproduce every number

From the repository root, with the environment from `DEVELOPMENT.md` §1:

```powershell
# All 44 cases across the three applications
python -m authflowguard.evaluation.case_runner --application A,B,C --run-id my-run

# Measured consumption: browser requests and durations
python -m authflowguard.evaluation.measurements my-run --out evaluation/reports/measurements.md

# EVA-004: discovery reliability, five attempts per application
python -m authflowguard.evaluation.discovery_reliability `
  --out evaluation/reports/discovery-reliability.md

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

1. Kevin's Application B expectations need correcting: CHK-001 is unsupported
   against a two-step JSON login. See `KNOWN_LIMITATIONS.md` §4.1. Do not change
   the product to make those rows pass.
2. Automatic discovery fails on Application C; all 16 cases ran guided. Worth
   investigating whether the two-form sign-in page can be disambiguated.
3. **Application B's automatic discovery succeeds only 2 times in 5.** Likely
   the same root cause as the intermittent `test_react_json_app` failure. This
   is the most serious open reliability defect.
4. EVA-006's only remaining condition is worker failure, blocked until a
   separate worker process exists (RUN-002).
5. Correct `pyproject.toml` to depend on `httpx2`.
6. Assign the `test_react_json_app` fixture-isolation defect (Member 2).
7. Bedrock discovery is wired into web scans (Task 2.6 / INT-011 offline integration under review). Live UI-to-Bedrock behavior has not been validated. Automated evaluation and tests use `DeterministicModelDouble` unless live calls are explicitly enabled.

## 23 September 2026 integration review

The web integration now saves only executed login steps, validates positional controls per replay step, persists partial controller evidence, counts model requests independently of browser success, enforces server caps, and shares one budget across discovery reliability attempts. Controller and proof waits check cancellation; synchronous SDK threads still require bounded timeouts and RUN-002 remains open. No real UI-to-Bedrock scan was run.

The fresh rules-mode formal run at `evaluation/results/bedrock-review-20260923/results.json` yielded 41/44 passing, with the same three Application B CHK-001 limitations as the historical baseline. Its separate report is `evaluation/reports/formal-cases-bedrock-review-20260923.md`. Offline reanalysis yielded 6/6 passing in `evaluation/reports/offline-verification-bedrock-review-20260923.md`. These are offline results, not live Bedrock reliability measurements.

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
