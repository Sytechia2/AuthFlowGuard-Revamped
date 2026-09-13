# AuthFlowGuard AI — Execution Plan and Progress Tracker

This document tracks implementation progress for the work defined in
[PROJECT_PLAN_AI.md](PROJECT_PLAN_AI.md). The project plan remains the source of
truth for scope, architecture, security rules, responsibilities, schedule, and
acceptance criteria. This execution plan translates that direction into tasks
that can be assigned, implemented, tested, and marked complete.

**Tracking started:** 10 September 2026

**Target submission:** 28–29 September 2026

**Last updated:** 13 September 2026

## 1. How to Maintain This Tracker

Use one of these statuses for every task:

| Status | Meaning |
| --- | --- |
| **Not started** | No implementation has been completed. |
| **In progress** | Work has started, but the definition of done is not satisfied. |
| **Blocked** | Work cannot continue until a named dependency or decision is resolved. |
| **Done** | The implementation, relevant tests, and required documentation are complete. |
| **Deferred** | The task is intentionally outside the current release or has been postponed. |

When changing a task to **Done**, add or update its evidence in this document.
Evidence should normally be a test file, implementation file, report, or other
repeatable verification. Code existing by itself is not enough when the project
plan requires browser-level, offline, privacy, or failure-handling tests.

Update this tracker in the same change as the implementation. Do not mark a
whole milestone complete because only its first component works.

## 2. Current Position

| Area | Status | Current evidence |
| --- | --- | --- |
| Repository and backend foundation | **Done** | Python package, shared models, FastAPI, React, packaged frontend/backend connection, Playwright, bounded Bedrock request, and project-wide quality commands work locally. |
| Playwright observations | **In progress** | A bounded Bedrock-driven loop now converts sanitized observations into validated browser actions, records action traffic and page changes, and completes the controlled login with an offline model double. Guided recording and fresh-context replay are covered by `authentication.py` and `test_authentication.py`; UI integration remains pending. |
| Verified authentication information | **In progress** | Automatic and guided CSRF-safe login flows produce verified profiles from authenticated and isolated anonymous account-marker evidence, and saved flows replay in fresh contexts. The second authentication style and stale-flow revalidation remain pending. |
| Bedrock integration | **In progress** | The structured Converse client and live CLI completed the controlled login in three model decisions within the configured cost cap. Sanitization, validation, limits, retry feedback, and guidance escalation are tested. Usage persistence across restarts remains pending. |
| Security checks | **In progress** | `CHK-001` has a browser runner and deterministic offline analyser; the remaining five checks are pending. |
| Evidence persistence and reports | **In progress** | `EvidenceStore` writes bounded redacted scan evidence, append-only events, and versioned results; offline JSON/HTML export and first-slice scan API integration are implemented. Worker-process separation remains pending. |
| Interface | **In progress** | The four-view React shell now submits Setup data, starts a local scan, polls live status, lists persisted past runs, and keeps Scan ID search; guidance and full result controls remain pending. |
| Evaluation and release | **In progress** | The first controlled evaluation application is complete. The second and withheld-layout applications, reliability measurements, installation test, and demonstration are pending. |

Current automated verification: **98 tests passing**: 89 backend tests and 9
React behavior tests. The backend suite includes real Chromium tests against
controlled local pages, secure and intentionally vulnerable form/cookie flows,
adversarial scope and privacy cases, strict Bedrock response validation, and
authentication-proof rejection cases. There is one non-blocking deprecation
warning from Starlette's test client.

## 3. Delivery Milestones

These milestones follow the dates and priorities in Section 5.2 of the project
plan.

| Milestone | Target dates | Status | Completion condition |
| --- | --- | --- | --- |
| **M0 — Working foundation** | 10–12 Sep | **Done** | Shared models, backend, React connection, Playwright worker, and one bounded Bedrock request all work locally. |
| **M1 — Verified authentication** | 13–16 Sep | **In progress** | Automatic login discovery, guided fallback, authentication proof, and fresh-context replay work on a controlled application. |
| **M2 — First complete security check** | 13–16 Sep | **Not started** | One runner produces evidence, its offline analyser produces a repeatable result, and HTML/JSON reporting presents it. |
| **M3 — All six checks integrated** | 17–21 Sep | **Not started** | All six runner/analyser pairs use the common evidence and result pipeline. |
| **M4 — Evaluation and hardening** | 22–25 Sep | **Not started** | Evaluation applications, offline analysis, reliability, cost, failure handling, and second-computer installation are verified. |
| **M5 — Release preparation** | 26–27 Sep | **Not started** | Features are frozen, documentation is complete, known limitations are recorded, and the demonstration is recorded. |
| **M6 — Submission** | 28–29 Sep | **Not started** | Final review is complete and all required deliverables are submitted. |

## 4. Foundation Tasks

Primary owner: **Member 1**. Member 2 supports Playwright and Bedrock work;
Member 4 owns the frontend connection.

| ID | Task | Status | Depends on | Evidence or completion notes |
| --- | --- | --- | --- | --- |
| FND-001 | Establish the separate repository and Python project structure. | **Done** | — | `pyproject.toml` and `backend/authflowguard/` |
| FND-002 | Record the requirement for simple, explicit, understandable code. | **Done** | — | Project plan Section 2.7 |
| FND-003 | Define the six shared Pydantic contracts and supporting types. | **Done** | FND-001 | `backend/authflowguard/models.py`; round-trip, boundary, contradictory-field, unknown-field, and secret-exclusion tests |
| FND-004 | Create a minimal FastAPI application and health endpoint. | **Done** | FND-001 | `backend/authflowguard/app.py`; `backend/tests/test_app.py` |
| FND-005 | Create the React, TypeScript, and Vite application. | **Done** | FND-001 | `frontend/`; the TypeScript and Vite production build passes. |
| FND-006 | Connect the local React interface to the FastAPI health endpoint. | **Done** | FND-004, FND-005 | The interface fetches `/api/health`; tests cover connected, invalid-response, and network-failure states; FastAPI serves the production build without shadowing API routes. |
| FND-007 | Make Playwright and Chromium installation reproducible. | **Done** | FND-001 | Dependency and installation command are recorded in `pyproject.toml` and `Documentation/DEVELOPMENT.md`. |
| FND-008 | Perform one structured Bedrock Converse API action request. | **Done** | FND-001 | Nova Micro returned a validated `fill` action: 652 input tokens, 51 output tokens, estimated cost `$0.00002996`, reserved maximum cost `$0.00006828`. Sanitization, validation, and pre-call cost-limit tests pass. |
| FND-009 | Add project-wide formatting, linting, and type-checking commands. | **Done** | FND-001 | Ruff formatting/linting and mypy cover all backend source and test files. Prettier, ESLint, and TypeScript checks cover the frontend. Commands are documented in `Documentation/DEVELOPMENT.md`. |

## 5. Website Interaction and Authentication Tasks

Primary owners: **Member 2** for browser/AI interaction and **Member 1** for
authentication information.

| ID | Task | Status | Depends on | Evidence or completion notes |
| --- | --- | --- | --- | --- |
| INT-001 | Enforce permitted origins and redact query strings and fragments. | **Done** | FND-003 | Tests cover deceptive hosts, user-info URLs, ports, case normalization, query/fragment removal, and real browser blocking. |
| INT-002 | Record requests, responses, page controls, cookies, and browser storage without saving live secrets. | **Done** | FND-003, FND-007 | A controlled Chromium test verifies blocked external requests, event relationships, cookie/local/session-storage fingerprints, and exclusion of live storage and input values. |
| INT-003 | Implement validated execution for every `BrowserAction` type. | **Done** | INT-002 | `action_executor.py`; Chromium tests cover navigate, click, fill by secret reference, select, key press, wait, URL redaction, and scope rejection. |
| INT-004 | Associate request and response evidence with scan and action identifiers. | **Done** | INT-002, INT-003 | `BrowserActionExecutor` emits redacted action-time request and response events with scan/action IDs; traffic references carry the action ID; browser tests verify the association. |
| INT-005 | Detect and describe observable page changes after an action. | **Done** | INT-003 | Execution results and page-state evidence compare sanitized URLs, titles, visible controls, and a nonreversible visible-text fingerprint; browser tests verify URL and control-visibility changes. |
| INT-006 | Implement automatic action selection through Bedrock. | **Done** | FND-008, INT-003, INT-005 | `automatic_actions.py` and `agent_cli.py`; Nova Micro completed the controlled login in three live decisions: fill username, fill password, and submit. Local guards restrict actions to visible compatible controls, and the run completed below its `$0.001` cap. |
| INT-007 | Limit AI decisions, retry failed actions twice, and request guidance. | **Done** | INT-006 | The controller enforces decision, active-time, and cumulative inference-cost limits; retries with fresh observations twice; and returns explicit guidance-required status after exhaustion. |
| INT-008 | Record developer-guided actions with local credential references. | **Done** | INT-003 | `record_guided_flow` validates references, removes URL query/fragment data, redacts descriptions, and persists only structured actions; browser and privacy tests in `backend/tests/test_authentication.py`. |
| INT-009 | Replay a recorded flow in a fresh browser context. | **Done** | INT-003, INT-008 | `replay_verified_auth_profile` executes saved steps in fresh authenticated and anonymous contexts and creates new proof evidence; Chromium replay test in `backend/tests/test_authentication.py`. |
| INT-010 | Stop browser and HTTP work cleanly when cancellation is requested. | **Not started** | INT-003 | Preserve completed evidence and mark unfinished work cancelled. |
| AUTH-001 | Define saved, nonsecret authentication-profile data. | **Done** | FND-003 | `AuthProfile` and supporting models |
| AUTH-002 | Require an authenticated account marker and anonymous comparison. | **Done** | AUTH-001 | `auth_profiles.py`; positive and rejection tests |
| AUTH-003 | Discover and execute a complete login flow on a controlled form application. | **Done** | INT-003, INT-005, EVA-001 | `authentication.py`; a real Chromium test discovers conventional login controls and submits the live form with its changing CSRF token through validated structured actions. |
| AUTH-004 | Verify the protected resource in authenticated and isolated anonymous contexts. | **Done** | AUTH-003 | The browser workflow records independent page-state evidence, proves the account marker present only in the authenticated context, and saves both evidence references in the verified profile. Tests also prove credentials, query data, cookie values, and marker text are excluded from persisted output. |
| AUTH-005 | Produce and replay a verified `AuthProfile` in a fresh context. | **Done** | AUTH-004, INT-009 | Guided execution builds a verified profile and replay re-proves the account marker anonymously and authenticated in new contexts; `execute_guided_verified_login_flow`, `replay_verified_auth_profile`, and browser tests. |
| AUTH-006 | Support two-step login and bearer-token sessions. | **Not started** | AUTH-005 | Verify on the controlled React/JSON application. |
| AUTH-007 | Revalidate saved flows before reuse in a new scan. | **Not started** | AUTH-005 | Stale flows must request guidance or produce an explicit outcome. |
| AUTH-008 | Keep live credentials in worker memory and discard them on completion or cancellation. | **In progress** | INT-003, INT-010 | `RuntimeSecrets` resolves and discards in-memory values. Cancellation, export, and model-request coverage remain pending. |

## 6. Scan Execution, Evidence, and Reporting Tasks

Primary owners: **Member 1** for lifecycle and **Member 4** for evidence and
reporting.

| ID | Task | Status | Depends on | Evidence or completion notes |
| --- | --- | --- | --- | --- |
| RUN-001 | Define the scan state machine, including awaiting-guidance and cancellation. | **In progress** | FND-003 | `ScanState` and cancellation transitions are implemented; explicit invalid-transition coverage remains. |
| RUN-002 | Run one scan at a time in a worker process separate from FastAPI. | **In progress** | RUN-001 | A single background executor currently keeps FastAPI responsive; a separate worker process remains. |
| RUN-003 | Add APIs for create, status, events, guidance, cancellation, downloads, and reanalysis. | **In progress** | RUN-001 | Create/status/events/cancellation/download/reanalysis endpoints are implemented; guidance endpoint and full lifecycle integration remain. |
| EVD-001 | Create per-scan directories and metadata files. | **Done** | RUN-001 | `EvidenceStore` creates UUID-bounded scan directories and metadata files; `test_evidence_reports.py`. |
| EVD-002 | Implement the append-only evidence event log. | **Done** | EVD-001 | `EvidenceStore.append_event` writes NDJSON and survives reopening; `test_evidence_reports.py`. |
| EVD-003 | Implement central redaction before evidence is written. | **Done** | EVD-002 | Secrets, query/fragment URL data, and sensitive evidence fields are redacted before disk writes; storage tests. |
| EVD-004 | Save compact per-check evidence packages and explicit coverage. | **Done** | EVD-002 | `EvidenceStore.save_evidence` stores `TestRunEvidence` under per-check directories with coverage; storage tests. |
| EVD-005 | Save versioned results without overwriting earlier analysis. | **Done** | EVD-004 | `EvidenceStore.save_result` writes incrementing result versions; storage tests. |
| RPT-001 | Generate a JSON report offline. | **Done** | EVD-005 | `export_scan_reports` produces JSON from saved models without target, browser, AWS, or credentials. |
| RPT-002 | Generate a readable and printable HTML report offline. | **Done** | EVD-005 | `export_scan_reports` produces escaped HTML with outcomes, OWASP references, and coverage limitations. |

## 7. Security Check Tasks

Each check requires a browser runner and a separate deterministic offline
analyser. Every analyser must accept the equivalent of
`analyse(evidence, profile, policy) -> CheckResult`.

| ID | Check | Primary owner | Status | Required scenario set |
| --- | --- | --- | --- | --- |
| CHK-001 | Login account enumeration — WSTG-IDNT-04 | Member 3 | **Done** | `login_enumeration.py` compares three fresh known/nonexistent failure pairs; tests cover vulnerable, secure, ambiguous, and execution-failure outcomes. |
| CHK-002 | Registration account enumeration — WSTG-IDNT-04 | Member 3 | **Not started** | Vulnerable, secure, ambiguous, execution failure |
| CHK-003 | Reset-request account enumeration — WSTG-IDNT-04 | Member 3 | **Not started** | Vulnerable, secure, ambiguous, execution failure |
| CHK-004 | Login throttling and lockout — WSTG-ATHN-03 | Member 5 | **Not started** | Vulnerable, secure, ambiguous, execution failure |
| CHK-005 | Session fixation — WSTG-SESS-03 | Member 5 | **Not started** | Vulnerable, secure, ambiguous, execution failure |
| CHK-006 | Logout invalidation — WSTG-SESS-06 | Member 5 | **Not started** | Vulnerable, secure, ambiguous, execution failure |

For each `CHK` task, all of the following are part of the definition of done:

1. The runner uses the browser and records attempted steps, observations,
   controls, errors, and coverage.
2. The analyser performs no browser, network, AWS, or credential access.
3. Repeated analysis of identical evidence, policy, and analyser version returns
   the same result.
4. Browser-level runner tests and offline analyser tests pass.
5. Results reference the relevant saved evidence and the correct OWASP WSTG v4.2
   section.
6. The runner follows the common limits and comparison rules in Section 3.1 of
   the project plan.

Recommended first complete check: **CHK-001, login account enumeration**. It
builds directly on login discovery and establishes the runner/analyser/report
pattern that the other checks can copy.

## 8. Interface Tasks

Primary owner: **Member 4**.

| ID | Task | Status | Depends on | Completion notes |
| --- | --- | --- | --- | --- |
| UI-001 | Build the Setup view. | **In progress** | FND-005, RUN-003 | Target, origins, runtime credential inputs, accessible labels, check selection, and API submission are behavior-tested; policies and limits remain. |
| UI-002 | Build the Discovery view and guidance controls. | **Not started** | INT-007, INT-008, RUN-003 | Label automatic and guided flows separately. |
| UI-003 | Build the Testing view with polling and cancellation. | **In progress** | RUN-003 | Live scan polling, scan ID, counters, completed-state navigation, and cancellation are connected; detailed live progress remains. |
| UI-004 | Build the Results view. | **In progress** | RPT-001, RPT-002 | Results view lists persisted past runs, retains Scan ID search, displays outcomes and counts, and is reached from Testing after completion; live refresh remains. |
| UI-005 | Add report downloads and offline reanalysis controls. | **In progress** | RUN-003, EVD-005 | Results view links JSON/HTML downloads; reanalysis control and result-version display remain. |
| UI-006 | Package the frontend for the local backend to serve. | **Done** | FND-005, FND-006 | FastAPI serves `frontend/dist`; production build and backend static-serving test pass. |

## 9. Evaluation and Release Tasks

Primary owner: **Member 5**, with Member 3 helping prepare controlled
applications. All members contribute to integration and release checks.

| ID | Task | Status | Depends on | Completion notes |
| --- | --- | --- | --- | --- |
| EVA-001 | Prepare the server-rendered form/cookie application with secure and vulnerable modes. | **Done** | — | `controlled_app.py`; unit and real-Chromium tests cover redirects, changing single-use CSRF tokens, cookie sessions, isolated anonymous access, account enumeration, registration, reset, throttling, session rotation, and logout invalidation. Explicit prerequisite for AUTH-003. |
| EVA-002 | Prepare the React/JSON two-step bearer-token application. | **Not started** | — | Layout and API behavior must differ from EVA-001. |
| EVA-003 | Independently prepare the withheld-layout evaluation application. | **Not started** | — | Discovery implementers must not tune against it. |
| EVA-004 | Run each supported discovery flow five times per relevant application. | **Not started** | AUTH-006, EVA-001–EVA-003 | Report automatic and guided completion separately. |
| EVA-005 | Execute at least 24 required security-check scenarios. | **Not started** | CHK-001–CHK-006 | Four scenario types for each of six checks. |
| EVA-006 | Test timeouts, Bedrock outages, stale flows, missing features, cancellation, and unsupported authentication. | **Not started** | Integrated application | Every failure needs an explicit outcome. |
| EVA-007 | Verify analyzers and reports with target, browser, AWS, and network unavailable. | **Not started** | EVD-005, RPT-001, RPT-002 | Enforce offline behavior in automated tests. |
| EVA-008 | Measure discovery reliability, request volume, model usage, and cost. | **Not started** | Integrated application | Measure consumption before credits. |
| EVA-009 | Complete a clean installation and scan on another team member's computer. | **Not started** | Integrated application | Must not install or start mitmproxy. |
| REL-001 | Freeze features and document known limitations. | **Not started** | EVA-004–EVA-009 | Do not present incomplete checks as complete. |
| REL-002 | Complete installation and OWASP coverage documentation. | **Not started** | REL-001 | Include supported and unsupported behavior. |
| REL-003 | Record the demonstration video. | **Not started** | REL-001, REL-002 | Show setup, discovery/guidance, testing, evidence, and reports. |
| REL-004 | Perform final review and submit. | **Not started** | REL-003 | Target 28–29 September. |

## 10. Acceptance-Criteria Tracking

This table mirrors Section 5.4 of the project plan. Detailed test cases should
be linked here as they are created.

| Acceptance area | Status | Current gap |
| --- | --- | --- |
| Six checks and 24 scenarios | **In progress** | `CHK-001` covers secure, vulnerable, ambiguous, and execution-failure scenarios; five checks remain. |
| Runner/analyser separation | **In progress** | `CHK-001` keeps browser execution in the runner and analysis in an offline function; remaining checks are pending. |
| Repeatable analysis | **In progress** | `CHK-001` analyser output is tested for repeatable outcome/explanation; versioned result storage is implemented. |
| Offline reporting | **Done** | JSON and HTML reports are generated from local evidence/results without target, browser, AWS, or network access. |
| Generality | **In progress** | Scope and observation logic contain no application-name or fixed-route branches. Discovery and checks remain untested. |
| Discovery reliability | **In progress** | One live Nova Micro run completed the controlled login in three decisions. The required five-run measurements on each relevant evaluation application remain pending. |
| Guided fallback | **In progress** | Structured guided recording and replay work with local credential references; the guidance API and React controls remain pending. |
| Authentication proof | **In progress** | End-to-end automatic and guided login proof passes on the controlled application, including saved-flow replay in fresh contexts; the second authentication style remains pending. |
| Session isolation | **In progress** | Authentication-profile replay uses separate fresh authenticated and anonymous browser contexts; broader session replay for security checks remains pending. |
| Stateful flows | **Not started** | No changing-CSRF or changing-control test exists. |
| Failure handling | **In progress** | Automatic action failures retry twice before an explicit guidance-required outcome, and decision, time, and cost limits stop cleanly. Scan lifecycle, cancellation, stale flows, and unsupported-authentication outcomes remain. |
| Privacy and scope | **In progress** | URL, embedded-credential, session, input-value, origin-blocking, and Bedrock sanitization cases are tested. Full evidence-export redaction remains pending. |
| Installation | **In progress** | Local virtual environment and Chromium work; clean documented setup on another computer is pending. |

## 11. Immediate Execution Order

Unless a dependency changes, implement the next work in this order:

1. **RUN-001–RUN-003:** Add scan lifecycle, worker, and API orchestration around
   the completed browser/analyser/report slice.
2. **UI-002–UI-005:** Connect discovery guidance, scan progress, results, report
   downloads, and offline reanalysis to the backend.
3. **CHK-002 and CHK-003:** Add registration and reset-request enumeration using
   the established runner/analyser/evidence/report pattern.

The first three items extend the completed first runner-to-analyser-to-report
slice into an actual scan workflow and then cover the remaining enumeration
checks before session checks are added.
