# AuthFlowGuard AI — Execution Plan and Progress Tracker

This document tracks implementation progress for the work defined in
[PROJECT_PLAN_AI.md](PROJECT_PLAN_AI.md). The project plan remains the source of
truth for scope, architecture, security rules, responsibilities, schedule, and
acceptance criteria. This execution plan translates that direction into tasks
that can be assigned, implemented, tested, and marked complete.

The remaining teammate assignments, dependencies, deliverables, and update
format are maintained in
[WORK_BREAKDOWN_STRUCTURE.md](WORK_BREAKDOWN_STRUCTURE.md).

This execution plan is the Team Lead's technical progress and evidence tracker.
Teammates should use the WBS for their assignments and maintain a small GitHub
issue or individual work plan for their own implementation steps. They should
send completion evidence to the Team Lead instead of creating a separate
project-wide execution plan.

**Tracking started:** 10 September 2026

**Target submission:** 28–29 September 2026

**Last updated:** 14 September 2026

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
| Playwright observations | **In progress** | A bounded Bedrock-driven loop converts sanitized observations into validated browser actions, records action traffic and page changes, and completes the controlled login with an offline model double. Guided observation exposes safe control metadata through the API and Discovery UI; deterministic two-step JSON actions are now covered, while broader SPA layouts remain pending. |
| Verified authentication information | **In progress** | Automatic and guided login flows produce verified profiles from authenticated and isolated anonymous account-marker evidence, and saved flows replay in fresh contexts. Conventional forms and a React/JSON bearer-token flow are covered; broader session replay remains pending. |
| Bedrock integration | **In progress** | The structured Converse client and live CLI completed the controlled login in three model decisions within the configured cost cap. Sanitization, validation, limits, retry feedback, and guidance escalation are tested. Usage persistence across restarts remains pending. |
| Security checks | **Done** | `CHK-001` through `CHK-006` have browser runners, offline analysers, persisted evidence, scan integration, and coverage tests. |
| Evidence persistence and reports | **In progress** | `EvidenceStore` writes bounded redacted scan evidence, append-only events, and versioned results; offline JSON/HTML export and first-slice scan API integration are implemented. Worker-process separation remains pending. |
| Interface | **In progress** | The four-view React shell submits Setup data, starts a local scan, pauses for guided discovery, presents plain-language control choices, submits guided flows, polls live status, lists persisted past runs, and keeps Scan ID search; full result controls remain pending. |
| Evaluation and release | **In progress** | The first controlled evaluation application is complete. The second and withheld-layout applications, reliability measurements, installation test, and demonstration are pending. |

Current automated verification: **187 tests passing**: 177 backend tests and 10
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
| **M2 — First complete security check** | 13–16 Sep | **Done** | The first complete runner/analyser/report slice is integrated and tested. |
| **M3 — All six checks integrated** | 17–21 Sep | **Done** | All six runner/analyser pairs use the common evidence and result pipeline. |
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
| AUTH-006 | Support two-step login and bearer-token sessions. | **Done** | AUTH-005 | Deterministic discovery supports username → JSON verification step → bearer-token storage, and fresh-context proof records only storage fingerprints. Covered by `react_json_app.py` and browser/API tests. |
| AUTH-007 | Revalidate saved flows before reuse in a new scan. | **Done** | AUTH-005 | Completed profiles retain nonsecret control signatures. A matching new scan revalidates the current login page before replay; missing, added, changed, or legacy unsigned controls return the scan to `awaiting_guidance`. |
| AUTH-008 | Keep live credentials in worker memory and discard them on completion or cancellation. | **In progress** | INT-003, INT-010 | `RuntimeSecrets` resolves and discards in-memory values. Cancellation, export, and model-request coverage remain pending. |

## 6. Scan Execution, Evidence, and Reporting Tasks

Primary owners: **Member 1** for lifecycle and **Member 4** for evidence and
reporting.

| ID | Task | Status | Depends on | Evidence or completion notes |
| --- | --- | --- | --- | --- |
| RUN-001 | Define the scan state machine, including awaiting-guidance and cancellation. | **In progress** | FND-003 | `ScanState` and cancellation transitions are implemented; explicit invalid-transition coverage remains. |
| RUN-002 | Run one scan at a time in a worker process separate from FastAPI. | **In progress** | RUN-001 | A single background executor currently keeps FastAPI responsive; a separate worker process remains. |
| RUN-003 | Add APIs for create, status, events, guidance, cancellation, downloads, and reanalysis. | **In progress** | RUN-001 | Create/status/events/cancellation/download/reanalysis and guidance observation/submission endpoints are implemented; broader lifecycle and worker-process hardening remain. |
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
| CHK-002 | Registration account enumeration — WSTG-IDNT-04 | Member 3 | **Done** | `registration_enumeration.py` uses the shared native-form runner/analyser in `form_enumeration.py`; one fresh known/nonexistent pair avoids resubmitting a newly created account. `test_form_enumeration.py` and `test_enumeration_scans.py` cover secure/vulnerable, incomplete/malformed, execution failure, redaction, cancellation, automatic/guided scans, persistence, and reanalysis. |
| CHK-003 | Reset-request account enumeration — WSTG-IDNT-04 | Member 3 | **Done** | `reset_request_enumeration.py` captures a fresh known/nonexistent pair and runs before registration to preserve nonexistent-account state. The shared tests cover outcomes, CSRF/session isolation, nonstandard routes, offline determinism, selected-check execution, reports, and reanalysis. The Setup check ID now maps to `reset_request_enumeration`. |
| CHK-004 | Login throttling and lockout — WSTG-ATHN-03 | Member 5 | **Done** | `login_throttling.py` runs bounded failed attempts in fresh contexts followed by a valid-login control. Offline tests cover secure, vulnerable, explicit thresholds, malformed evidence, unexpected server errors, cancellation, deterministic analysis, and scan persistence/reanalysis. |
| CHK-005 | Session fixation — WSTG-SESS-03 | Member 5 | **Done** | `session_fixation.py` captures pre-login cookie state, verifies authenticated access, and replays the original state in an isolated context. The completed scope covers username/password login with cookie sessions; OTP/additional-fill and bearer-token replay remain unsupported. Tests cover secure, vulnerable, malformed, deterministic, and execution-error outcomes. |
| CHK-006 | Logout invalidation — WSTG-SESS-06 | Member 5 | **Done** | `logout_invalidation.py` verifies login, submits the discovered logout form, and replays the captured cookie session against authenticated and anonymous controls. The completed scope supports identifiable HTML logout forms that produce POST responses; logout links and other JavaScript/HTTP-method patterns remain unsupported. Tests cover secure, vulnerable, malformed, deterministic, and execution-error outcomes. |

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
| UI-002 | Build the Discovery view and guidance controls. | **Done** | INT-007, INT-008, RUN-003 | Discovery pauses after automatic discovery failure, observes a selected in-scope page, maps structured navigate/fill/click actions to safe control references, and labels guided profiles separately. |
| UI-003 | Build the Testing view with polling and cancellation. | **In progress** | RUN-003 | Live scan polling, scan ID, counters, completed-state navigation, and cancellation are connected; detailed live progress remains. |
| UI-004 | Build the Results view. | **In progress** | RPT-001, RPT-002 | Results view lists persisted past runs, retains Scan ID search, displays outcomes and counts, and is reached from Testing after completion; live refresh remains. |
| UI-005 | Add report downloads and offline reanalysis controls. | **In progress** | RUN-003, EVD-005 | Results view links JSON/HTML downloads; reanalysis control and result-version display remain. |
| UI-006 | Package the frontend for the local backend to serve. | **Done** | FND-005, FND-006 | FastAPI serves `frontend/dist`; production build and backend static-serving test pass. |
| UI-007 | Refine guided discovery into plain-language questions about missing login information. | **Done** | UI-002, RUN-003 | Discovery explains why the scan paused, reuses Setup credentials, offers recognizable username/password/button choices from fresh observations, clears stale selections after refresh, and keeps proof overrides under Advanced settings. Frontend behavior and submission tests pass. |

### 8.1. Guided Discovery Refinement

**Status: Done.** UI-007 implemented this refinement on top of the UI-002
fallback. The interface now explains why a scan paused, reuses Setup
credentials, presents recognizable field and button choices, clears stale
selections after refreshed observations, and keeps proof overrides under
Advanced settings. The requirements below record the user feedback received on
13 September 2026 and the behavior covered by the completed implementation.

The feedback asked AuthFlowGuard to explain which part of logging in needs help,
then ask for the information needed to continue. The earlier wording, especially
"Observe target controls," was too technical. The implemented design supports
the familiar sequence of entering a username or email and password, selecting
Sign in, and reaching an account page or dashboard.

#### Implemented interaction

1. **Explain the pause and the specific help needed.** Use a heading such as
   "Help us log in." When supported by observations, say, for example, "We found
   more than one possible sign-in button. Which one do you normally use?"
   Distinguish missing fields, ambiguous choices, and a page that could not be
   opened. If the cause is unknown, say so and start by checking the login page.
   Keep raw diagnostics in expandable technical details.
2. **Ask only for missing or uncertain information.** Reuse the login details
   entered in Setup and retain information already identified reliably. Ask
   "Which page do you use to log in?" when the page needs clarification, then
   offer "Find login fields." Show one focused question at a time or a short
   group of related questions, rather than a full action editor at the outset.
3. **Offer recognizable field and button choices.** Ask "Which field is for
   your username or email?", "Which field is for your password?", or "Which
   button signs you in?" as needed. Present available labels and helpful page
   context instead of requiring users to copy IDs such as `control-5`. Allow
   "I can't find the right field or button" and explain how to check the URL or
   refresh the choices. Do not silently guess when choices are ambiguous.
4. **Explain how login success will be checked.** Reuse the check configured in
   Setup, with a plain-language explanation that the account page must contain
   something visible only after signing in. Put selector and URL overrides under
   "Advanced: change how login is checked," with examples. Do not imply that a
   dashboard URL or the word "Dashboard" alone proves a successful login.
5. **Review and continue.** Summarize the proposed steps in everyday language:
   open the login page, enter the test account details, and select the chosen
   sign-in button. Use "Check login and continue" for submission. Explain that
   AuthFlowGuard will try these steps, verify login, and then resume the scan.
   If verification fails, explain what failed and what information to correct.

These questions can use ordinary form inputs and selections; a conversational
chat interface or live browser recorder is not required for this refinement.
The current implementation also covers the controlled React/JSON two-step
bearer-token flow; broader SPA layouts remain part of the generality evaluation.

#### Implemented wording

| Earlier wording | Implemented user-facing wording |
| --- | --- |
| Guided discovery | Help us log in |
| Page to observe | Login page address |
| Observe target controls | Find login fields |
| Observed controls | Fields and buttons found on this page |
| Authentication flow | Steps to log in |
| Credential references only | Use the test account details from Setup |
| Protected-resource proof | How we check that login worked |
| Save and verify guided flow | Check login and continue |

#### Completion evidence for UI-007

- A user can explain why the scan paused, what information is missing, and what
  will happen after submission without knowing browser automation terminology.
- The standard login path requires no manual control IDs, action types,
  credential-reference names, or repeated entry of Setup credentials.
- Reliably identified information is retained and reviewable; questions focus
  on unresolved information. Backend status or observation data must support
  any claim about what was found or what failed.
- Missing, ambiguous, unnamed, and stale field/button choices have clear
  recovery instructions. Refreshing or changing the page invalidates outdated
  selections, and incomplete answers cannot be submitted as a valid flow.
- Advanced verification settings remain available and explain the required
  selector honestly. Login proof still checks separate signed-in and signed-out
  sessions, and saved actions continue to exclude live credentials.
- Frontend behavior tests cover focused questions, recognizable choices, Setup
  reuse, recovery, and submission. The controlled-application guided-login
  walkthrough is documented in `Documentation/DEVELOPMENT.md`. Broader user
  evaluation remains part of the release evaluation rather than UI-007's
  implementation status.

## 9. Evaluation and Release Tasks

Primary owner: **Member 5**, with Member 3 helping prepare controlled
applications. All members contribute to integration and release checks.

| ID | Task | Status | Depends on | Completion notes |
| --- | --- | --- | --- | --- |
| EVA-001 | Prepare the server-rendered form/cookie application with secure and vulnerable modes. | **Done** | — | `controlled_app.py`; unit and real-Chromium tests cover redirects, changing single-use CSRF tokens, cookie sessions, isolated anonymous access, account enumeration, registration, reset, throttling, session rotation, and logout invalidation. Explicit prerequisite for AUTH-003. |
| EVA-002 | Prepare the React/JSON two-step bearer-token application. | **Done** | — | `react_json_app.py` exposes secure/vulnerable modes, JSON start/verify endpoints, localStorage bearer sessions, and an account marker page with a deliberately different SPA layout. |
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
| Six checks and 24 evaluated scenarios | **In progress** | Automated tests cover secure, vulnerable, ambiguous/incomplete, and execution-failure outcomes for CHK-001 through CHK-006. EVA-005 must still execute and document the formal 24-scenario evaluation matrix. |
| Runner/analyser separation | **Done** | All six checks keep browser execution separate from offline analysis. Reanalysis dispatches every stored evidence record to its check-specific analyser. |
| Repeatable analysis | **Done** | All six checks produce deterministic results for identical evidence/policy/version. Reanalysis retains version files and exposes only the latest result per evidence, including after restart. |
| Offline reporting | **Done** | JSON and HTML reports are generated from local evidence/results without target, browser, AWS, or network access. |
| Generality | **In progress** | Scope and observation logic contain no application-name or fixed-route branches. Guided observation/replay and the React/JSON bearer flow are tested on separate controlled applications; withheld-layout evaluation remains pending. |
| Discovery reliability | **In progress** | One live Nova Micro run completed the controlled login in three decisions. The required five-run measurements on each relevant evaluation application remain pending. |
| Guided fallback | **Done** | Automatic discovery failures transition to `awaiting_guidance`; the guidance API and React Discovery UI observe safe controls, present plain-language choices, accept credential references, verify fresh authenticated/anonymous contexts, persist `auth-profile.json`, and label the profile source. The UI is a structured choice flow rather than live browser clicking. |
| Authentication proof | **In progress** | End-to-end automatic and guided login proof passes on the controlled form and React/JSON applications, including saved-flow replay in fresh contexts; broader session replay remains pending. |
| Session isolation | **In progress** | Authentication-profile replay uses separate fresh authenticated and anonymous browser contexts. CHK-005/006 isolate cookie-session replays for username/password flows; OTP/additional-fill flows, bearer-token storage replay, and non-POST logout patterns remain pending. |
| Stateful flows | **Done** | CHK-002/003 verify fresh CSRF and cookie sessions, CHK-004 uses fresh contexts for each attempt, and CHK-005/006 isolate pre-login and pre-logout session replays. Broader stateful layouts remain pending. |
| Failure handling | **In progress** | Automatic action failures retry twice before an explicit guidance-required outcome, and decision, time, cost, and stale-flow limits stop cleanly. Scan lifecycle, cancellation, and unsupported-authentication outcomes remain. |
| Privacy and scope | **In progress** | URL, embedded-credential, session, input-value, origin-blocking, and Bedrock sanitization cases are tested. Full evidence-export redaction remains pending. |
| Installation | **In progress** | Local virtual environment and Chromium work; clean documented setup on another computer is pending. |

## 11. Immediate Execution Order

The CHK-005/CHK-006 implementation batch is complete. See Development Sections 12 through 14 for manual verification, bounded lockout behavior, session replay behavior, reanalysis, and known limits.

The next implementation batch covers additional target applications, worker-process separation, broader bearer-session support, and release evaluation.
