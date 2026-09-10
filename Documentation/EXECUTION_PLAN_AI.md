# AuthFlowGuard AI — Execution Plan and Progress Tracker

This document tracks implementation progress for the work defined in
[PROJECT_PLAN_AI.md](PROJECT_PLAN_AI.md). The project plan remains the source of
truth for scope, architecture, security rules, responsibilities, schedule, and
acceptance criteria. This execution plan translates that direction into tasks
that can be assigned, implemented, tested, and marked complete.

**Tracking started:** 10 September 2026

**Target submission:** 28–29 September 2026

**Last updated:** 10 September 2026

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
| Repository and backend foundation | **In progress** | Python package, shared models, and FastAPI health endpoint exist. The React application and local frontend/backend connection do not exist yet. |
| Playwright observations | **In progress** | A browser can record redacted observations and execute all validated `BrowserAction` types. Evidence still needs to be associated with individual action IDs and observable changes. |
| Verified authentication information | **In progress** | A profile builder enforces authenticated and anonymous account-marker evidence. A complete login flow has not yet produced and replayed a verified profile. |
| Bedrock integration | **Not started** | No Converse API request or cost guard exists. |
| Security checks | **Not started** | No complete runner/analyser pair exists. |
| Evidence persistence and reports | **Not started** | Models exist, but scan directories, append-only logs, result versioning, HTML reports, and JSON exports are not implemented. |
| Interface | **Not started** | No React/Vite application exists. |
| Evaluation and release | **Not started** | Evaluation applications, reliability measurements, installation test, and demonstration are pending. |

Current automated verification: **14 tests passing**, including real Chromium
tests against controlled local pages. There is one non-blocking
deprecation warning from Starlette's test client.

## 3. Delivery Milestones

These milestones follow the dates and priorities in Section 5.2 of the project
plan.

| Milestone | Target dates | Status | Completion condition |
| --- | --- | --- | --- |
| **M0 — Working foundation** | 10–12 Sep | **In progress** | Shared models, backend, React connection, Playwright worker, and one bounded Bedrock request all work locally. |
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
| FND-003 | Define the six shared Pydantic contracts and supporting types. | **Done** | FND-001 | `backend/authflowguard/models.py`; serialization and validation tests |
| FND-004 | Create a minimal FastAPI application and health endpoint. | **Done** | FND-001 | `backend/authflowguard/app.py`; `backend/tests/test_app.py` |
| FND-005 | Create the React, TypeScript, and Vite application. | **Not started** | FND-001 | Must build successfully from a clean installation. |
| FND-006 | Connect the local React interface to the FastAPI health endpoint. | **Not started** | FND-004, FND-005 | Browser test or documented repeatable check required. |
| FND-007 | Make Playwright and Chromium installation reproducible. | **In progress** | FND-001 | Python dependency is declared and Chromium works locally; installation instructions or setup automation are still required. |
| FND-008 | Perform one structured Bedrock Converse API action request. | **Not started** | FND-001 | Must use explicit profile, region, model ID, sanitized input, and a small cost limit. |
| FND-009 | Add project-wide formatting, linting, and type-checking commands. | **Not started** | FND-001 | Checks should favor clear diagnostics and run locally. |

## 5. Website Interaction and Authentication Tasks

Primary owners: **Member 2** for browser/AI interaction and **Member 1** for
authentication information.

| ID | Task | Status | Depends on | Evidence or completion notes |
| --- | --- | --- | --- | --- |
| INT-001 | Enforce permitted origins and redact query strings and fragments. | **Done** | FND-003 | `scope.py`; scope and browser-level tests |
| INT-002 | Record requests, responses, page controls, cookies, and browser storage without saving live secrets. | **Done** | FND-003, FND-007 | `playwright_worker.py`; controlled Chromium test |
| INT-003 | Implement validated execution for every `BrowserAction` type. | **Done** | INT-002 | `action_executor.py`; Chromium tests cover navigate, click, fill by secret reference, select, key press, wait, URL redaction, and scope rejection. |
| INT-004 | Associate request and response evidence with scan and action identifiers. | **In progress** | INT-002, INT-003 | Actions now have stable IDs and execution results; browser evidence is not yet grouped by action. |
| INT-005 | Detect and describe observable page changes after an action. | **Not started** | INT-003 | Must avoid treating a URL, cookie, or status code alone as login proof. |
| INT-006 | Implement automatic action selection through Bedrock. | **Not started** | FND-008, INT-003, INT-005 | The model returns validated structured actions, never executable code. |
| INT-007 | Limit AI decisions, retry failed actions twice, and request guidance. | **Not started** | INT-006 | Enforce configured scan and cost limits. |
| INT-008 | Record developer-guided actions with local credential references. | **Not started** | INT-003 | Guidance must not store credential values. |
| INT-009 | Replay a recorded flow in a fresh browser context. | **Not started** | INT-003, INT-008 | Required for guided fallback acceptance. |
| INT-010 | Stop browser and HTTP work cleanly when cancellation is requested. | **Not started** | INT-003 | Preserve completed evidence and mark unfinished work cancelled. |
| AUTH-001 | Define saved, nonsecret authentication-profile data. | **Done** | FND-003 | `AuthProfile` and supporting models |
| AUTH-002 | Require an authenticated account marker and anonymous comparison. | **Done** | AUTH-001 | `auth_profiles.py`; positive and rejection tests |
| AUTH-003 | Discover and execute a complete login flow on a controlled form application. | **Not started** | INT-003, INT-005 | Must include CSRF-safe browser form submission. |
| AUTH-004 | Verify the protected resource in authenticated and isolated anonymous contexts. | **Not started** | AUTH-003 | Both evidence references must be saved in the profile. |
| AUTH-005 | Produce and replay a verified `AuthProfile` in a fresh context. | **Not started** | AUTH-004, INT-009 | Completes the first technical milestone from the project plan. |
| AUTH-006 | Support two-step login and bearer-token sessions. | **Not started** | AUTH-005 | Verify on the controlled React/JSON application. |
| AUTH-007 | Revalidate saved flows before reuse in a new scan. | **Not started** | AUTH-005 | Stale flows must request guidance or produce an explicit outcome. |
| AUTH-008 | Keep live credentials in worker memory and discard them on completion or cancellation. | **In progress** | INT-003, INT-010 | `RuntimeSecrets` resolves and discards in-memory values. Cancellation, export, and model-request coverage remain pending. |

## 6. Scan Execution, Evidence, and Reporting Tasks

Primary owners: **Member 1** for lifecycle and **Member 4** for evidence and
reporting.

| ID | Task | Status | Depends on | Evidence or completion notes |
| --- | --- | --- | --- | --- |
| RUN-001 | Define the scan state machine, including awaiting-guidance and cancellation. | **Not started** | FND-003 | State transitions and invalid transitions need unit tests. |
| RUN-002 | Run one scan at a time in a worker process separate from FastAPI. | **Not started** | RUN-001 | Server must remain responsive while the browser runs. |
| RUN-003 | Add APIs for create, status, events, guidance, cancellation, downloads, and reanalysis. | **Not started** | RUN-001 | Validate all request and response models. |
| EVD-001 | Create per-scan directories and metadata files. | **Not started** | RUN-001 | Paths must remain within the configured local data directory. |
| EVD-002 | Implement the append-only evidence event log. | **Not started** | EVD-001 | Survive restart without corrupting completed evidence. |
| EVD-003 | Implement central redaction before evidence is written. | **Not started** | EVD-002 | Test passwords, cookies, tokens, headers, URLs, and response bodies. |
| EVD-004 | Save compact per-check evidence packages and explicit coverage. | **Not started** | EVD-002 | Packages must support offline analysis without target access. |
| EVD-005 | Save versioned results without overwriting earlier analysis. | **Not started** | EVD-004 | Reanalysis creates a new result version. |
| RPT-001 | Generate a JSON report offline. | **Not started** | EVD-005 | No browser, target, Bedrock, or credentials may be required. |
| RPT-002 | Generate a readable and printable HTML report offline. | **Not started** | EVD-005 | Show evidence, limitations, and incomplete coverage clearly. |

## 7. Security Check Tasks

Each check requires a browser runner and a separate deterministic offline
analyser. Every analyser must accept the equivalent of
`analyse(evidence, profile, policy) -> CheckResult`.

| ID | Check | Primary owner | Status | Required scenario set |
| --- | --- | --- | --- | --- |
| CHK-001 | Login account enumeration — WSTG-IDNT-04 | Member 3 | **Not started** | Vulnerable, secure, ambiguous, execution failure |
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
| UI-001 | Build the Setup view. | **Not started** | FND-005, RUN-003 | Target, origins, references, policies, limits, and selected checks |
| UI-002 | Build the Discovery view and guidance controls. | **Not started** | INT-007, INT-008, RUN-003 | Label automatic and guided flows separately. |
| UI-003 | Build the Testing view with polling and cancellation. | **Not started** | RUN-003 | Poll once per second; show progress, requests, and outcomes. |
| UI-004 | Build the Results view. | **Not started** | RPT-001, RPT-002 | Show evidence and incomplete coverage without an aggregate score. |
| UI-005 | Add report downloads and offline reanalysis controls. | **Not started** | RUN-003, EVD-005 | Preserve and display result versions. |
| UI-006 | Package the frontend for the local backend to serve. | **Not started** | UI-001–UI-005 | Production build runs without a separate development server. |

## 9. Evaluation and Release Tasks

Primary owner: **Member 5**, with Member 3 helping prepare controlled
applications. All members contribute to integration and release checks.

| ID | Task | Status | Depends on | Completion notes |
| --- | --- | --- | --- | --- |
| EVA-001 | Prepare the server-rendered form/cookie application with secure and vulnerable modes. | **Not started** | — | Include redirects and changing CSRF tokens. |
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
| Six checks and 24 scenarios | **Not started** | No runner/analyser pair exists. |
| Runner/analyser separation | **Not started** | Shared models establish the boundary, but it is not implemented. |
| Repeatable analysis | **Not started** | Result serialization is tested; analyser determinism is not. |
| Offline reporting | **Not started** | No report generator exists. |
| Generality | **In progress** | Scope and observation logic contain no application-name or fixed-route branches. Discovery and checks remain untested. |
| Discovery reliability | **Not started** | No action selection or repeated flow execution exists. |
| Guided fallback | **Not started** | No guidance API or recorder exists. |
| Authentication proof | **In progress** | Profile builder enforces authenticated/anonymous marker comparison; end-to-end login proof is pending. |
| Session isolation | **Not started** | Observation uses a fresh context, but replay experiments are not implemented. |
| Stateful flows | **Not started** | No changing-CSRF or changing-control test exists. |
| Failure handling | **Not started** | No scan lifecycle or explicit failure outcomes are implemented. |
| Privacy and scope | **In progress** | URL and session redaction plus origin blocking are tested; full export and Bedrock sanitization tests are pending. |
| Installation | **In progress** | Local virtual environment and Chromium work; clean documented setup on another computer is pending. |

## 11. Immediate Execution Order

Unless a dependency changes, implement the next work in this order:

1. **INT-004 and INT-005:** Attach evidence to action IDs and measure observable
   page changes.
2. **AUTH-003 and AUTH-004:** Run a controlled login and prove protected access
   against an anonymous context.
3. **INT-009 and AUTH-005:** Replay the saved flow in a fresh context and produce
   a verified profile.
4. **FND-008:** Prove one bounded, sanitized Bedrock structured-action request.
5. **FND-005 and FND-006:** Scaffold React and connect it to the local backend.
6. **CHK-001, EVD-001–EVD-005, and RPT-001–RPT-002:** Complete the first
   runner-to-analyser-to-report slice.

The first three items complete the project's first technical milestone. The
sixth item completes the required second technical milestone and establishes
the pattern for the remaining five checks.
