# AuthFlowGuard AI — Remaining Work Breakdown Structure

**Prepared:** 14 September 2026  
**Target submission:** 28–29 September 2026

## 1. Purpose

This document explains the remaining work in plain English. It tells each
teammate what they own, why the work matters, what they need to do, and how they
can prove that the task is complete.

Members 2 through 5 own the work below. The Team Lead coordinates the team,
reviews results, resolves decisions, and approves completed work. The Team Lead
is not assigned a separate implementation workload here.

The foundation and all six security checks are already implemented. The
remaining goal is to make the application reliable, finish the interface, test
it on different applications, and prepare the final submission.

## 2. How to Use the Project Documents

The project should have one shared plan. Each teammate may also create a short
plan for their own assigned work.

| Document | What it is for | Who maintains it |
| --- | --- | --- |
| PROJECT_PLAN_AI.md | The agreed scope, architecture, security rules, and acceptance criteria | Team Lead, with team approval for major changes |
| WORK_BREAKDOWN_STRUCTURE.md | The shared assignment list: who owns each area and what they must deliver | Team Lead |
| EXECUTION_PLAN_AI.md | The detailed technical progress record and evidence tracker | Team Lead |
| GitHub issue or individual work plan | The steps one teammate will take to finish an assigned task | That teammate |

Teammates should create their own small work plans. They may decide how to
implement their tasks, divide them into smaller steps, and estimate their time.
Their plans must still follow the shared project scope, safety rules, required
results, and deadlines.

Teammates should not create separate versions of the overall project plan.

## 3. Work Already Completed

The team can build on the following completed work:

- The Python, FastAPI, Playwright, React, and TypeScript foundation.
- Automatic login discovery and guided login setup.
- Verified login profiles and saved-login replay.
- All six security-check runners and offline analysers.
- Saved evidence, versioned results, and JSON and HTML reports.
- Automated backend, browser, and frontend tests.
- A form-and-cookie test application.
- A React and JSON test application using bearer-token authentication.

These areas should not be rebuilt unless testing reveals a defect.

## 4. Responsibility Summary

| Member | Main responsibility | Expected result |
| --- | --- | --- |
| **Member 2** | Make scan execution, cancellation, credential handling, and AI usage reliable | Scans stop safely, recover from failures, and do not leak credentials |
| **Member 3** | Build an independent third test application and prepare the evaluation cases | The product is tested fairly against an unfamiliar application |
| **Member 4** | Complete the Setup, Testing, Results, download, and reanalysis screens | A user can complete and understand the whole workflow |
| **Member 5** | Lead formal testing, failure testing, reliability measurement, and cost measurement | The final claims are supported by repeatable evidence |
| **Members 2–5** | Help prepare installation, documentation, demonstration, and final review | The project can be installed, demonstrated, and submitted confidently |

## 5. Member 2 — Reliable Scan Execution

### Task 2.1 — Make cancellation work everywhere

**Tracker item:** INT-010

**Why this matters:** A user must be able to stop a scan without leaving a
browser, network request, or background task running.

**What to do:**

- Check for cancellation during automatic discovery, guided login replay,
  authentication verification, and every security check.
- Stop Playwright actions, navigation, and response waits when possible.
- Close all pages, browser contexts, and browser processes.
- Keep evidence completed before cancellation.
- Clearly mark unfinished work as cancelled.

**Done when:**

- Tests cancel scans during discovery, login verification, and security checks.
- No browser or background task remains after cancellation.
- Cancellation never appears as a completed or secure result.

### Task 2.2 — Protect and discard credentials

**Tracker item:** AUTH-008

**Why this matters:** Passwords and other credentials must remain in memory only
while they are needed.

**What to do:**

- Discard credentials after success, failure, cancellation, and unexpected
  exceptions.
- Check model requests, logs, scan metadata, events, evidence, and reports for
  credential values.
- Add tests for all of these paths.

**Done when:**

- Tests confirm that supplied credentials are absent from all saved and
  displayed information.
- Credentials are discarded regardless of how the scan ends.

### Task 2.3 — Make scan states and API errors predictable

**Tracker items:** RUN-001 and RUN-003

**Why this matters:** The interface needs a clear answer when an action is not
allowed, such as reanalysing a running scan.

**What to do:**

- List every valid movement between created, running, awaiting-guidance,
  cancelled, failed, and completed states.
- Reject invalid start, guidance, cancellation, download, and reanalysis
  requests with clear responses.
- Preserve the correct state after a backend restart or worker failure.
- Ensure errors do not reveal credentials.

**Done when:**

- Tests cover valid and invalid actions for every scan state.
- The interface can rely on consistent status and error responses.

### Task 2.4 — Run scans outside the API process

**Tracker item:** RUN-002

**Why this matters:** A slow or failed browser scan must not freeze the API used
by the interface.

**What to do:**

- Move scan execution into a separate worker process.
- Keep the API responsive while a scan runs.
- Continue allowing only one active scan at a time.
- Handle a worker that hangs, crashes, or exits unexpectedly.

**Done when:**

- Health and status requests work during a long-running scan.
- A worker crash produces a clear failed or cancelled state.
- Existing scan and evidence tests continue to pass.

### Task 2.5 — Save AI usage and cost

**Why this matters:** Restarting the backend must not reset the token total or
allow a scan to exceed its cost limit.

**What to do:**

- Save input tokens, output tokens, and estimated cost.
- Restore the totals after a restart.
- Reserve the maximum expected cost before making a model request.

**Done when:**

- Restart tests confirm that usage totals and cost limits are preserved.

## 6. Member 3 — Additional Test Application and Test Cases

### Task 3.1 — Build a third, unfamiliar test application

**Tracker item:** EVA-003

**Why this matters:** The first two applications were developed alongside the
discovery logic. A separately designed application gives the team a fairer test
of whether AuthFlowGuard can adapt.

**What to do:**

- Build a local application without copying the labels, page layout, routes, or
  response fields of the existing applications.
- Include a login flow and a protected page containing account-specific
  information.
- Include secure and intentionally vulnerable behavior where practical.
- Document how to start, reset, and use it.
- Do not show its implementation to the discovery owner before the first
  recorded test. 

**Done when:**

- Another member can start it using one documented command.
- Fixture tests confirm its intended secure and vulnerable behavior.
- The first discovery results are recorded before the product is adjusted for
  this application.

### Task 3.2 — Prepare the 24 formal security-check cases

**Tracker item:** EVA-005

**Why this matters:** Automated tests cover the main outcomes, but the project
also requires a recorded evaluation.

**What to do:**

- Prepare four cases for each of the six checks:
  - a vulnerable case;
  - a secure case;
  - an ambiguous or incomplete case; and
  - an execution-failure case.
- Record the setup, expected result, actual result, evidence identifier, and
  pass or fail decision for every case.
- Give the completed checklist to Member 5 for execution.

**Done when:**

- The team has a complete 24-row evaluation checklist.
- Every executed row can be traced to saved evidence and a result.

### Task 3.3 — Review the session-check decisions

**Why this matters:** A second person should confirm that failed or unsupported
session testing is never described as secure behavior.

**What to do:**

- Review login throttling, session fixation, and logout invalidation results.
- Check the conditions for secure, vulnerable, inconclusive, and
  execution-error outcomes.
- Record unclear decisions before feature freeze.

**Done when:**

- Review notes identify what was checked and any corrections needed.

## 7. Member 4 — Complete the User Interface

### Task 4.1 — Finish the Setup screen

**Tracker item:** UI-001

**Why this matters:** Users need to set the required policies and limits without
manually creating API requests.

**What to do:**

- Add the remaining policy and execution-limit fields.
- Provide safe defaults and plain-English explanations.
- Keep uncommon settings in an Advanced section.
- Show clear validation and API errors.

**Done when:**

- Frontend tests cover defaults, invalid entries, submitted data, and API
  failures.

### Task 4.2 — Show useful scan progress

**Tracker item:** UI-003

**Why this matters:** A user should know what the application is doing and
whether it is waiting, cancelled, failed, or finished.

**What to do:**

- Show the current phase or security check.
- Show completed and remaining work when the API provides it.
- Explain awaiting-guidance, cancelling, cancelled, failed, and completed
  states.
- Show safe user-facing errors instead of raw internal messages.

**Done when:**

- Frontend tests cover every important scan state.

### Task 4.3 — Finish the Results screen

**Tracker item:** UI-004

**Why this matters:** Users need to understand the result, its evidence, and the
limits of the test.

**What to do:**

- Refresh results after a scan or reanalysis completes.
- Show the outcome, explanation, OWASP reference, and coverage limitations.
- Clearly explain finding confirmed, no issue observed, inconclusive, and
  execution error.

**Done when:**

- Tests cover empty, partial, completed, stale, and failed result responses.
- Incomplete testing is never presented as secure.

### Task 4.4 — Add reanalysis and result versions

**Tracker item:** UI-005

**Why this matters:** Users should be able to run the offline analysers again and
see that a new result version was created.

**What to do:**

- Add a Reanalyse action with progress and error feedback.
- Show the analyser and result version.
- Refresh the displayed result after reanalysis.
- Keep JSON and printable HTML downloads available.

**Done when:**

- Tests cover successful reanalysis, reanalysis while running, and API failure.

## 8. Member 5 — Formal Evaluation and Measurements

Formal measurements should begin only after the required runtime and interface
changes are merged and the team freezes the behavior being tested.

### Task 5.1 — Measure login discovery reliability

**Tracker item:** EVA-004

**Why this matters:** One successful demonstration does not show that discovery
works reliably.

**What to do:**

- Attempt each supported login flow five times on each relevant application.
- Record automatic successes separately from guided successes.
- Record why every failed attempt failed.
- Do not adjust the product for the third application until its first results
  are saved.

**Done when:**

- A table shows successes out of five for every tested flow and application.
- The development applications reach four automatic successes out of five, or
  the shortfall is documented.

### Task 5.2 — Execute the 24 security-check cases

**Tracker item:** EVA-005

**Why this matters:** This is the formal evidence that all six checks produce
the correct type of result in secure, vulnerable, unclear, and failed cases.

**What to do:**

- Run the checklist prepared by Member 3.
- Compare each result with the expected result.
- Save evidence and reports for every case.
- Investigate incorrect results and repeat affected cases after fixes.

**Done when:**

- All 24 rows contain a result and evidence reference.
- Incorrect results are fixed or recorded as limitations.

### Task 5.3 — Test failure situations

**Tracker item:** EVA-006

**Why this matters:** The application must fail clearly and safely when it
cannot finish a test.

**What to do:**

- Test timeouts, Bedrock outages, stale saved flows, missing target features,
  cancellation, worker failure, and unsupported authentication.
- Confirm that every case has a clear outcome and useful explanation.

**Done when:**

- No failed or unsupported test is reported as a security pass.

### Task 5.4 — Confirm offline analysis and reports

**Tracker item:** EVA-007

**Why this matters:** Analysers and reports must work from saved evidence without
contacting the target application or AWS.

**What to do:**

- Stop the target application and regenerate results and reports.
- Repeat without a browser, AWS credentials, or network access.

**Done when:**

- Reanalysis and report generation use saved local evidence only.

### Task 5.5 — Measure usage, cost, and duration

**Tracker item:** EVA-008

**Why this matters:** The final report must explain how reliable and expensive
the AI-assisted work is.

**What to do:**

- Record browser request counts.
- Record model input and output tokens.
- Record estimated cost before credits.
- Record discovery time and total scan time.
- State the configuration and number of runs used.

**Done when:**

- The final report contains a reproducible measurement table.

### Task 5.6 — Decide the final session-check scope

**Why this matters:** CHK-005 and CHK-006 currently focus on username and
password flows using browser cookies.

**What to do:**

- Decide whether time permits support for one-time-code login replay,
  bearer-token session replay, or non-POST logout.
- Keep anything not implemented as a clear known limitation.
- Confirm that unsupported behavior cannot produce a false security pass.

**Done when:**

- Each item is marked implemented, deferred, or outside the release, with a test
  or documentation reference.

## 9. Testing With Different Applications

AuthFlowGuard must be tested against more than the original form-based
application.

| Test application | Current state | What the team will test |
| --- | --- | --- |
| **Application A — Forms and cookie sessions** | Complete; has secure and vulnerable modes | Automatic and guided login, CSRF, redirects, all six checks, evidence, reports, and failure handling |
| **Application B — React, JSON, and bearer token** | Complete; has secure and vulnerable modes | Two-step login, changing controls, JSON requests, bearer-token login proof, login enumeration, and honest handling of unsupported session checks |
| **Application C — Independent withheld layout** | Member 3 will build it | General discovery, guided fallback, login proof, unfamiliar labels and routes, and any checks supported by its features |
| **Additional authorized application** | Optional if time permits | Extra evidence using a local or staging application owned by the team or explicitly approved for testing |

Only applications owned by the team or explicitly approved for testing may be
used.

### Required Tests Across Applications

| Test | Applications | Owner |
| --- | --- | --- |
| Run each supported discovery flow five times | Applications A, B, and C where applicable | Member 5 |
| Compare automatic and guided completion | Applications A, B, and C | Member 5 |
| Execute the 24 formal check cases | Mainly Application A and purpose-built incomplete or failure cases | Members 3 and 5 |
| Test unfamiliar labels, routes, and layout | Application C | Members 3 and 5 |
| Confirm unsupported behavior is reported honestly | Applications B and C | Member 5 |
| Perform a clean installation and complete scan | Application A on another computer | Member 3 |

Not every security check has to run against every application. If an application
does not provide a feature required by a check, record the check as not
applicable, unsupported, inconclusive, or an execution error as appropriate. Do
not count it as a security pass.

## 10. Installation and Release

### Task 10.1 — Test installation on another computer

**Owner:** Member 3  
**Tracker item:** EVA-009

- Follow only the written setup instructions.
- Install the project and Chromium.
- Start Application A and complete one full scan.
- Record and correct missing or confusing instructions.
- Confirm that mitmproxy is not required.

### Task 10.2 — Freeze features and list limitations

**Owner:** Member 5  
**Tracker item:** REL-001

- Stop adding optional features after formal evaluation begins.
- Combine all known limitations into one clear list.
- Confirm that incomplete behavior is not described as complete.

### Task 10.3 — Finish installation and OWASP documentation

**Owner:** Member 3  
**Tracker item:** REL-002

- Finalize installation, usage, and troubleshooting instructions.
- Map every check to its OWASP WSTG reference and supported boundary.

### Task 10.4 — Record the demonstration

**Owner:** Member 4  
**Tracker item:** REL-003

- Demonstrate Setup, discovery or guidance, testing, evidence, results, report
  download, and reanalysis.
- Record the demonstration only after feature freeze.

### Task 10.5 — Run the final technical checks

**Owner:** Member 2

- Run all backend and frontend checks from a clean checkout.
- Confirm that no secrets or generated scan evidence are committed.
- Record commands, test counts, software versions, and the final commit ID.

### Task 10.6 — Review and submit

Members 2 through 5 provide their completed work. The Team Lead approves and
submits the final package.

- Confirm that every required artifact is included.
- Confirm that every claim is supported by evidence.
- Submit on 28–29 September.
- Keep 30 September as a contingency date only.

## 11. Recommended Order

### Phase 1 — Work in parallel

- Member 2 starts runtime and cancellation work.
- Member 3 builds the third application and evaluation checklist.
- Member 4 completes interface work using the current API.
- Member 5 prepares evaluation tables and failure cases.

### Phase 2 — Integrate

- Members 2 and 4 agree on any API response changes.
- Merge the runtime, third-application, and interface work.
- Run the complete automated test suite.
- Fix blocking problems.

### Phase 3 — Freeze and evaluate

- Freeze the behavior being evaluated.
- Run discovery five times per relevant application.
- Execute the 24 formal cases.
- Test failures, offline analysis, cost, and duration.
- Perform the clean installation test.

### Phase 4 — Prepare the release

- Fix only release-blocking defects.
- Finalize limitations and documentation.
- Record the demonstration.
- Run final checks and submit.

## 12. Suggested Dates

| Date | Expected result |
| --- | --- |
| **14–15 Sep** | Teammates confirm assignments and create individual work plans |
| **15–20 Sep** | Runtime, third application, interface, and evaluation preparation proceed in parallel |
| **20–21 Sep** | Merge the main work and fix integration problems |
| **22 Sep** | Freeze features needed for formal evaluation |
| **22–25 Sep** | Complete formal evaluation and clean installation |
| **25–26 Sep** | Fix release-blocking problems and finalize limitations |
| **26–27 Sep** | Complete documentation and record the demonstration |
| **28–29 Sep** | Final review and submission |
| **30 Sep** | Contingency only |

## 13. How Teammates Should Work

Suggested branches:

| Member | Suggested branch |
| --- | --- |
| Member 2 | feature/runtime-hardening |
| Member 3 | feature/evaluation-environment |
| Member 4 | feature/interface-completion |
| Member 5 | evaluation/formal-results |

To reduce conflicts:

- The Team Lead updates task statuses in EXECUTION_PLAN_AI.md after reviewing
  the owner's evidence.
- Teammates update instructions affected by their changes.
- Member 4 agrees backend response changes with Member 2 before using them.
- Member 5 measures only merged and frozen behavior.
- A pull request should cover one task or a small related group of tasks.
- Every pull request explains how the change was tested.

## 14. Individual Work Plan Template

Each teammate can copy this into a GitHub issue or a short work-plan document:

    Name:
    Assigned tasks:
    Goal:

    Steps I plan to take:
    1.
    2.
    3.

    Files or areas I expect to change:
    People I need to coordinate with:
    Expected completion date:
    How I will prove the work is complete:
    Current blocker or decision needed:

## 15. Definition of Done

A task is complete only when:

1. The requested work or evaluation is complete.
2. Relevant automated or manual tests pass.
3. Failure and privacy behavior has been checked where relevant.
4. Documentation describes the real behavior and its limitations.
5. The owner provides a commit, test result, report, or other repeatable
   evidence.
6. Another member reviews the work.
7. The Team Lead accepts the evidence and updates the execution tracker.
