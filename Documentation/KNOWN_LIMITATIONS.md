# Known Limitations

**Prepared by Member 5 for REL-001, 23 September 2026.**

This is the single consolidated list of what AuthFlowGuard does not do. It
exists so that no incomplete behaviour is presented as complete. Every entry
states what is unsupported and what the product does instead, because the
governing rule for this project is that an unsupported or failed test is never
reported as a security pass.

## 1. Session-check scope (Task 5.6 decision)

CHK-005 (session fixation) and CHK-006 (logout invalidation) support login
flows that use a username, a password, and a browser cookie session. The
following were considered for this release and are **deferred**:

| Capability | Decision | What happens instead |
| --- | --- | --- |
| One-time-code login replay | Deferred | The session-check adapter assigns the username to the first fill action and the password to every later fill action, so it cannot replay a flow containing a verification-code step. An unsupported flow shape fails before check evidence is created and fails the scan. |
| Bearer-token session replay | Deferred | Discovery and login proof support the React/JSON bearer fixture, but these two checks copy and replay cookies only. Tokens in local or session storage are not replayed. |
| Non-POST logout | Deferred | CHK-006 discovers logout only through an HTML form whose submit produces a POST response. Logout links, client-side navigation, and JavaScript requests using another method are recorded as `execution_error`. |

None of these can produce a false pass. Unsupported logout discovery yields
`execution_error`, and an analyser given incomplete evidence yields
`inconclusive`. Both are distinct from `no_issue_observed` in the reports.

## 2. AI integration (Updated for INT-011)

Task 2.6 / INT-011 connects the Bedrock browser controller directly to web scans
initiated from the React interface via FastAPI. Users can select Bedrock AI discovery,
configure bounded execution limits, observe real-time decision metrics and token spend,
obtain verified authentication profiles with multi-page replay support, and run all six
security checks through the existing reporting pipeline.

**Live AWS Session Prerequisite:**
Live model dispatch requires an active AWS profile session with Bedrock Converse
entitlements:
```bash
aws sso login --profile authflowguard-dev
# or: aws login --profile authflowguard-dev
```
Automated tests and the evaluation harness use `DeterministicModelDouble`
(`UsageSource.MOCK`) unless live calls are explicitly enabled. A user-selected
Bedrock web scan does not silently switch to the double or rules when AWS is
unconfigured. Mock usage is labeled in scan provenance and evaluation output.

## 3. Runtime

| Area | Limitation |
| --- | --- |
| Background execution | Scans run in a background thread inside the API process, not a separate worker process. A long scan shares a process with the API. |
| Cancellation | Cancellation handling exists, but stopping every active browser operation is unfinished. |
| Credential handling | Credentials are held in temporary in-memory objects. Complete cleanup on every exit path, and leak checks in exports, remain open. |
| Restart recovery | A scan that was running or awaiting guidance is marked failed after a backend restart. |

## 4. Evaluation coverage

- All 44 authored cases were executed: Application A (24), B (4) and C (16).
  41 passed. The three exceptions are all Application B and are recorded in
  Section 4.1 as findings, not as harness defects.
- **Automatic login discovery did not succeed on Application C.** All 16 of its
  cases completed through the guided fallback instead. The site presents two
  forms on the sign-in page, which discovery treats as ambiguous. This is the
  intended purpose of an independently designed target, and it is the clearest
  generality result the evaluation produced.
- Application C (`site_app`) has no registration or reset-request features, so
  those two checks have no cases for it. That is an absence of the feature, not
  a pass.
- The execution-failure cases inject HTTP 503 responses. Two of them
  ("stop the target") are realised as every route returning 503 from the
  trigger onward rather than the process being killed, so the scan observes
  server errors rather than a refused connection. Both are documented triggers
  for `execution_error`; the distinction is recorded in each result's `detail`.
- Live cases run against an ephemeral local port rather than the fixed ports in
  the case file, so a run cannot fail because a port was busy. The origin
  actually used is recorded on every result.

### 4.1 Application B — login enumeration is not supported

Application B uses a two-step JSON login with a verification code and a bearer
token. Automatic discovery succeeded and login was proven, but CHK-001 could
not run: the enumeration runner submits failed logins through a native form,
and Application B has no such form.

| Case | Expected | Actual | Reading |
| --- | --- | --- | --- |
| `B-CHK-001-secure` | `no_issue_observed` | `execution_error` | The product refused to claim a pass it could not evidence. The case expectation was optimistic. |
| `B-CHK-001-ambiguous` | `inconclusive` | `execution_error` | Derived from the secure run's evidence, so it inherits the same outcome. |
| `B-CHK-001-vulnerable` | `finding_confirmed` | not reached | Automatic discovery paused, and the guided fallback submits a username, a password and a submit control. It cannot express a two-step flow whose second step is a verification code. |
| `B-CHK-001-execution-failure` | `execution_error` | `execution_error` | Passed. |

**These expectations were not adjusted to make the rows pass.** The correct
correction is to record CHK-001 as unsupported for Application B. The important
property holds: an unsupported flow produced `execution_error`, never
`no_issue_observed`.

## 5. Measurements not taken

| Tracker | Task | Status | Reason |
| --- | --- | --- | --- |
| EVA-004 | Discovery reliability of the **terminal Bedrock agent** | **Blocked** | The agent needs live AWS and is subject to the Nova quota problem in `DEVELOPMENT.md` Section 5. Discovery reliability of the web application's own rule-based discovery **was measured** — see Section 6. |
| EVA-008 | Model token and cost measurement | **Blocked** | Requires live Bedrock calls. Browser request volume and scan duration **were** measured across 22 live scans (`evaluation/reports/measurements.md`). Cost accounting is implemented and tested (`cost_model`, `cost_tracking`) and will produce a table as soon as real model calls exist. No projected figure is published, because a projection is not a measurement. |

### EVA-006 failure testing is partial

Task 5.3 names seven failure conditions. **Six are evidenced. One is blocked**
because the component it tests does not exist yet, so EVA-006 is as complete as
it can be before RUN-002 lands.

| Condition | State | Evidence or reason |
| --- | --- | --- |
| Stale saved flows | Covered | `test_enumeration_scans.py` returns a stale profile to `awaiting_guidance` before any check runs |
| Cancellation | Covered | Cancellation tests in `test_enumeration_scans.py` and `test_app.py` |
| Missing target features / target errors | Covered | Eleven fault-injection cases across three applications produce `execution_error` from the analyser |
| Timeouts | Covered | `test_evaluation_failures.py` drives a real scan against a protected resource that stops responding, and asserts the result is never `no_issue_observed`. Model-request timeouts are covered separately by the active-time-limit test |
| Unsupported authentication | Covered | Application B's two-step JSON login is unsupported by CHK-001 and by the guided fallback; both refuse rather than pass (Section 4.1) |
| Bedrock outages | Covered | `test_evaluation_failures.py` drives the controller against an unreachable model: it escalates to guidance, never reports success, and does not leak the service error into the operator-facing reason |
| Worker failure | **Blocked** | Scans run in a background thread; the separate worker process (RUN-002) does not exist yet |

The task's completion criterion — that no failed or unsupported test is reported
as a security pass — holds for every condition that was exercised. Twenty-two of
the forty-four executed cases exist specifically to demonstrate it: eleven
degrade saved evidence and require `inconclusive`, and eleven inject server
errors during a real scan and require `execution_error`. Neither may be reported
as `no_issue_observed`.

These are dependencies on unfinished integration work, not gaps in the
evaluation method. Scan duration *was* recorded for all 24 executed cases and is
in `evaluation/reports/formal-cases.csv`.

## 7. Test suite

`backend/tests/test_react_json_app.py::test_automatic_flow_supports_two_step_json_and_bearer_sessions`
fails when the full suite runs, and passes when run alone. The failure is
`Page.goto: net::ERR_ABORTED` against the fixture's ephemeral port, and is
deterministic across repeated full-suite runs.

This is a pre-existing fixture-isolation defect, not a regression. It was
invisible until `test_controlled_app.py` began collecting. That module imports
`httpx2`, which is correct for Starlette 1.6, but `pyproject.toml` lists `httpx`
in its dev extras, so a environment built from `pyproject.toml` could not
collect it. **The dependency should be corrected to `httpx2`.**

Current state: **213 passed, 1 failed**.

## 6. Discovery reliability, measured

EVA-004 was **not** blocked. Login discovery in a scan started from the web
interface is rule-based — `scan_manager.py` contains no Bedrock reference — so
it can be measured without AWS. Each application's login flow was attempted
five times against a freshly started fixture.

| Application | Automatic | Guided | Failed | Meets the 4/5 automatic target |
| --- | --- | --- | --- | --- |
| A — forms and cookies | 5/5 | 0/5 | 0/5 | Yes |
| B — React, JSON, bearer token | 2/5 | 0/5 | 3/5 | **No** |
| C — independent withheld layout | 0/5 | 5/5 | 0/5 | No |

Three findings follow from this table.

**Application B's automatic discovery is non-deterministic.** It succeeded on
two attempts out of five, and attempt durations ranged from 0.89 s to 94.49 s
against an identical fixture. This is very likely the same defect as the
intermittent `test_react_json_app` full-suite failure in Section 7: both involve
the React/JSON target and both are order- or timing-dependent. **This is the
most serious reliability finding in the evaluation** and should be assigned
before any reliability claim is published.

**Application C never completes automatically, and always completes guided.**
Its sign-in page carries two forms, which discovery treats as ambiguous. As the
independently designed target, it is doing exactly the job it was built for.

**Application A meets the target** at 5 of 5, with durations between 4.71 s and
4.80 s.

What remains unmeasured is the reliability of the *terminal Bedrock agent*, for
the reason in Section 5.

Keep two distinctions apart, because they are easy to conflate:

| | What decides the next step | Measured? |
| --- | --- | --- |
| **Automatic** discovery in a web scan | Programmed rules. **No AI.** | Yes — the table above |
| **Guided** fallback in a web scan | A person identifies the fields | Yes — the table above |
| **Terminal Bedrock agent** | Amazon Bedrock chooses each action | No — needs live AWS |

"Automatic" therefore does **not** mean "AI". Every figure in the table above
was produced without a single model call. The Bedrock agent is a separate
command-line tool that is not wired into scans at all, which is why its
reliability is the only part left unmeasured.

## Bedrock web integration review (23 September 2026)

Offline integration tests do not establish live AWS model access, quota, or discovery reliability. Active synchronous SDK requests have bounded network timeouts, but cancellation cannot terminate the underlying thread; worker-process termination remains RUN-002.
