# Known Limitations

**Prepared by Member 5 for REL-001. Updated 28 September 2026** to reflect the
merged process worker (RUN-002), Bedrock web discovery (INT-011), and the
single-page-application work evaluated against OWASP Juice Shop.

This is the single consolidated list of what AuthFlowGuard does not do. It
exists so that no incomplete behaviour is presented as complete. Every entry
states what is unsupported and what the product does instead, because the
governing rule for this project is that an unsupported or failed test is never
reported as a security pass.

## 1. Session-check scope (Task 5.6 decision)

CHK-005 (session fixation) and CHK-006 (logout invalidation) were first scoped
to username-and-password logins with cookie sessions. The Juice Shop work
extended part of that scope; the rest remains deferred.

| Capability | Status | What happens |
| --- | --- | --- |
| Logout through a menu button or client-side logout | **Supported** (was deferred) | With no logout form, CHK-006 finds a visible control labelled "log out" / "sign out", opening up to three account-menu toggles. A logout that sends no request counts only when the runner recorded it and the page then showed signed-out. A control without such a label is not found and the check reports `execution_error`. |
| Protected pages that answer signed-out visitors with a server error | **Supported** (new) | A `5xx` counts as a failure only when it differs from the anonymous control; when it matches, it is how that site rejects signed-out requests. |
| Bearer-token session replay | Deferred | These two checks copy and replay browser cookies only. Tokens held in local or session storage are not replayed. Choose a cookie-protected resource, or the check cannot demonstrate reuse. |
| One-time-code login replay in session checks | Deferred | The session-check adapter assigns the username to the first fill and the password to later fills, so it cannot replay a login with a verification-code step. It fails before check evidence is created. (Login enumeration, CHK-001, *does* support two-step logins; see §4.) |

None of these can produce a false pass: an unsupported shape yields
`execution_error`, and incomplete evidence yields `inconclusive`.

## 2. AI integration

Bedrock discovery is wired into web scans (INT-011). A user can select Bedrock
discovery in the interface; each scan is bounded by a maximum number of AI
decisions (default 40, server maximum 100), active time (default 900 s, server
maximum 1,800 s) and inference cost (default $0.25, server maximum $1.00), and
every model call is refused if its conservative pre-call estimate exceeds
$0.001. Usage and cost are recorded per call in a ledger and shown live.

**Not measured live.** No member has yet run Bedrock discovery against live
AWS for the evaluation. The whole AI path was exercised end to end with the
built-in deterministic model double (`UsageSource.MOCK`, clearly labelled in
provenance and ledgers): Applications A and C pass all their formal cases in
Bedrock mode. On Application B the double cannot handle the verification-code
step, spends its 40-decision cap and stops, and those cases end `blocked`
(`evaluation/results/bedrock-offline-final`). Real reliability of
the model's choices, real token counts and real cost therefore remain
unmeasured. See `evaluation/reports/final-evaluation-report.md` §5 for the
cost envelope implied by the configured prices and caps.

Live dispatch needs an AWS profile with Bedrock Converse access:

```bash
aws sso login --profile authflowguard-dev
```

A Bedrock scan never silently falls back to the double or to rules when AWS is
unavailable; it requests guidance instead (tested in
`test_evaluation_failures.py`).

## 3. Runtime

| Area | Limitation |
| --- | --- |
| Worker process | Scans run in a separate spawned worker process (RUN-002). A worker that stops responding is stopped at its runtime limit (default one hour) and the scan is marked failed. A worker that reports its result but then fails to exit is stopped after 10 s and its result is kept. |
| Cancellation | A synchronous Bedrock SDK request cannot be interrupted inside its thread; cancellation takes effect when the request returns or the worker is stopped. |
| Restart recovery | A scan that was running or awaiting guidance when the backend restarts is marked failed; it is not resumed. |
| One scan at a time | The server runs one active scan; a second start is refused with `scan_busy`. |

## 4. Evaluation coverage

- **Formal cases: 44 of 44 pass** across Applications A (24), B (4) and C (16),
  run `ABC-spa-support` (`evaluation/reports/formal-cases.md`).
- **OWASP Juice Shop: 6 of 6** correct, with ground truth established
  independently before the tool was run; 4 of 4 real vulnerabilities detected,
  no false passes (`evaluation/reports/juiceshop.md`).
- **Application C always uses the guided fallback.** Its sign-in field is
  labelled "Member ID" with no username semantics, and the page also carries a
  search form with its own submit button, so automatic discovery cannot
  identify the login controls with certainty and hands over rather than
  guessing. Guided completion succeeded 5 of 5. Discovery was deliberately
  **not** tuned to Application C after its results were seen: it is the
  independently designed target, and tuning to it would turn a blind
  generality measurement into a fitted one.
- **Juice Shop also used the guided fallback** in every case, for the same kind
  of reason (no conventional username semantics on its login fields).
- Application C (`site_app`) has no registration or reset-request feature, so
  those two checks have no Application C cases. That is an absent feature, not
  a pass.
- Execution-failure cases inject HTTP 503 responses. Two of them ("stop the
  target") are realised as every route returning 503 from the trigger onward
  rather than a killed process; both are documented triggers for
  `execution_error`, recorded in each result's `detail`.
- Live cases run on ephemeral local ports rather than the fixed ports in the
  case file; the origin used is recorded on every result.

### 4.1 Application B — resolved

On 22 September, Application B's login-enumeration cases failed (1 of 4). Two
causes were found and fixed on 27–28 September:

1. **Tool defect.** An unknown email is rejected at the first step of B's
   two-step login, so the code field never appears. The runner waited 30 s for
   that hidden field and discarded the attempt. It now records the early
   rejection as the response; the known-identifier attempt must still complete
   every step, so a broken flow stays an error.
2. **Test-application defect.** B's secure mode answered the first step with
   `200 "Code sent."` for the known email and `401` for any other, itself an
   enumeration leak contrary to the case rationale. With the old application,
   the fixed tool correctly reported `finding_confirmed` on the "secure" mode.
   The secure mode now answers every email identically. Case expectations were
   not edited.

## 5. Single-page applications (from the Juice Shop evaluation)

| Area | Limitation |
| --- | --- |
| Reset forms on JavaScript apps | Compared on the page's reaction to the identifier only; the form is never submitted, since completing it could change a real account's password. An app that leaks only after a full submission reads as secure for CHK-003. |
| Numeric-only differences | Background JSON responses are compared with numbers normalised, because record ids differ between any two requests. A difference carried only by a number is not detected; differences in keys, text, status or page state are. |
| Registration side effects | Registration comparison may create the disposable account; use a fresh identifier per run (`{run}` in the case file does this). |
| Positional control references | Guided replays fill controls by position. If a page's layout changes, a credential could be typed into an unrelated field. Recommended, not implemented: check that a fill's target still matches the recorded control before typing a secret. |

## 6. Measurements

| Tracker | Task | Status |
| --- | --- | --- |
| EVA-004 | Discovery reliability, rule-based | **Measured**: A 5/5 automatic, B 5/5 automatic, C 0/5 automatic and 5/5 guided (`discovery-reliability.md`) |
| EVA-004 | Discovery reliability, live Bedrock | **Not measured**: needs AWS credentials and billable calls |
| EVA-006 | Failure situations | **7 of 7 covered** (§7) |
| EVA-007 | Offline reanalysis and reports | **Measured**: 6 of 6 on Application A and 6 of 6 on a Juice Shop client-form scan, target stopped |
| EVA-008 | Browser requests and durations | **Measured** across 28 live scans (`measurements.md`) |
| EVA-008 | Model tokens and cost | **Not measured live**; pipeline verified with the labelled double, cost envelope derived from configured prices and caps |

## 7. Failure testing (EVA-006)

| Condition | Evidence |
| --- | --- |
| Stale saved flows | `test_enumeration_scans.py` returns a stale profile to `awaiting_guidance` before any check runs |
| Cancellation | `test_enumeration_scans.py`, `test_app.py`, `test_process_worker.py` |
| Missing target features / target errors | Eleven fault-injection cases across three applications produce `execution_error` |
| Timeouts | `test_evaluation_failures.py` drives a real scan against a protected resource that stops responding and asserts it is never `no_issue_observed` |
| Unsupported authentication | Unsupported flow shapes refuse rather than pass (§1); Application C and Juice Shop hand over to guided discovery |
| Bedrock outages | `test_evaluation_failures.py`: an unreachable model escalates to guidance, never reports success, and does not leak the service error |
| Worker failure | `test_process_worker.py`: abrupt exit, unresponsive worker, startup timeout, runtime limit and a worker that lingers after its result all end in a safe, explicit state |

Twenty-two of the forty-four formal cases exist specifically to show that a
failed or incomplete test is never a pass: eleven degrade saved evidence and
require `inconclusive`, and eleven inject server errors and require
`execution_error`. All twenty-two pass.
