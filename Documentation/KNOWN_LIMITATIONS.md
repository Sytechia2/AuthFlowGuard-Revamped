# Known Limitations

**Prepared by Member 5 for REL-001, 22 September 2026.**

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

## 2. AI integration

Scans started from the web interface **do not call Amazon Bedrock**. Login
discovery in the web application uses programmed rules. The Bedrock browser
agent exists but runs only from the terminal (`authflowguard.agent_cli`), stops
when its account marker becomes visible, and does not perform the full
signed-in/signed-out comparison, run the six checks, or persist a scan through
ScanManager.

Consequently the measurements that depend on live model behaviour — discovery
reliability (EVA-004) and token/cost measurement (EVA-008) — could not be taken.
See Section 5.

## 3. Runtime

| Area | Limitation |
| --- | --- |
| Background execution | Scans run in a background thread inside the API process, not a separate worker process. A long scan shares a process with the API. |
| Cancellation | Cancellation handling exists, but stopping every active browser operation is unfinished. |
| Credential handling | Credentials are held in temporary in-memory objects. Complete cleanup on every exit path, and leak checks in exports, remain open. |
| Restart recovery | A scan that was running or awaiting guidance is marked failed after a backend restart. |

## 4. Evaluation coverage

- The formal 24-case matrix was executed against **Application A only**. Cases
  for Applications B (4) and C (16) are authored but **not executed**.
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

## 5. Measurements not taken

| Tracker | Task | Status | Reason |
| --- | --- | --- | --- |
| EVA-004 | Discovery reliability, five runs per flow per application | **Blocked** | Requires live Bedrock discovery, which the web application does not use (Section 2). The terminal agent is also subject to the Nova quota problem recorded in `DEVELOPMENT.md` Section 5. |
| EVA-008 | Token, cost, and duration measurement | **Blocked for live figures** | Requires live Bedrock calls. Cost accounting infrastructure is implemented and tested (`authflowguard.evaluation.cost_model`, `cost_tracking`), and can produce projected figures from fixture token counts, but every such figure is labelled `MOCK ONLY` and is not an AWS charge. |

These are dependencies on unfinished integration work, not gaps in the
evaluation method. Scan duration *was* recorded for all 24 executed cases and is
in `evaluation/reports/formal-cases.csv`.

## 6. Test suite

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
