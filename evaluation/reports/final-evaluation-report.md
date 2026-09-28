# AuthFlowGuard — Final Evaluation Report

**Prepared by Member 5 (formal testing, failure testing, reliability and cost
measurement), 28 September 2026.** Code evaluated: branch `feature/spa-support`,
commit `25b2d59`. All figures below were produced on that code.

## Summary

| Question | Answer | Evidence |
| --- | --- | --- |
| Do the six security checks give the right answer on the purpose-built targets? | **44 of 44 formal cases** across Applications A, B and C | §3.1, `formal-cases.md` |
| Does the tool work on a real application it was never tuned for? | **OWASP Juice Shop: 6 of 6** correct; all 4 real vulnerabilities found | §3.2, `juiceshop.md` |
| Has a failed or unsupported test ever been reported as a pass? | **No.** 22 cases exist only to test this, and all pass | §3.4 |
| How reliably is the login flow discovered? | Rule-based: A 5/5 and B 5/5 automatic; C 5/5 through the guided fallback | §3.3 |
| Can results be re-analysed without the target, browser or AWS? | **Yes**, 6 of 6 checks, twice | §3.5 |
| What does a scan cost? | 5.7–14.5 s and 11–147 browser requests on average per scan; model spend is hard-capped, but has **not been measured live** | §4, §5 |

The governing rule of the project held throughout: **an unsupported or failed
test is never reported as a security pass.** Every outcome is one of
`finding_confirmed`, `no_issue_observed`, `inconclusive` or
`execution_error`, and only `no_issue_observed` means "tested and clean".

## 1. What was evaluated

**Security checks** (all run in a real Chromium browser against a target the
developer owns):

| Check | What it tests | OWASP WSTG |
| --- | --- | --- |
| CHK-001 Login enumeration | Do failed logins reveal whether an account exists? | WSTG-IDNT-04 |
| CHK-002 Registration enumeration | Does sign-up reveal existing accounts? | WSTG-IDNT-04 |
| CHK-003 Reset-request enumeration | Does password reset reveal existing accounts? | WSTG-IDNT-04 |
| CHK-004 Login throttling | Are repeated failed logins limited? | WSTG-ATHN-03 |
| CHK-005 Session fixation | Is the session identifier replaced at login? | WSTG-SESS-03 |
| CHK-006 Logout invalidation | Does logout end the session on the server? | WSTG-SESS-06 |

**Login discovery** finds the target's login flow before any check runs:
rule-based (default), Bedrock-driven (the AI mode), or guided by the developer
when neither can identify the flow with certainty.

**Targets**

| Target | What it is | Role |
| --- | --- | --- |
| A | Server-rendered forms, cookie sessions | Development target with secure and vulnerable modes |
| B | React app, JSON two-step login with a verification code, bearer token | Development target for single-page behaviour |
| C | Independently designed "workshop booking desk" | Withheld target: the tool was not tuned to it |
| J | OWASP Juice Shop v20.2.0 (Angular), in Docker on 127.0.0.1 | Real-world generality test, unseen during development |

**Environment:** Windows 11, Python 3.14.0, Playwright 1.63.0 with Chromium
153.0.8010.12, FastAPI 0.141.1, Docker 29.6.2. Scans ran in the separate
worker process used in production.

## 2. Method

- **Four case types per check.** *Vulnerable* (must be `finding_confirmed`),
  *secure* (must be `no_issue_observed`), *ambiguous* (saved evidence
  deliberately degraded; must be `inconclusive`) and *execution failure*
  (server errors injected mid-scan; must be `execution_error`). The last two
  exist to prove that a broken test cannot read as a pass.
- **Expected outcomes were fixed in advance** in `evaluation/cases/`, authored
  by Member 3, and never edited to make a row pass.
- **Fresh target per case**, so one case cannot disturb another (for example,
  lockouts from login enumeration).
- **Juice Shop ground truth came first:** each behaviour was established with
  `curl` and a plain browser before the tool was run.
- **Application C was not tuned for**, so its result stays a blind measure of
  generality.
- **Everything is reproducible** from committed case files with the commands in
  `Documentation/SESSION_HANDOFF.md`. Raw scan data is kept locally; results and
  reports are committed.

## 3. Results

### 3.1 Formal cases — 44 of 44 (EVA-005)

Run `ABC-spa-support`.

| Check | Vulnerable | Secure | Ambiguous | Execution failure |
| --- | --- | --- | --- | --- |
| CHK-001 Login enumeration (A, B, C) | 3/3 | 3/3 | 3/3 | 3/3 |
| CHK-002 Registration enumeration (A) | 1/1 | 1/1 | 1/1 | 1/1 |
| CHK-003 Reset enumeration (A) | 1/1 | 1/1 | 1/1 | 1/1 |
| CHK-004 Login throttling (A, C) | 2/2 | 2/2 | 2/2 | 2/2 |
| CHK-005 Session fixation (A, C) | 2/2 | 2/2 | 2/2 | 2/2 |
| CHK-006 Logout invalidation (A, C) | 2/2 | 2/2 | 2/2 | 2/2 |
| **Total** | **11/11** | **11/11** | **11/11** | **11/11** |

Application C has no registration or reset feature, so those checks have no C
cases. Applications A (24 cases) and C (16) were unchanged from the 22
September results; Application B rose from 1 of 4 to 4 of 4 (§6).

### 3.2 OWASP Juice Shop — 6 of 6

| Check | Ground truth | Result |
| --- | --- | --- |
| CHK-001 Login enumeration | Secure: identical `401` for known and unknown emails | `no_issue_observed` ✓ |
| CHK-002 Registration enumeration | Vulnerable: `400 "email must be unique"` vs `201` | `finding_confirmed` ✓ |
| CHK-003 Reset enumeration | Vulnerable: known email reveals its security question | `finding_confirmed` ✓ |
| CHK-004 Login throttling | Vulnerable: correct login succeeds after six failures | `finding_confirmed` ✓ |
| CHK-005 Session fixation | Secure: new token issued at login | `no_issue_observed` ✓ |
| CHK-006 Logout invalidation | Vulnerable: logout only clears the browser | `finding_confirmed` ✓ |

On the code as first merged, **all six Juice Shop scans failed before any check
ran.** The evaluation found the causes and they were fixed (§6). Across nine
full runs, eight were 6 of 6; in the other, the evaluation harness misread one
correctly completed scan, which led to the worker fix in §6. No run produced a
wrong verdict. A null control (two different non-existent emails) produced "no
difference" for both new form checks, confirming they do not invent findings.

### 3.3 Login discovery reliability (EVA-004)

Five attempts per application, each against a freshly started target,
rule-based discovery.

| Application | Automatic | Guided | Failed | Plan target (4/5 automatic) |
| --- | --- | --- | --- | --- |
| A | 5/5 | 0/5 | 0/5 | Met |
| B | 5/5 | 0/5 | 0/5 | Met (was 2/5 on 22 September) |
| C | 0/5 | 5/5 | 0/5 | Not applicable: withheld target |

Application C's sign-in field is labelled "Member ID" with no username
semantics, and the page also carries a search form with its own submit button.
Automatic discovery cannot be certain which controls log in, so it hands over
to the developer rather than guessing, and the guided route then succeeds every
time. Juice Shop behaved the same way. This is the intended safe behaviour; the
cost is one guided step on unfamiliar layouts.

### 3.4 Failure situations (EVA-006) — 7 of 7

| Condition | Result |
| --- | --- |
| Timeouts | A protected page that stops responding is never reported as clean |
| Bedrock outage | An unreachable model escalates to guidance, never reports success, and does not leak the service error |
| Stale saved login flow | Returns to guidance before any check runs |
| Missing target features / server errors | 11 injected-failure cases all give `execution_error` |
| Cancellation | Stops the scan and records it as cancelled |
| Worker failure | Crash, hang, startup timeout, runtime limit, and a worker that lingers after its result all end in an explicit, safe state |
| Unsupported authentication | Refused or handed to guided discovery, never passed |

### 3.5 Offline reanalysis and reports (EVA-007) — 6 of 6, twice

With the target stopped, no browser and no AWS credentials, a saved scan was
re-analysed and its JSON and HTML reports regenerated. The reanalysed outcome
matched the original and earlier result versions were kept. This held for an
Application A scan and for a Juice Shop registration scan using the new
client-side form evidence.

## 4. Measured consumption (EVA-008)

28 live scans, one per case (run `ABC-spa-support` and `J-spa-support`).

| Target | Scans | Average duration | Range | Average browser requests |
| --- | --- | --- | --- | --- |
| A | 12 | 5.69 s | 5.17–7.02 s | 10.8 |
| B | 2 | 11.45 s | 8.98–13.92 s | 25.5 |
| C | 8 | 9.21 s | 8.41–10.50 s | 11.6 |
| Juice Shop | 6 | 14.47 s | 11.11–17.43 s | 147.2 |

A real application costs more browser traffic than the small test targets
(Juice Shop loads a full Angular app on every page), but a complete check still
finishes in under 20 seconds. Rule-based scans make **no** AWS calls and cost
nothing beyond local compute. Per-case figures are in `measurements.md`.

## 5. The AI path (Amazon Bedrock) and its cost

**What exists.** A scan can use Bedrock (default model Amazon Nova Micro,
`us-east-1`) to choose each browser action during login discovery. It is
selectable in the interface and bounded by hard limits:

| Limit | Default | Server maximum |
| --- | --- | --- |
| AI decisions per scan | 40 | 100 |
| Active time per scan | 900 s | 1,800 s |
| Inference cost per scan | $0.25 | $1.00 |
| Estimated cost per single model call | $0.001 (call refused above this) | — |

Each call reserves its conservative maximum in a cost ledger before it is sent,
then records actual usage and reconciles. Usage and spend are shown live and
saved with the scan.

**What was verified, offline.** The complete AI path (interface request, model
decisions, browser actions, cost ledger, security checks and reports) was run
with the built-in deterministic model double, which makes no AWS calls and
labels all its usage `mock`:

| Target | Formal cases in Bedrock mode | Discovery | AI decisions per scan |
| --- | --- | --- | --- |
| A | 24 / 24 | 12 of 12 automatic | 3 |
| C | 16 / 16 | 8 of 8 automatic | 3 |
| B | 1 / 4 (3 blocked) | Not completed | 40, the cap |

Run `bedrock-offline-final`. Every scan's provenance records engine `bedrock`
and usage source `mock`, and every model call has a reservation and a
reconciled entry in the scan's cost ledger. The figures show the pipeline and
its limits working, **not** how the real model behaves. The double's simple
policy handled A's and C's login forms but not B's verification-code step: it
spent exactly the 40 decisions allowed and stopped, which demonstrates the
decision cap. The evaluation harness's guided fallback cannot express a
two-step login either, so those cases ended `blocked`, never as a pass. With
the real model, B's result is unknown.

**What was not measured.** No live Bedrock run was made for this evaluation.
The machine used had no AWS credentials, and live calls are billable, so they
need an agreed budget. Therefore the real model's discovery reliability, real
token counts and real cost are **not measured**, and no projected figure is
presented as a measurement.

**Cost envelope (derived, not measured).** Nova Micro is priced in the code at
$0.000035 per 1,000 input tokens and $0.00014 per 1,000 output tokens, with at
most 128 output tokens per call. For illustration, a decision sending 2,000
input tokens costs about $0.00009; the double's path of three decisions per
discovery would cost well under $0.001. Whatever the model does, spend cannot
exceed the caps above: at most $0.001 per call, $0.04 per scan at the default
40 decisions, and $0.25 per scan by the default cost limit. The checks
themselves never call Bedrock.

## 6. Changes made during evaluation

The evaluation's main value was finding defects before submission. Each fix
below came with tests that fail on the previous code, and was re-verified
against every target.

| Found by | Defect | Fix |
| --- | --- | --- |
| Juice Shop | Guided login replay stripped hash routes (`#/login`), opening the wrong page | Keep route-like fragments; still strip token-like ones |
| Juice Shop | Reading page controls raced client-side re-rendering | One atomic snapshot |
| Juice Shop, B | Actions ran before a JavaScript app had rendered, or before its background login finished | Wait for the requests an action starts (bounded) |
| Juice Shop | Failed scans recorded no cause | Record the exception type (never its message) |
| Juice Shop | Session checks could not judge sites that answer signed-out visitors with `500` | Compare against the anonymous baseline |
| Juice Shop | Logout only supported HTML forms | Find a logout control, including inside account menus |
| Juice Shop | Registration and reset checks only supported native forms | Compare JavaScript forms by background requests and page reaction |
| B | Two-step login attempts were discarded after a 30 s wait | Record the application's early rejection |
| B | The "secure" test mode leaked account existence | Corrected to match its stated rationale |
| Repeat runs | A finished scan could be held open by a lingering worker process | Publish the result before teardown; reap a lingering worker after 10 s |

The full backend suite passes (316 tests; `ruff`, `ruff format` and
`mypy` clean).

## 7. Limitations

The complete, maintained list is `Documentation/KNOWN_LIMITATIONS.md`. The ones
that matter most when reading this report:

- **Live Bedrock is unmeasured** (§5).
- **Session checks replay browser cookies, not bearer tokens.** A site that
  keeps its session only in JavaScript storage cannot be tested for session
  fixation or logout invalidation; the check reports that rather than passing.
- **Unfamiliar login layouts need one guided step** (§3.3).
- **Reset forms on JavaScript apps are compared before submission only**, to
  avoid changing a real password.
- **Evaluation used one run per case** for the formal cases, plus seven full
  repeats on Juice Shop and five discovery attempts per application; it does
  not establish behaviour beyond those runs.

## 8. Reports behind this summary

| Report | Tracker |
| --- | --- |
| `evaluation/reports/formal-cases.md` / `.csv` | EVA-005 |
| `evaluation/reports/juiceshop.md` | Generality |
| `evaluation/reports/discovery-reliability.md` | EVA-004 |
| `Documentation/KNOWN_LIMITATIONS.md` §7 | EVA-006 |
| `evaluation/reports/offline-verification.md`, `offline-verification-juiceshop.md` | EVA-007 |
| `evaluation/reports/measurements.md` | EVA-008 |
| `Documentation/KNOWN_LIMITATIONS.md` | REL-001 |
