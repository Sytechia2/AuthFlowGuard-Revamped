# AuthFlowGuard AI — New Application Project Plan

Implementation tasks and current progress are tracked separately in
[EXECUTION_PLAN_AI.md](EXECUTION_PLAN_AI.md). This project plan remains the
source of truth for the agreed scope, architecture, and acceptance criteria.

## 1. Project Summary

AuthFlowGuard AI will help developers test authentication features in websites they are building. The application will discover how a website handles authentication, perform six controlled security checks, and produce results supported by recorded evidence.

The application will be developed **from scratch in a separate repository**. The existing AuthFlowGuard application and its February reports will remain historical reference material. The new application will not depend on the old workflows, configuration files, analysers, or proxy setup.

| Project decision | Agreed direction |
| --- | --- |
| Intended users | Developers testing their own local or staging websites. |
| Implementation | A Python backend, Playwright browser automation, and a React interface. |
| Execution | The interface, backend, and browser run on the developer's computer. |
| AI service | Amazon Bedrock provides navigation decisions. |
| Website support | Traditional forms and JavaScript applications, including separate username/password steps and cookie or bearer-token sessions. |
| Developer assistance | The agent attempts discovery first. If necessary, the developer demonstrates a flow or identifies controls and a protected page. |
| Security analysis | Explicit OWASP-based analysers evaluate recorded evidence. The AI does not decide security verdicts. |
| Traffic capture | Playwright captures the browser activity required by the six checks. Mitmproxy is not required for the first release. |
| Team and deadline | Five members will work towards submission by 30 September 2026, aiming to submit on 28 or 29 September. |
| Resources | The project lead has confirmed more than $100 in AWS credits. Teammate accounts and credits are additional resources only after confirmation. |

Supporting different websites means that new targets can be tested through discovery and recorded guidance without adding website-specific code to the security checks. It does not mean that the first release supports every authentication method.

MFA, CAPTCHA, external identity providers, password-reset completion, and applications without a browser interface are outside the first release.

## 2. Application Architecture

### 2.1 The Four Main Components

| Component | Responsibility | Output |
| --- | --- | --- |
| **Website interaction** | Playwright opens pages, operates forms, follows redirects, and observes network activity. The AI agent chooses navigation actions when the next step is unknown. | Recorded actions, requests and responses, and changes in browser state. |
| **Authentication information** | This component establishes how authentication works on the target and verifies which observations are reliable. | Reusable authentication steps, session references, and evidence distinguishing authenticated access from anonymous access. |
| **Security checks** | This component contains two separate parts: test runners perform controlled experiments, and analysers evaluate the recorded evidence. | A result for each check, its supporting evidence, and any limits on what was tested. |
| **Evidence and results** | This component stores redacted evidence and presents the analyser's results. It does not independently decide whether the website is vulnerable. | A results page and downloadable HTML and JSON reports. |

The normal sequence is:

1. The agent uses Playwright to discover and verify the authentication flows.
2. The authentication-information component records the verified flows and the evidence needed to recognise account access.
3. A test runner uses those flows to perform a controlled experiment through Playwright.
4. The runner saves an evidence package describing what was attempted and observed.
5. An analyser evaluates that package using the check's rules and declared application policy.
6. The results interface and report generator present the outcome and evidence.

### 2.2 Playwright and the Removal of Mitmproxy

Playwright will be the main execution tool. It can monitor browser requests and responses, inspect cookies and browser storage, create isolated browser contexts, and send HTTP requests for replay experiments. These capabilities cover the planned first-release checks. See the official documentation for [network monitoring](https://playwright.dev/python/docs/network), [browser contexts](https://playwright.dev/python/docs/api/class-browsercontext), and [API testing](https://playwright.dev/python/docs/api-testing).

| Previous responsibility | First-release implementation |
| --- | --- |
| Record browser requests and responses | Playwright request and response listeners will associate observations with the current scan, check, and action. |
| Inspect session state | Playwright will inspect cookies and relevant browser storage. Observed authentication headers will also be recorded as local secret references. |
| Retry a protected request using an old session | A test runner will use an isolated Playwright browser context or API request context containing only the intended captured state. |
| Associate traffic with test steps | The runner will assign scan, check, and action identifiers when collecting evidence. |

There will be **no mitmproxy dependency, proxy process, or proxy certificate installation** in the first release. This decision covers traffic generated by the controlled browser and explicit replay requests; it does not claim visibility into every process or server-side request. Missing observations must produce an inconclusive or unsupported result. A separate proxy can be reconsidered if later requirements need broader traffic visibility.

The application will initially use Chromium and Playwright's asynchronous Python library. Pytest will test AuthFlowGuard itself; it will not act as the application's scan scheduler.

### 2.3 Test Runners and Analysers

The concept of analysers will be retained, but their implementation will be new. Each of the six checks will have a runner responsible for collecting evidence and an analyser responsible for interpreting it.

| Part | What it may do | What it must not do |
| --- | --- | --- |
| **Test runner** | Operate the browser, submit forms, perform controlled failures, capture sessions, replay requests, and record execution errors. | Treat a request's success or failure as a security verdict without the analyser's evaluation. |
| **Analyser** | Read recorded evidence and the nonsecret authentication profile, apply OWASP-based rules, and return a result with evidence references. | Open a browser, contact the target, call the AI, read live credentials, or change the test environment. |
| **Report generator** | Present saved results, supporting evidence, coverage, and limitations. | Perform additional tests or create a new verdict independently of the analyser. |

An analyser will behave consistently: the same evidence, policy, and analyser version must produce the same result. It will be callable without a running browser, target website, or AWS connection. This allows the team to test its logic and reanalyse saved evidence offline.

**Example: logout invalidation**

1. The runner logs in and verifies access to private account information.
2. It captures the active session, performs logout, and retries the protected resource using only the captured session.
3. It records authenticated, anonymous, and replay responses, together with evidence of the logout action and any errors.
4. The analyser compares those observations and decides whether the old session still provides private access.
5. If a required control is missing or ambiguous, the analyser reports insufficient evidence rather than a pass.

### 2.4 Technology and Execution

| Area | Implementation decision |
| --- | --- |
| Backend | Python with FastAPI and Pydantic for validated requests and shared data definitions. |
| Browser automation | Playwright's asynchronous Python API. |
| AI integration | Boto3 calls Bedrock through its Converse API. The AWS profile, region, and model identifier are explicit configuration settings. |
| Interface | React with TypeScript and Vite. The packaged frontend is served by the local backend. |
| Scan execution | One worker process runs one scan at a time, keeping browser execution separate from the web server. |
| Local storage | Each scan has a metadata file, an append-only event log, evidence files, and result files. A database is unnecessary initially. |
| Reports | HTML for reading or printing and JSON for further processing. |

The backend will bind to the local machine. The interface will poll scan status once per second. Cancellation must stop browser and HTTP activity, discard live credentials, preserve completed evidence, and mark unfinished work as cancelled. Cancellation is an execution state, not a security finding.

### 2.5 Website Interaction and Guided Fallback

The agent will repeatedly examine the page, choose an action against an observed control, execute the validated action, and check the result. Allowed actions include navigation, clicking, filling fields, selecting options, pressing keys, and waiting for observable changes. The model will not generate executable Python or JavaScript.

If discovery repeatedly fails, the application will pause and let the developer use the controlled browser to:

- Demonstrate the missing authentication steps.
- Identify a field or button.
- Identify a read-only protected page and the account information that proves login succeeded.

The application will record guidance as structured actions, replace credentials with local references, and verify the flow by replaying it. Automatic and guided flows will be labelled separately. Guidance assists navigation; it does not substitute for evidence that a security check completed.

### 2.6 Authentication Information and Shared Interfaces

Security checks will receive a verified authentication profile rather than guessed website addresses.

| Information | Required content |
| --- | --- |
| Target scope | The website address and explicitly permitted frontend and API origins. |
| Available features | Which features were found, verified, absent, or unsupported. |
| Authentication steps | Reusable actions for each feature, with credentials represented by references. |
| Relevant traffic | Requests associated with authentication actions, including redirects and multi-request login flows. |
| Session information | Observed cookies, storage changes, and authentication headers. Secret values remain available only during execution. |
| Protected-resource check | A read-only page or request whose account-specific result is present after login and absent without authentication. |
| Discovery history | Whether information was discovered automatically or supplied by the developer. |

A successful status code, URL change, or cookie alone will not prove login. Session-dependent checks require verified access to account-specific information and an anonymous comparison. If that proof cannot be established, the application will request guidance or report the affected checks as inconclusive.

The backend will define these shared Pydantic models:

| Model | Purpose |
| --- | --- |
| `ScanRequest` | Contains target details, selected checks, credential references, relevant policies, and execution limits. |
| `BrowserAction` | Describes a validated action against an observed control. |
| `AuthProfile` | Contains verified authentication information. Its saved form excludes live secrets. |
| `EvidenceEvent` | Associates a scan, check, action, and recorded observation. |
| `TestRunEvidence` | Contains the runner's observations, control comparisons, attempted steps, errors, and coverage. This is the analyser's input. |
| `CheckResult` | Contains the outcome, OWASP reference, analyser version, explanation, evidence references, and coverage limitations. |

Each analyser will expose the equivalent of `analyse(evidence, profile, policy) -> CheckResult`, using the saved nonsecret profile. Comparisons involving secret values will be represented by redacted facts or nonreversible identifiers in the evidence package. Analysers will not require the original password or session token.

The local API will support creating a scan, reading status and events, submitting guidance, cancelling execution, downloading results, and reanalysing saved evidence. Reanalysis will create a new versioned result without overwriting the original. No endpoint will make the analyser perform live testing.

### 2.7 Code Readability

The codebase must be simple and easy for every team member to understand. Clear, explicit, and slightly longer code is preferred over short but overly complex code. Implementations should use descriptive names, small focused functions, straightforward control flow, and comments only where they explain decisions that the code itself cannot make obvious. Abstractions will be introduced only when they remove demonstrated duplication or enforce an important boundary such as secret handling or runner/analyser separation.

## 3. Six OWASP-Based Security Checks

The application will use versioned **OWASP WSTG v4.2** references. These are selected automated procedures based on OWASP guidance; the reports will not claim complete OWASP compliance.

| Check | OWASP reference | Runner procedure and analyser requirements |
| --- | --- | --- |
| **1. Login account enumeration** | WSTG-IDNT-04 | Compare failures for a known account and a known nonexistent identifier. The analyser looks for repeatable differences after removing harmless changing values. |
| **2. Registration account enumeration** | WSTG-IDNT-04 | Compare an existing identifier with fresh test identifiers. The analyser records any account disclosure and evaluates it against the developer's stated privacy expectations. |
| **3. Reset-request account enumeration** | WSTG-IDNT-04 | Compare initial reset-request responses for existing and nonexistent identifiers. Completing the reset is not required. |
| **4. Login throttling and lockout** | WSTG-ATHN-03 | Perform bounded failed attempts and a valid-login control. The analyser distinguishes observed restrictions, policy violations, unrelated errors, and limits on the tested threshold. |
| **5. Session fixation** | WSTG-SESS-03 | Capture a pre-login session, complete login, and test that original session in a separate context. The analyser requires evidence of authenticated access and records assumptions about session placement and cookie protections. |
| **6. Logout invalidation** | WSTG-SESS-06 | Verify login, perform logout, and replay the old session against a protected resource. The analyser compares the replay with authenticated and anonymous controls. |

The procedures follow OWASP guidance for [account enumeration](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account), [lockout mechanisms](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism), [session fixation](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation), and [logout functionality](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality).

### 3.1 Common Test Rules

- Enumeration checks use three paired comparisons. Timing or raw response length alone will not confirm a finding. Reflected identifiers and unrelated changing values are removed before comparison.
- Form submissions use the actual browser flow so that current CSRF tokens and hidden fields are retained.
- Registration repetitions use fresh disposable identifiers. Created accounts and generated reset requests are recorded.
- Throttling runs last, with a default limit of ten failed attempts two seconds apart. A declared expected threshold is evaluated only within the configured limits. No restriction in a short test does not prove that all protection is absent.
- Session replay uses isolated contexts containing only the intended captured state. Current cookies and automatic token refresh must not contaminate the experiment.
- Session fixation distinguishes demonstrated reuse from an unchanged cookie. It does not claim that an attacker can force a session onto a victim unless that prerequisite has been established.
- Missing prerequisites stop dependent procedures with a clear explanation. No application name, fixed login address, or familiar response field determines a verdict.

### 3.2 Result Categories

| Result | Meaning |
| --- | --- |
| **Finding confirmed** | Evidence satisfies the check's stated finding conditions. |
| **No issue observed** | The procedure completed without demonstrating the issue under the recorded conditions. |
| **Inconclusive** | Available evidence cannot support a decision. |
| **Not applicable** | The required feature or authentication mechanism is absent. |
| **Unsupported** | The feature exists, but the application cannot currently test its implementation. |
| **Execution error** | A technical failure prevented completion. |

The analyser produces these results from evidence. The interface must show incomplete coverage as clearly as confirmed findings.

## 4. Developer Experience, Evidence, and AWS

### 4.1 User Journey

| View | Developer actions |
| --- | --- |
| **Setup** | Enter the target, permitted origins, dedicated accounts, disposable identifiers, selected checks, and relevant security policies. |
| **Discovery** | Follow browser activity, inspect discovered features, and provide guidance when requested. |
| **Testing** | See each check's progress, request count, and outcome, or cancel the scan. |
| **Results** | Read findings, inspect redacted evidence, understand untested coverage, export reports, or reanalyse saved evidence. |

Saved profiles retain nonsecret navigation information. Credentials are supplied again for each new scan, and stored flows are revalidated before reuse. Controlled registration and reset tests will use disposable accounts and a test mailbox or local email capture.

### 4.2 Evidence Handling

Each check will produce a compact package containing actions, timestamps, relevant redacted responses, control comparisons, masked screenshots where useful, and explicit coverage information. The package must contain enough nonsecret information for an analyser to reevaluate its conclusion offline.

- Passwords, session tokens, and unredacted authentication state remain in worker memory and are discarded when execution ends.
- Raw Playwright traces and HAR files are not saved by default because they can contain secrets.
- Model requests contain sanitised text descriptions. Screenshots remain local in the first release.
- Page content is untrusted input and cannot change the target scope or permitted actions.
- Report generation and reanalysis use saved evidence without contacting the target or Bedrock.
- No aggregate security score will be invented.

### 4.3 AWS Services

| Service | Role and priority |
| --- | --- |
| **Amazon Bedrock** | This is the core AWS integration for navigation decisions through the [Converse API](https://docs.aws.amazon.com/bedrock/latest/userguide/conversation-inference.html). |
| **IAM** | This provides individual access and limited backend permissions. AWS credentials stay out of the frontend. See [IAM documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html). |
| **AWS Budgets** | This supplies cost alerts in addition to application limits. Billing updates can be delayed. See [budget guidance](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-best-practices.html). |
| **S3** | This is optional storage for selected redacted reports after the local application works. See [S3 documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html). |
| **CloudWatch** | This is optional central monitoring for nonsecret operating logs and usage measurements. See [CloudWatch documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html). |
| **EC2 or AgentCore Browser** | These are later alternatives for cloud execution. Neither is required for the local release. Cloud browsers need explicit connectivity to local targets. See [EC2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html) and [AgentCore Browser documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-tool.html). |
| **DynamoDB and Amplify Hosting** | These are later options for shared scan history and a hosted interface. Hosting the frontend alone does not host the browser or backend. See [DynamoDB documentation](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html) and [Amplify Hosting documentation](https://docs.aws.amazon.com/amplify/latest/userguide/welcome.html). |

### 4.4 Accounts and Budget

The confirmed $100+ credits are the funding basis. The team will use one designated account for the integrated demonstration where practical. Teammates may experiment in their own accounts, but their balances are not assumed to be pooled. Eligibility and expiry must be checked against the account's [credit details](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/useconsolidatedbilling-credits.html).

| Allocation of the first $100 | Allowance |
| --- | --- |
| Bedrock development and evaluation | $40 |
| Optional storage and monitoring | $10 |
| Optional experiments | $10 |
| Unspent reserve | $40 |

These are allowances rather than expected costs. Bedrock model access must be verified with a small structured-action test, and current [model prices](https://aws.amazon.com/bedrock/pricing/) must be used for cost estimates.

Default application limits are:

- One active scan and forty AI decisions per scan, including retries.
- Two retries for a failed action before requesting guidance.
- Fifteen minutes of active execution, excluding time awaiting developer guidance.
- An estimated inference allowance of $0.25 per scan, checked before every model request.

Cumulative usage is saved across restarts. The backend reserves estimated input and maximum permitted output cost before a model call. Security-test repetitions use ordinary code where possible instead of making an AI request for each attempt. Cost reviews include consumption before credits, not only the amount payable.

## 5. Delivery Plan and Acceptance Criteria

### 5.1 Five-Person Responsibilities

| Member | Ownership |
| --- | --- |
| **1 — Backend and authentication information** | Builds FastAPI, the worker lifecycle, shared models, scan coordination, verified authentication profiles, and analyser invocation. Coordinates AWS permissions and limits. |
| **2 — Website interaction and AI** | Builds Playwright control and capture, Bedrock integration, automatic discovery, guided recording, and replay of authentication flows. |
| **3 — Enumeration checks** | Builds the runners and separate analysers for login, registration, and reset-request enumeration. Supplies evidence fixtures and expected results. |
| **4 — Interface and evidence** | Builds the four views, guidance controls, progress, evidence storage and redaction, report export, and access to offline reanalysis. |
| **5 — Session checks and evaluation environments** | Builds the runners and separate analysers for throttling, fixation, and logout. Prepares test applications with help from Member 3. |

All members contribute to integration testing and the demonstration. Each check owner supplies both browser-level tests of the runner and offline tests of the analyser. Members 1 and 2 review session and browser integration; Members 3 and 5 review each other's result rules.

### 5.2 Schedule

| Dates | Delivery milestone |
| --- | --- |
| **10–12 September** | Establish the new repository, shared models, local frontend/backend connection, a Playwright worker, and a working Bedrock request. |
| **13–16 September** | Complete login discovery, guided fallback, verified authentication information, and one complete runner-to-analyser-to-report example. |
| **17–21 September** | Add registration and reset-request discovery and integrate all six runners and analysers with evidence and result handling. |
| **22–25 September** | Evaluate different applications, verify offline analysis, fix incorrect conclusions, measure reliability and cost, and check setup on another computer. |
| **26–27 September** | Freeze features, complete documentation, and record the demonstration. |
| **28–29 September** | Review and submit. |
| **30 September** | Reserve for submission problems. |

This is an ambitious prototype schedule for a part-time team. Planning assumes four to six hours per member each week. Optional AWS services and interface features will be postponed before reducing the six checks. Any remaining unsupported behaviour will be documented, and incomplete checks will not be presented as completed.

### 5.3 Evaluation Applications

The test environment will include:

- A server-rendered application using forms, redirects, CSRF protection, and cookie sessions.
- A React application using JSON requests, a two-step login page, and bearer-token authentication.
- A separately prepared application whose labels, routes, response fields, and layout are withheld from discovery tuning until evaluation.

Controlled applications will provide secure and vulnerable settings. The evaluation owner will prepare the third application independently of the discovery implementation. This tests adaptation to an unfamiliar layout; it does not prove compatibility with every production application. Historical bWAPP and Juice Shop reports remain comparison material, not a requirement to recreate the old pipeline.

### 5.4 Acceptance Criteria

| Area | Required evidence |
| --- | --- |
| **Six checks** | Each has a vulnerable case, a secure case, an ambiguous case, and an execution-failure case: at least 24 evaluated scenarios. |
| **Runner/analyser separation** | Analysers run with network access disabled and no browser or AWS credentials. Tests fail if an analyser attempts live I/O. |
| **Repeatable analysis** | The same evidence, policy, and analyser version produce the same result. Reanalysis stores a new result while preserving the original. |
| **Offline reporting** | A report can be regenerated from saved evidence and results while the target and AWS are unavailable. |
| **Generality** | Check logic has no branches based on application names, fixed login paths, or familiar response fields. |
| **Discovery** | Each supported flow is attempted five times per relevant application. Automatic and guided completions are reported separately. The target is four automatic completions out of five on the development applications. |
| **Guided fallback** | A developer can demonstrate an initially unsupported flow, and the application can replay it in a fresh context without a code change. |
| **Authentication proof** | HTTP 200, an anonymous response containing a user field, or an unchanged cookie cannot alone establish authenticated access. |
| **Session isolation** | Replay contexts contain only the intended state. Refreshed tokens and current login cookies cannot leak into the experiment. |
| **Stateful flows** | Tests cover changing CSRF tokens, redirects, changing controls, and identifiers that become registered during testing. |
| **Failure handling** | Timeouts, model outages, missing features, stale flows, cancellation, and unsupported authentication produce explicit outcomes. |
| **Privacy and scope** | Test secrets are absent from model requests and exports. Page instructions cannot trigger actions outside the configured scope. |
| **Installation** | Another member can install the new application and complete a scan without installing or starting mitmproxy. |

The final deliverables are the new application, installation instructions, documented OWASP coverage, evaluation results, cost measurements, known limitations, and a demonstration video. The first technical milestone is the connection between **Playwright observations and verified authentication information**, followed by a complete **test runner, offline analyser, and report** for one check.
