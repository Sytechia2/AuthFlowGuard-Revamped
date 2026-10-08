// How each controlled check works, written for administrators who need to
// verify what a check tests and how its verdict is reached without reading
// the code. Every statement mirrors the backend implementation in
// backend/authflowguard/checks (runners and offline analysers) and the scan
// order in backend/authflowguard/scan_manager.py. Update this file whenever a
// check's procedure, compared signals, limits or verdict rules change.
// Codes, labels, severities and recommendations live in checks.ts.

export type CheckVerdictRules = {
  /** When the analyser reports finding_confirmed. */
  finding: string;
  /** When it reports no_issue_observed. */
  noIssue: string;
  /** When it reports inconclusive or execution_error. */
  inconclusive: string;
};

export type CheckDetail = {
  /** Backend check id; matches the ids in checks.ts. */
  id: string;
  /** The security question the check answers. */
  question: string;
  /** Why it matters and what an attacker gains. */
  risk: string;
  /** Inputs or page features the check needs. */
  prerequisites: string[];
  /** Ordered steps the scanner performs. */
  procedure: string[];
  /** What is compared or measured to decide. */
  signals: string[];
  /** What is recorded in the evidence package. */
  evidence: string[];
  verdicts: CheckVerdictRules;
  /** Limits that keep the check non-destructive and in scope. */
  safeguards: string[];
  /** What the check does not establish. */
  limitations: string[];
  /** Repo-relative paths of the implementing modules. */
  sourceFiles: string[];
  /** Official OWASP WSTG page for the check's reference. */
  owaspUrl: string;
};

const WSTG =
  "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing";

const ACCOUNT_ENUMERATION_URL = `${WSTG}/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account`;

const FORM_SOURCE_FILES = [
  "backend/authflowguard/checks/form_enumeration.py",
  "backend/authflowguard/auth_profiles.py",
  "backend/authflowguard/control_roles.py",
  "backend/authflowguard/page_settling.py",
  "backend/authflowguard/action_executor.py",
];

const FORM_NORMALIZATION =
  "Before hashing, page text is normalized: the known, nonexistent and repeat identifiers and the disposable password are replaced, csrf/nonce/request id/tracking id/timestamp key-value pairs, ISO dates and UUIDs become placeholders, and whitespace is collapsed. Native forms also remove the values of hidden inputs. In JSON background responses every number becomes a placeholder.";

const FORM_CLIENT_SIGNALS =
  "Client-rendered form: for the identifier reaction (and, for registration, the submission) the analyser compares background request outcomes (method, path hash, status), background response body hashes, visible text hash, title hash, route hash and control-state hash, plus whether a submission was observed and the matched message categories.";

const FORM_REPEAT_SIGNAL =
  "Client-rendered form: any field that also differed between the nonexistent identifier and a second nonexistent identifier (the first with '-repeat' added) is treated as volatile and discarded.";

export const checkDetails: CheckDetail[] = [
  {
    id: "login_enumeration",
    question:
      "Does a failed login look different for an existing account than for an account that does not exist?",
    risk: "If failures differ, an attacker can confirm which usernames or email addresses have accounts. That list feeds password guessing, credential stuffing and targeted phishing.",
    prerequisites: [
      "A verified login flow saved in the auth profile (the account marker appeared on the protected resource after login and not in an anonymous browser).",
      "The scan's known account username, used as the existing identifier.",
      "A nonexistent identifier supplied with the scan.",
      "A failure password that is not the known account's real password.",
    ],
    procedure: [
      "Launch one headless Chromium browser.",
      "Run 3 pairs of attempts (PAIR_COUNT = 3). Each pair is one failed login with the known identifier, then one with the nonexistent identifier, each in its own new browser context.",
      "Each attempt replays the saved login steps, typing the identifier into the username field and the failure password into the password field (or the field the saved flow fills second).",
      "In a multi-step login, before each later step the scanner waits up to 2000 ms for that step's control. If it does not appear, the nonexistent-identifier attempt stops there and its page is recorded; the known-identifier attempt must complete every step or the attempt is an error.",
      "After the last step, record a page signature: URL without query or fragment, page title, a SHA-256 hash of the visible body text (identifier replaced, whitespace collapsed), its length, a SHA-256 hash of the page's control descriptions, and the in-scope response statuses.",
      "Close the context and discard the attempt's secrets before the next attempt.",
    ],
    signals: [
      "For each pair, the known and nonexistent signatures are compared on four fields: URL, title, body text hash and control-description hash.",
      "Response statuses, body length and steps completed are recorded but not compared.",
      "Response timing is not measured.",
    ],
    evidence: [
      "pairs: for each of the 3 pairs, a known and a nonexistent signature (URL, title, body fingerprint, body length, control fingerprint, response statuses, steps completed).",
      "pair_count, attempted and completed step labels (for example pair-1-known-failure), and any per-attempt error with its error type.",
      "Page-state events labelled with the comparison label, plus the request, response and page-change events from each browser action.",
    ],
    verdicts: {
      finding:
        "All 3 pairs show a difference in URL, title, body hash or control hash, and the policy treats account existence as private (the default).",
      noIssue:
        "None of the 3 pairs shows a difference. Also reported when the scan policy sets account_existence_is_private to false.",
      inconclusive:
        "Inconclusive when some pairs differ and others do not, or when fewer than 3 complete pairs were recorded. Execution error when any of the 6 attempts failed. This analyser never reports unsupported or not applicable.",
    },
    safeguards: [
      "Exactly 6 login attempts, all with the failure password, so the known account receives 3 failed logins from this check.",
      "Each attempt uses a fresh browser context that is closed afterwards.",
      "Actions go through the action executor, which keeps traffic inside the permitted origins and types passwords only into password fields.",
      "Only hashes of page text and controls are kept, not the page body.",
    ],
    limitations: [
      "The check compares three bounded failure pairs and does not establish behavior outside those attempts.",
      "Status codes, headers, body size and timing are not compared, so a difference only in those is not detected.",
      "Body text is normalized only by removing the typed identifier and collapsing whitespace. Visible text that changes on every request can produce a difference that is not account state.",
    ],
    sourceFiles: [
      "backend/authflowguard/checks/login_enumeration.py",
      "backend/authflowguard/action_executor.py",
      "backend/authflowguard/playwright_worker.py",
    ],
    owaspUrl: ACCOUNT_ENUMERATION_URL,
  },
  {
    id: "registration_enumeration",
    question:
      "Does the registration form reveal whether an identifier already has an account?",
    risk: "A registration form that says an address is already registered lets an attacker test identifiers at will. Confirmed accounts become targets for password attacks and phishing.",
    prerequisites: [
      "The registration form address. It is taken from the scan request (registration_url) if given, then from the auth profile if discovery saved an in-scope registration link, and otherwise from a single visible link on the login page whose name matches register, registration, sign up or create (an) account.",
      "The scan's known account username, used as the existing identifier.",
      "A fresh nonexistent identifier that differs from the known one.",
      "A disposable registration password. If none is supplied, the scan's failure password is used.",
    ],
    procedure: [
      "Each attempt uses a new browser context with service workers blocked and a 5000 ms default action and navigation timeout.",
      "If no form address was supplied or saved, open the login page and look for exactly one matching registration link destination.",
      "Open the form. If the page has exactly one visible form and it uses POST, treat it as a native form; otherwise treat it as client-rendered.",
      "Native form: require a form action inside the permitted origins, exactly one identifier field, exactly one password field and exactly one submit control. Fill the identifier and disposable password, submit, and wait for the POST navigation. Statuses 200, 201, 202, 302, 303 and 409 are accepted; anything else is an error.",
      "Client-rendered form: require exactly one visible identifier-like field. Type the identifier and press Tab, wait up to 2 s for a background request carrying the identifier to start and up to 5 s more for it to finish, then record the reaction.",
      "Client-rendered form, continued: fill the form's other empty visible fields (password fields with the disposable password, text fields with 'AuthFlowGuard evaluation'), choose the first option of empty dropdowns, and click the single submit control if it is enabled. Record the submission.",
      "Run this once with the known identifier and once with the nonexistent identifier. For a client-rendered form, run it a third time with a second nonexistent identifier (the first with '-repeat' added before the @, or appended).",
    ],
    signals: [
      "Native form: initial status, final status, normalized body hash, title hash, redirect path hash, control-state hash (type, visibility, disabled, aria-invalid, validity) and matched message categories. Any difference in one of these is a difference.",
      "Message categories are fixed patterns: existing_account (already registered/exists/in use, must be unique), unknown_account (no account exists, account not found) and generic_instructions.",
      FORM_CLIENT_SIGNALS,
      FORM_REPEAT_SIGNAL,
      FORM_NORMALIZATION,
    ],
    evidence: [
      "known_identifier_attempt, nonexistent_identifier_attempt and, for client-rendered forms, repeat_nonexistent_identifier_attempt: the hashed signature of each.",
      "form_url_source (scan_input, saved_profile or keyword_search) and the capture time.",
      "Attempted and completed step labels, and structural action events (method, resource type, status, timing, which page aspects changed). Page titles and URLs from actions are not kept.",
    ],
    verdicts: {
      finding:
        "Any compared field differs between the known and nonexistent attempts in the single captured pair (after discarding volatile fields for client-rendered forms), and account existence is private (the default).",
      noIssue:
        "No compared field differs. Also reported when the policy sets account_existence_is_private to false.",
      inconclusive:
        "Inconclusive when either attempt lacks a complete submitted observation, when a client-rendered registration was not accepted (the nonexistent submission was not observed or got no 2xx background response), or when every difference also appeared between the two nonexistent identifiers. Execution error when an attempt failed, an unexpected native status was recorded, or any background response of a client-rendered form was 5xx. This analyser never reports unsupported or not applicable.",
    },
    safeguards: [
      "Each identifier is submitted once; the nonexistent attempt is not repeated because that could turn it into a real account.",
      "The form's submission target must be inside the permitted origins, and scripted actions go through the action executor's scope guard.",
      "Only one unambiguous form is used; missing or ambiguous identifier, password or submit controls stop the attempt.",
      "Response bodies are read in memory and only their normalized hashes are stored.",
    ],
    limitations: [
      "One known/nonexistent pair was submitted in separate fresh browser contexts; timing differences and repeatability beyond this pair were not tested.",
      "Registration may create the disposable account (and, for a client-rendered form, a second one with '-repeat' added to its identifier). Use a new nonexistent identifier or reset the evaluation application before the next scan.",
      "Dynamic hidden values, labelled tokens, timestamps and UUIDs are normalized; unrecognized dynamic content can require manual evidence review.",
      "Client-rendered forms only count background fetch/XHR requests whose URL or POST body carries the identifier; other traffic is ignored.",
    ],
    sourceFiles: [
      "backend/authflowguard/checks/registration_enumeration.py",
      ...FORM_SOURCE_FILES,
    ],
    owaspUrl: ACCOUNT_ENUMERATION_URL,
  },
  {
    id: "reset_request_enumeration",
    question:
      "Does the password-reset request reveal whether an identifier has an account?",
    risk: "A reset form that answers 'no account found' for unknown identifiers is an unauthenticated account-existence oracle. It is also a channel for flooding real users with reset messages.",
    prerequisites: [
      "The reset-request form address. It is taken from the scan request (reset_request_url) if given, then from the auth profile if discovery saved an in-scope reset link, and otherwise from a single visible link on the login page whose name matches reset/forgot/recover (your) password or password reset.",
      "The scan's known account username, used as the existing identifier.",
      "A nonexistent identifier that differs from the known one.",
    ],
    procedure: [
      "Each attempt uses a new browser context with service workers blocked and a 5000 ms default action and navigation timeout.",
      "If no form address was supplied or saved, open the login page and look for exactly one matching reset link destination.",
      "Open the form. If the page has exactly one visible form and it uses POST, treat it as a native form; otherwise treat it as client-rendered.",
      "Native form: require a form action inside the permitted origins, exactly one identifier field, no password field and exactly one submit control. Fill the identifier, submit, and wait for the POST navigation. Statuses 200, 201, 202, 302 and 303 are accepted; anything else is an error.",
      "Client-rendered form: require exactly one visible identifier-like field. Type the identifier and press Tab, wait up to 2 s for a background request carrying the identifier to start and up to 5 s more for it to finish, then record the reaction. The form is not submitted.",
      "Run this once with the known identifier and once with the nonexistent identifier. For a client-rendered form, run it a third time with a second nonexistent identifier (the first with '-repeat' added).",
    ],
    signals: [
      "Native form: initial status, final status, normalized body hash, title hash, redirect path hash, control-state hash and matched message categories (existing_account, unknown_account, generic_instructions). Any difference counts.",
      FORM_CLIENT_SIGNALS,
      FORM_REPEAT_SIGNAL,
      FORM_NORMALIZATION,
    ],
    evidence: [
      "known_identifier_attempt, nonexistent_identifier_attempt and, for client-rendered forms, repeat_nonexistent_identifier_attempt: the hashed signature of each.",
      "form_url_source (scan_input, saved_profile or keyword_search) and the capture time.",
      "Attempted and completed step labels and structural action events.",
    ],
    verdicts: {
      finding:
        "Any compared field differs between the known and nonexistent attempts in the single captured pair (after discarding volatile fields for client-rendered forms), and account existence is private (the default).",
      noIssue:
        "No compared field differs. Also reported when the policy sets account_existence_is_private to false.",
      inconclusive:
        "Inconclusive when either attempt lacks a complete observation, when a client-rendered form sent no background request carrying the identifier for the known or the nonexistent attempt (nothing was compared), or when every difference also appeared between the two nonexistent identifiers. Execution error when an attempt failed, an unexpected native status was recorded, or any background response of a client-rendered form was 5xx. This analyser never reports unsupported or not applicable.",
    },
    safeguards: [
      "Each identifier is used in exactly one attempt.",
      "Client-rendered reset forms are never submitted, because completing one could change a real account's password.",
      "The form's submission target must be inside the permitted origins, and scripted actions go through the action executor's scope guard.",
      "Response bodies are read in memory and only their normalized hashes are stored.",
    ],
    limitations: [
      "One known/nonexistent pair was submitted in separate fresh browser contexts; timing differences and repeatability beyond this pair were not tested.",
      "A native reset form is submitted for the known identifier, so the application may send a reset message to that account.",
      "A client-rendered form is compared only on how it reacts to the identifier before submission; a difference shown only after submitting is not observed.",
      "Dynamic hidden values, labelled tokens, timestamps and UUIDs are normalized; unrecognized dynamic content can require manual evidence review.",
    ],
    sourceFiles: [
      "backend/authflowguard/checks/reset_request_enumeration.py",
      ...FORM_SOURCE_FILES,
    ],
    owaspUrl: ACCOUNT_ENUMERATION_URL,
  },
  {
    id: "login_throttling",
    question:
      "After repeated failed logins, does the application restrict a further correct login for the same account?",
    risk: "Without throttling or lockout, an attacker can guess passwords for an account as fast as the server answers. Online brute force and credential stuffing then become practical.",
    prerequisites: [
      "A verified login flow with at least a username and a password fill.",
      "The known account's username and correct password.",
      "A failure password that is not the correct password.",
      "Optional: expected_lockout_threshold in the scan request's policy (SecurityPolicy in backend/authflowguard/models.py). It is unset by default.",
    ],
    procedure: [
      "Work out the number of failed attempts: the policy's expected_lockout_threshold if set, otherwise 3 (DEFAULT_ATTEMPTS), and never more than 5 (MAX_ATTEMPTS).",
      "Make that many failed logins one after another, each replaying the saved login steps with the known username and the failure password in a new browser context with service workers blocked. There is no pause between attempts.",
      "Stop at the first attempt that fails to run.",
      "If all failed attempts ran, make one more login with the correct password in a new context: the valid-login control.",
      "For each attempt record the in-scope response statuses, the last of them as the final status, the URL without query, hashes of the title and body text, and which fixed indicators the body text matches.",
    ],
    signals: [
      "The valid-login control is restricted if its final status is 401, 403, 423 or 429, or its page text matches 'try again later', 'too many', 'locked' or 'unavailable'.",
      "The valid-login control succeeded if its final status is 200, 201, 202, 204, 302 or 303.",
      "Every failed attempt's final status must be one of 200, 201, 202, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 409, 423 or 429.",
      "Any recorded status of 500 or above, in any attempt, is a server error.",
    ],
    evidence: [
      "failed_attempts: one signature per failed attempt (status codes, final status, URL, title and body fingerprints, safe indicators: rate_limited, authentication_required, signed_in), followed by valid_login_control with the same fields.",
      "attempt_count and the capture time.",
      "Action events with structural fields only (status, method, resource type, URL, timing, which page aspects changed).",
    ],
    verdicts: {
      finding:
        "The valid-login control succeeded after the bounded failed attempts, with no throttling or lockout response observed.",
      noIssue:
        "The valid-login control was restricted after the failed attempts.",
      inconclusive:
        "Inconclusive when the attempt sequence or control is incomplete or malformed, or when the control's final status is neither a success nor a restriction status and no rate-limit text appeared. Execution error when an attempt failed to run, any status was 500 or above, or a failed attempt's final status is outside the accepted list. This analyser never reports unsupported or not applicable.",
    },
    safeguards: [
      "At most 5 failed attempts and one valid login per scan.",
      "Each attempt uses a fresh browser context with service workers blocked, closed afterwards.",
      "Scripted actions go through the action executor's scope guard; passwords are typed only into password fields.",
      "Only hashes of page text and title are stored.",
    ],
    limitations: [
      "The runner tested the bounded number of failed attempts (3 by default) and one valid-login control.",
      "The threshold outside this bounded attempt count was not tested. If expected_lockout_threshold is above 5, only 5 failures are made, and a successful control is still reported as a finding.",
      "The final status is the last in-scope response the browser saw during the login steps, which can be a page sub-resource rather than the login response itself.",
      "Rate-limit text is matched with fixed English patterns only.",
      "This check runs before session fixation and logout invalidation. If it locks the account, those later checks may not demonstrate authenticated access.",
    ],
    sourceFiles: [
      "backend/authflowguard/checks/login_throttling.py",
      "backend/authflowguard/action_executor.py",
    ],
    owaspUrl: `${WSTG}/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism`,
  },
  {
    id: "session_fixation",
    question:
      "Does the session the browser held before login still grant authenticated access after login?",
    risk: "If the pre-login session identifier stays valid after login, an attacker who plants or learns it before the victim signs in can use the victim's authenticated session.",
    prerequisites: [
      "A verified login flow with at least a username and a password fill.",
      "The known account's username and password.",
      "A protected resource URL inside the permitted origins.",
      "An account marker: a CSS selector that matches only on the signed-in view of the protected resource.",
    ],
    procedure: [
      "Context A (new, service workers blocked): open the target URL and wait for it to load and for background requests to settle (up to 5 s).",
      "Capture every cookie in context A: the pre-login session.",
      "Run the saved login steps in the same context, then open the protected resource and record its status, whether the account marker is present, and its URL. This is the authenticated control. Capture the cookies again: the post-login session.",
      "Close context A. Open context B, load only the pre-login cookies into it, open the protected resource and record status and marker: the original-session replay.",
      "Open context C with no cookies, open the protected resource and record status and marker: the anonymous control.",
    ],
    signals: [
      "Authenticated control: status 200 and marker present is required.",
      "Original-session replay: status 200 with the marker present means the pre-login session authenticates.",
      "The replay counts as rejected only when the anonymous control lacks the marker and the replay returned 401 or 403, or returned the same 5xx status as the anonymous control without the marker.",
      "Whether the cookie set changed between pre-login and post-login is recorded (session_rotated) but does not decide the verdict.",
    ],
    evidence: [
      "pre_login_session and post_login_session: cookie count, cookie names and a SHA-256 fingerprint over name, domain, path and a hash of each value.",
      "authenticated_control, original_session_replay and anonymous_control: status, marker present, URL without query or fragment.",
      "session_rotated and the capture time.",
    ],
    verdicts: {
      finding:
        "The authenticated control showed the marker with status 200, and the replay of the pre-login cookies also returned 200 with the marker.",
      noIssue:
        "The authenticated control was demonstrated and the replay was rejected like a signed-out visitor (see signals).",
      inconclusive:
        "Inconclusive when a control is missing or has no usable status, when authenticated access was not demonstrated, or when the replay is neither authenticated nor rejected (for example a redirect to a login page that ends in 200 without the marker). Execution error when execution failed or a server error prevents a trustworthy comparison. This analyser never reports unsupported or not applicable.",
    },
    safeguards: [
      "One login with the known account; the replay and anonymous controls only open the protected resource.",
      "Each phase runs in its own browser context with service workers blocked, closed afterwards.",
      "The protected resource must be inside the permitted origins; login steps go through the action executor's scope guard.",
      "Cookie values are used only in memory to build the replay; evidence stores hashes of them.",
    ],
    limitations: [
      "The procedure demonstrates session reuse when the captured pre-login state authenticates; it does not establish that an attacker can force a victim to accept that state.",
      "Only browser cookie state visible to the isolated context was compared.",
      "A signed-out response other than 401, 403 or a 5xx matching the anonymous control gives an inconclusive result rather than a pass.",
    ],
    sourceFiles: [
      "backend/authflowguard/checks/session_fixation.py",
      "backend/authflowguard/checks/session_common.py",
      "backend/authflowguard/page_settling.py",
    ],
    owaspUrl: `${WSTG}/06-Session_Management_Testing/03-Testing_for_Session_Fixation`,
  },
  {
    id: "logout_invalidation",
    question:
      "After logout, does the server still accept the session cookies the browser held before logging out?",
    risk: "If logout only clears the browser, anyone who copied the session cookie keeps full access to the account. A stolen or shared-computer session then outlives the user's logout.",
    prerequisites: [
      "A verified login flow with at least a username and a password fill.",
      "The known account's username and password.",
      "A protected resource URL inside the permitted origins and an account marker selector.",
      "A way to log out: a verified logout flow saved in the auth profile, or a logout form or control the check can find.",
    ],
    procedure: [
      "Context A (new, service workers blocked): run the saved login steps, open the protected resource and record status, marker and URL: the authenticated control.",
      "Capture every cookie in context A: the active session.",
      "Log out. If the profile has a verified logout flow, replay it; each control must match its recorded fingerprint. If a recorded control is not found, mark the saved flow stale and fall back to searching.",
      "Search, step 1: submit the first form whose action contains 'logout' or whose text contains 'log out' or 'logout', waiting up to 5000 ms for a POST response.",
      "Search, step 2: click the first visible button, link, role=button or role=menuitem labelled log out, log off, sign out or sign off (with or without a space or hyphen). If none is visible, open up to 3 account menus (buttons that declare a popup, labelled account, user, profile or menu), waiting 300 ms after each. If still none, go to the target URL and search once more.",
      "During the logout, record the status of every non-GET response and every response to a URL matching log/sign out/off. Then open the protected resource again in context A: the post-logout control.",
      "Close context A. Open context B, load only the captured pre-logout cookies, open the protected resource: the old-session replay.",
      "Open context C with no cookies and open the protected resource: the anonymous control.",
    ],
    signals: [
      "Authenticated control: status 200 and marker present is required.",
      "Logout must produce a usable status, or be shown as client-side only: a clicked control sent no request and the post-logout page lacks the marker.",
      "Old-session replay: status 200 with the marker present means the session survived logout.",
      "The replay counts as rejected only when the anonymous control lacks the marker and the replay returned 401 or 403, or returned the same 5xx status as the anonymous control without the marker.",
    ],
    evidence: [
      "authenticated_control, post_logout_control, old_session_replay and anonymous_control: status, marker present, URL without query or fragment.",
      "active_session: cookie count, names and a fingerprint of hashed values.",
      "logout_source (saved_profile or keyword_search), logout_method (form or control), logout_status, logout_request_observed, saved_logout_flow_stale when it applies, and the capture time.",
    ],
    verdicts: {
      finding:
        "Authenticated access was demonstrated and the replayed pre-logout cookies again returned 200 with the marker. If logout sent no request, the explanation says logout only cleared browser state.",
      noIssue:
        "Authenticated access was demonstrated and the replay was rejected like a signed-out visitor (see signals).",
      inconclusive:
        "Inconclusive when a control is missing, logout gave no usable status and was not shown to be client-side, authenticated access was not demonstrated, or the replay is neither authenticated nor rejected (for example a redirect to a login page ending in 200 without the marker). Execution error when execution failed, no logout control was found, logout returned 5xx, or a server error prevents a trustworthy comparison. This analyser never reports unsupported or not applicable.",
    },
    safeguards: [
      "When searching for a logout button or link, it never clicks a control labelled with delete, remove, deactivate, erase, terminate, unsubscribe, close, cancel or disable.",
      "Only menu toggles that declare a popup are opened, at most 3, and the search stops if opening one navigates away.",
      "Each saved logout step is checked by the action executor before it is clicked; if a recorded control no longer resolves, nothing else is clicked in its place.",
      "Each phase runs in its own browser context with service workers blocked, closed afterwards; cookie values are kept only as hashes in evidence.",
    ],
    limitations: [
      "The replay uses only browser cookie state captured before logout.",
      "Bearer tokens held outside browser cookie storage are not replayed by this check.",
      "The post-logout control in the original browser is used only to confirm a client-side logout; it does not decide the verdict otherwise.",
      "A signed-out response other than 401, 403 or a 5xx matching the anonymous control gives an inconclusive result rather than a pass.",
    ],
    sourceFiles: [
      "backend/authflowguard/checks/logout_invalidation.py",
      "backend/authflowguard/checks/session_common.py",
      "backend/authflowguard/control_roles.py",
      "backend/authflowguard/control_safety.py",
      "backend/authflowguard/auth_profiles.py",
    ],
    owaspUrl: `${WSTG}/06-Session_Management_Testing/06-Testing_for_Logout_Functionality`,
  },
];

export function checkDetail(checkId: string): CheckDetail | undefined {
  return checkDetails.find((detail) => detail.id === checkId);
}

/** Facts that apply to every check. */
export const methodology: string[] = [
  "Checks run only after the login flow is verified, one at a time in a fixed order: login enumeration, reset-request enumeration, registration enumeration, login throttling, session fixation, logout invalidation. Unselected checks are skipped.",
  "Scope is enforced by origin (scheme, host and port). The action executor refuses navigation outside the permitted origins, aborts any out-of-scope request from its browser context, and records only in-scope requests and responses.",
  "Each attempt runs in its own new headless Chromium browser context that is closed afterwards, and session checks use separate new contexts for the replay and anonymous controls. Cookies carry over only where a session check deliberately copies them into a replay context.",
  "AI (Amazon Bedrock, when that discovery mode is chosen) only helps with discovery: finding the login flow and its controls. Verdicts come from deterministic analysers that read the saved evidence and the scan policy, with no browser, network or model call, and can be re-run on stored evidence.",
  "Credentials are resolved in memory at the moment a field is filled and discarded after each check. Passwords are typed only into password fields. Stored evidence keeps hashes instead of page bodies and cookie values, and is redacted before saving: secret values are replaced, sensitive keys such as cookie, password, token, headers and body are blanked, and URL query strings are removed.",
];
