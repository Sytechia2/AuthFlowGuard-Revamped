import { FormEvent, useEffect, useState } from "react";

export type ViewId = "setup" | "discovery" | "testing" | "results";
export type ConnectionStatus = "checking" | "connected" | "offline";

type WorkflowView = {
  id: ViewId;
  label: string;
  description: string;
};

type SecurityCheck = {
  id: string;
  code: string;
  label: string;
  reference: string;
};

export type ScanResult = {
  result_id?: string;
  check_id: string;
  outcome: string;
  owasp_reference: string;
  explanation: string;
  evidence_references?: string[];
  coverage_limitations?: string[];
  created_at?: string;
  analyser_version?: string;
};

export type ScanStatus = {
  scan_id: string;
  state: string;
  target_url?: string;
  created_at?: string;
  event_count: number;
  evidence_count: number;
  result_count: number;
  results: ScanResult[];
  error?: string | null;
  profile_source?: "automatic" | "guided" | null;
  guidance_required?: boolean;
};

type SafeControl = {
  observed_control_id: string;
  tag: string;
  id: string | null;
  name: string | null;
  type: string | null;
  placeholder: string | null;
  autocomplete: string | null;
  aria_label: string | null;
  value_present: boolean | null;
  visible: boolean;
};

type GuidanceActionType = "navigate" | "fill" | "click";

type GuidanceActionDraft = {
  actionType: GuidanceActionType;
  controlId: string;
  valueReference: string;
  url: string;
  description: string;
};

type GuidanceObservation = {
  url?: string;
  title?: string;
  controls: SafeControl[];
};

function controlLabel(control: SafeControl): string {
  const label =
    control.aria_label ??
    control.name ??
    control.id ??
    control.placeholder ??
    (control.type === "password" ? "Password field" : "Unnamed control");
  const kind = control.type ? ` (${control.type})` : "";
  return `${label}${kind}`;
}

const workflowViews: WorkflowView[] = [
  {
    id: "setup",
    label: "Setup",
    description: "Define the target and test scope",
  },
  {
    id: "discovery",
    label: "Discovery",
    description: "Verify authentication flows",
  },
  {
    id: "testing",
    label: "Testing",
    description: "Run controlled security checks",
  },
  {
    id: "results",
    label: "Results",
    description: "Review evidence and coverage",
  },
];

const securityChecks: SecurityCheck[] = [
  {
    id: "login-enumeration",
    code: "CHK-001",
    label: "Login account enumeration",
    reference: "WSTG-IDNT-04",
  },
  {
    id: "registration-enumeration",
    code: "CHK-002",
    label: "Registration account enumeration",
    reference: "WSTG-IDNT-04",
  },
  {
    id: "reset-request-enumeration",
    code: "CHK-003",
    label: "Reset-request account enumeration",
    reference: "WSTG-IDNT-04",
  },
  {
    id: "login-throttling",
    code: "CHK-004",
    label: "Login throttling and lockout",
    reference: "WSTG-ATHN-03",
  },
  {
    id: "session-fixation",
    code: "CHK-005",
    label: "Session fixation",
    reference: "WSTG-SESS-03",
  },
  {
    id: "logout-invalidation",
    code: "CHK-006",
    label: "Logout invalidation",
    reference: "WSTG-SESS-06",
  },
];

type SidebarProps = {
  activeView: ViewId;
  connectionStatus: ConnectionStatus;
  scan: ScanStatus | null;
  onSelectView: (view: ViewId) => void;
};

export function Sidebar({
  activeView,
  connectionStatus,
  scan,
  onSelectView,
}: SidebarProps) {
  const statusLabels: Record<ConnectionStatus, string> = {
    checking: "Checking local API",
    connected: "Local API online",
    offline: "Local API offline",
  };

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark" aria-hidden="true">
          AF
        </div>
        <div>
          <strong>AuthFlowGuard</strong>
          <span>Local authentication testing</span>
        </div>
      </div>

      <nav aria-label="Assessment workflow">
        {workflowViews.map((view, index) => {
          const state = workflowState(view.id, scan);
          return (
            <button
              className={`nav-item ${activeView === view.id ? "nav-item-active" : ""}`}
              aria-current={activeView === view.id ? "step" : undefined}
              key={view.id}
              onClick={() => onSelectView(view.id)}
              type="button"
            >
              <span className="nav-index">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="nav-copy">
                <strong>{view.label}</strong>
                <small>{view.description}</small>
              </span>
              <span className={`workflow-state workflow-state-${state}`}>
                {formatWorkflowState(state)}
              </span>
            </button>
          );
        })}
      </nav>

      <div
        className={`connection connection-${connectionStatus}`}
        role="status"
      >
        <span className="status-dot" aria-hidden="true" />
        <div>
          <strong>{statusLabels[connectionStatus]}</strong>
          <small>FastAPI · 127.0.0.1:8080</small>
        </div>
      </div>
    </aside>
  );
}

function displayHost(value: string): string {
  try {
    return new URL(value).host || "Not set";
  } catch {
    return value.trim() || "Not set";
  }
}

function formatDate(value?: string): string {
  if (!value) return "Unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function formatScanState(state?: string): string {
  const labels: Record<string, string> = {
    created: "Created",
    running: "Running",
    awaiting_guidance: "Guidance required",
    completed: "Completed",
    failed: "Failed",
    cancelled: "Cancelled",
  };
  return state ? (labels[state] ?? state.replaceAll("_", " ")) : "Loading";
}

function checkDefinition(checkId: string): SecurityCheck {
  const normalized = checkId.replaceAll("_", "-");
  return (
    securityChecks.find((check) => check.id === normalized) ?? {
      id: normalized,
      code: "CHECK",
      label: checkId.replaceAll("_", " "),
      reference: "",
    }
  );
}

function outcomeDefinition(outcome: string): { label: string; tone: string } {
  const values: Record<string, { label: string; tone: string }> = {
    finding_confirmed: { label: "Finding confirmed", tone: "danger" },
    no_issue_observed: { label: "No issue observed", tone: "success" },
    inconclusive: { label: "Inconclusive", tone: "warning" },
    execution_error: { label: "Execution error", tone: "danger" },
    unsupported: { label: "Unsupported", tone: "neutral" },
    not_applicable: { label: "Not applicable", tone: "neutral" },
  };
  return (
    values[outcome] ?? {
      label: outcome.replaceAll("_", " "),
      tone: "neutral",
    }
  );
}

function StatusBadge({
  label,
  tone = "neutral",
}: {
  label: string;
  tone?: string;
}) {
  return <span className={`status-badge status-badge-${tone}`}>{label}</span>;
}

type WorkflowState = "active" | "complete" | "attention" | "running" | "idle";

function workflowState(view: ViewId, scan: ScanStatus | null): WorkflowState {
  if (!scan) return "idle";
  if (view === "setup") return "complete";
  if (view === "discovery") {
    return scan.guidance_required
      ? "attention"
      : scan.profile_source
        ? "complete"
        : "idle";
  }
  if (view === "testing") {
    return scan.state === "running"
      ? "running"
      : ["completed", "failed", "cancelled"].includes(scan.state)
        ? "complete"
        : "idle";
  }
  return scan.result_count > 0 || scan.state === "completed"
    ? "complete"
    : "idle";
}

function formatWorkflowState(state: WorkflowState): string {
  return {
    active: "Current",
    complete: "Complete",
    attention: "Needs input",
    running: "Running",
    idle: "Not started",
  }[state];
}

type SetupViewProps = {
  onStarted: (scanId: string, selectedChecks: string[]) => void;
};

export function SetupView({ onStarted }: SetupViewProps) {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:3000");
  const [permittedOrigins, setPermittedOrigins] = useState(
    "http://127.0.0.1:3000",
  );
  const [knownUsername, setKnownUsername] = useState("");
  const [password, setPassword] = useState("");
  const [secondFactor, setSecondFactor] = useState("");
  const [nonexistentUsername, setNonexistentUsername] = useState("");
  const [failurePassword, setFailurePassword] = useState("");
  const [protectedResource, setProtectedResource] = useState(
    "http://127.0.0.1:3000/account",
  );
  const [accountMarkerSelector, setAccountMarkerSelector] = useState(
    '[data-testid="account-marker"]',
  );
  const [accountMarkerDescription, setAccountMarkerDescription] = useState(
    "Authenticated account marker",
  );
  const [selectedChecks, setSelectedChecks] = useState<string[]>(
    securityChecks.map((check) => check.id),
  );
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function toggleCheck(checkId: string) {
    if (selectedChecks.includes(checkId)) {
      setSelectedChecks(selectedChecks.filter((id) => id !== checkId));
      return;
    }

    setSelectedChecks([...selectedChecks, checkId]);
  }

  async function submitSetup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsStarting(true);
    setError(null);

    try {
      const origins = permittedOrigins
        .split(/\r?\n/)
        .map((origin) => origin.trim())
        .filter(Boolean);
      const selectedBackendChecks = selectedChecks.map((checkId) =>
        checkId.replaceAll("-", "_"),
      );
      const createResponse = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: {
            target_url: targetUrl.trim(),
            permitted_origins: origins,
          },
          selected_checks: selectedBackendChecks,
          credential_references: [
            { reference_id: "username", purpose: "Known account username" },
            { reference_id: "password", purpose: "Known account password" },
            {
              reference_id: "failure_password",
              purpose: "Invalid password for controlled failures",
            },
            ...(secondFactor.trim()
              ? [
                  {
                    reference_id: "second_factor",
                    purpose: "One-time verification code",
                  },
                ]
              : []),
          ],
          disposable_identifier_references: [
            {
              reference_id: "nonexistent_username",
              purpose: "Nonexistent account identifier",
            },
          ],
        }),
      });
      if (!createResponse.ok) {
        const detail = (await createResponse.json().catch(() => null)) as {
          detail?: string;
        } | null;
        throw new Error(
          detail?.detail ??
            `The backend rejected the scan setup (HTTP ${createResponse.status}).`,
        );
      }
      const created = (await createResponse.json()) as {
        scan_id?: string;
      };
      if (!created.scan_id) {
        throw new Error("The backend did not return a scan ID.");
      }

      const startResponse = await fetch(
        `/api/scans/${encodeURIComponent(created.scan_id)}/start`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            runtime_secrets: {
              username: knownUsername,
              password,
              ...(secondFactor.trim() ? { second_factor: secondFactor } : {}),
              nonexistent_username: nonexistentUsername,
              failure_password: failurePassword,
            },
            username_reference: "username",
            password_reference: "password",
            second_factor_reference: secondFactor.trim()
              ? "second_factor"
              : null,
            nonexistent_identifier_reference: "nonexistent_username",
            failure_password_reference: "failure_password",
            protected_resource: protectedResource.trim(),
            account_marker_selector: accountMarkerSelector.trim(),
            account_marker_description: accountMarkerDescription.trim(),
          }),
        },
      );
      if (!startResponse.ok) {
        const detail = (await startResponse.json().catch(() => null)) as {
          detail?: string;
        } | null;
        throw new Error(
          detail?.detail ??
            `The backend could not start the scan (HTTP ${startResponse.status}).`,
        );
      }
      setPassword("");
      setSecondFactor("");
      setFailurePassword("");
      onStarted(created.scan_id, selectedChecks);
    } catch (startError) {
      setError(
        startError instanceof Error
          ? startError.message
          : "Unable to start the scan.",
      );
    } finally {
      setIsStarting(false);
    }
  }

  return (
    <form className="setup-grid" onSubmit={submitSetup}>
      <section className="panel target-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">A</p>
            <h2>Target scope</h2>
          </div>
          <span className="required-label">Required</span>
        </div>

        <div className="field">
          <label htmlFor="target-url">Target URL</label>
          <input
            aria-describedby="target-url-help"
            id="target-url"
            onChange={(event) => setTargetUrl(event.target.value)}
            placeholder="https://staging.example.test"
            required
            type="url"
            value={targetUrl}
          />
          <small id="target-url-help">
            The login page or application entry point.
          </small>
        </div>

        <div className="field">
          <label htmlFor="permitted-origins">Permitted origins</label>
          <textarea
            aria-describedby="permitted-origins-help"
            id="permitted-origins"
            onChange={(event) => setPermittedOrigins(event.target.value)}
            required
            rows={3}
            value={permittedOrigins}
          />
          <small id="permitted-origins-help">
            One frontend or API origin per line. Requests outside this list are
            blocked.
          </small>
        </div>

        <div className="scope-notice">
          <span aria-hidden="true">!</span>
          <p>
            Only test websites you own or have explicit permission to assess.
          </p>
        </div>
      </section>

      <section className="panel checks-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">B</p>
            <h2>Security checks</h2>
          </div>
          <span className="selection-count">
            {selectedChecks.length} selected
          </span>
        </div>

        <div className="check-list">
          {securityChecks.map((check, index) => (
            <label className="check-row" key={check.id}>
              <input
                checked={selectedChecks.includes(check.id)}
                onChange={() => toggleCheck(check.id)}
                type="checkbox"
              />
              <span className="check-index">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="check-copy">
                <strong>{check.label}</strong>
                <small>{check.reference}</small>
              </span>
            </label>
          ))}
        </div>
      </section>

      <section className="panel credentials-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">C</p>
            <h2>Runtime login data</h2>
          </div>
          <span className="required-label">Local only</span>
        </div>

        <p className="panel-help">
          These values are used for this scan only. They are sent to the local
          backend and discarded after execution.
        </p>
        <h3 className="subsection-title">Login credentials</h3>
        <div className="credential-fields">
          <div className="field">
            <label htmlFor="known-username">Known account username</label>
            <input
              id="known-username"
              onChange={(event) => setKnownUsername(event.target.value)}
              required
              value={knownUsername}
            />
          </div>
          <div className="field">
            <label htmlFor="known-password">Known account password</label>
            <input
              id="known-password"
              onChange={(event) => setPassword(event.target.value)}
              required
              type="password"
              value={password}
            />
          </div>
          <div className="field">
            <label htmlFor="second-factor">One-time verification code</label>
            <input
              id="second-factor"
              onChange={(event) => setSecondFactor(event.target.value)}
              placeholder="Only for two-step login flows"
              value={secondFactor}
            />
            <small>Optional; kept in memory only for this scan.</small>
          </div>
          <div className="field">
            <label htmlFor="nonexistent-username">
              Nonexistent account username
            </label>
            <input
              id="nonexistent-username"
              onChange={(event) => setNonexistentUsername(event.target.value)}
              required
              value={nonexistentUsername}
            />
            {selectedChecks.includes("registration-enumeration") && (
              <small>
                Registration may create this account. Use a fresh disposable
                identifier for each scan.
              </small>
            )}
          </div>
          <div className="field">
            <label htmlFor="failure-password">Invalid password</label>
            <input
              id="failure-password"
              onChange={(event) => setFailurePassword(event.target.value)}
              required
              type="password"
              value={failurePassword}
            />
            {selectedChecks.includes("registration-enumeration") && (
              <small>
                Also used as the disposable account's registration password.
              </small>
            )}
          </div>
        </div>

        <div className="subsection-heading">
          <div>
            <h3 className="subsection-title">Authentication verification</h3>
            <p>
              Define the protected page and the marker that proves sign-in
              succeeded.
            </p>
          </div>
          <span className="required-label">Advanced</span>
        </div>
        <div className="credential-fields">
          <div className="field">
            <label htmlFor="protected-resource">Protected resource URL</label>
            <input
              id="protected-resource"
              onChange={(event) => setProtectedResource(event.target.value)}
              required
              type="url"
              value={protectedResource}
            />
          </div>
          <div className="field">
            <label htmlFor="account-marker-selector">
              Authenticated marker selector
            </label>
            <input
              id="account-marker-selector"
              onChange={(event) => setAccountMarkerSelector(event.target.value)}
              required
              value={accountMarkerSelector}
            />
          </div>
          <div className="field">
            <label htmlFor="account-marker-description">
              Marker description
            </label>
            <input
              id="account-marker-description"
              onChange={(event) =>
                setAccountMarkerDescription(event.target.value)
              }
              required
              value={accountMarkerDescription}
            />
          </div>
        </div>
      </section>

      <section className="panel readiness-panel">
        <div>
          <p className="eyebrow">Scan readiness</p>
          <h2>Review the local scan plan</h2>
          <dl className="readiness-summary">
            <div>
              <dt>Target</dt>
              <dd>{displayHost(targetUrl)}</dd>
            </div>
            <div>
              <dt>Scope</dt>
              <dd>
                {
                  permittedOrigins
                    .split(/\r?\n/)
                    .filter((origin) => origin.trim()).length
                }{" "}
                permitted origin(s)
              </dd>
            </div>
            <div>
              <dt>Checks</dt>
              <dd>{selectedChecks.length} selected</dd>
            </div>
            <div>
              <dt>Credentials</dt>
              <dd>
                {knownUsername && password ? "Provided locally" : "Required"}
              </dd>
            </div>
          </dl>
        </div>
        <button
          className="primary-button"
          disabled={selectedChecks.length === 0 || isStarting}
          type="submit"
        >
          {isStarting ? "Starting scan..." : "Start local scan"}
          <span aria-hidden="true">→</span>
        </button>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </section>
    </form>
  );
}

type DiscoveryViewProps = {
  scanId: string;
  onSubmitted: () => void;
};

export function DiscoveryView({ scanId, onSubmitted }: DiscoveryViewProps) {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [observation, setObservation] = useState<GuidanceObservation | null>(
    null,
  );
  const [observationUrl, setObservationUrl] = useState("");
  const [actions, setActions] = useState<GuidanceActionDraft[]>([
    {
      actionType: "navigate",
      controlId: "",
      valueReference: "",
      url: "",
      description: "Open the login page",
    },
    {
      actionType: "fill",
      controlId: "",
      valueReference: "username",
      url: "",
      description: "Fill the username",
    },
    {
      actionType: "fill",
      controlId: "",
      valueReference: "password",
      url: "",
      description: "Fill the password",
    },
    {
      actionType: "click",
      controlId: "",
      valueReference: "",
      url: "",
      description: "Submit the login form",
    },
  ]);
  const [protectedResource, setProtectedResource] = useState("");
  const [markerSelector, setMarkerSelector] = useState(
    '[data-testid="account-marker"]',
  );
  const [markerDescription, setMarkerDescription] = useState(
    "Authenticated account marker",
  );
  const [isObserving, setIsObserving] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    let active = true;
    void fetch(`/api/scans/${encodeURIComponent(scanId)}`)
      .then(async (response) => {
        if (!response.ok)
          throw new Error("The scan status could not be loaded.");
        return (await response.json()) as ScanStatus;
      })
      .then((loadedScan) => {
        if (active) {
          setScan(loadedScan);
          setObservationUrl(loadedScan.target_url ?? "");
          setError(null);
        }
      })
      .catch((loadError: unknown) => {
        if (active) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load discovery status.",
          );
        }
      });
    return () => {
      active = false;
    };
  }, [scanId]);

  async function observePage() {
    setIsObserving(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}/guidance/observe`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: observationUrl.trim() }),
        },
      );
      if (!response.ok)
        throw new Error("The target page could not be observed.");
      const observed = (await response.json()) as GuidanceObservation;
      setObservation(observed);
      setActions((currentActions) =>
        currentActions.map((action, index) =>
          index === 0
            ? { ...action, url: observed.url ?? "" }
            : { ...action, controlId: "" },
        ),
      );
    } catch (observeError) {
      setError(
        observeError instanceof Error
          ? observeError.message
          : "Unable to observe the target page.",
      );
    } finally {
      setIsObserving(false);
    }
  }

  function updateAction(
    index: number,
    field: keyof GuidanceActionDraft,
    value: string,
  ) {
    setActions((currentActions) =>
      currentActions.map((action, actionIndex) =>
        actionIndex === index ? { ...action, [field]: value } : action,
      ),
    );
  }

  async function submitGuidance(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);
    try {
      const payload = actions.map((action) => {
        const common = {
          action_type: action.actionType,
          description:
            action.description.trim() || "Guided authentication step",
        };
        if (action.actionType === "navigate") {
          return { ...common, url: action.url.trim() };
        }
        if (action.actionType === "fill") {
          return {
            ...common,
            observed_control_id: action.controlId.trim(),
            value_reference: action.valueReference.trim(),
          };
        }
        return { ...common, observed_control_id: action.controlId.trim() };
      });
      const response = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}/guidance`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            actions: payload,
            ...(protectedResource.trim()
              ? { protected_resource: protectedResource.trim() }
              : {}),
            ...(markerSelector.trim()
              ? { account_marker_selector: markerSelector.trim() }
              : {}),
            ...(markerDescription.trim()
              ? { account_marker_description: markerDescription.trim() }
              : {}),
          }),
        },
      );
      if (!response.ok) {
        const detail = (await response.json().catch(() => null)) as {
          detail?: string;
        } | null;
        throw new Error(detail?.detail ?? "The guided flow was rejected.");
      }
      onSubmitted();
    } catch (submitError) {
      setError(
        submitError instanceof Error
          ? submitError.message
          : "Unable to submit guided flow.",
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  if (!scanId) {
    return (
      <EmptyWorkspace
        code="DISCOVERY_IDLE"
        heading="No discovery session yet"
        message="Start a scan from Setup. If automatic discovery cannot identify the login controls, the guided workspace will open here."
      />
    );
  }

  return (
    <form className="discovery-layout" onSubmit={submitGuidance}>
      <section className="panel discovery-intro-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">A</p>
            <h2>Help us log in</h2>
          </div>
          <span className="status-pill">{scan?.state ?? "loading"}</span>
        </div>
        <p>
          The scan paused because it could not identify the login controls with
          confidence. Find the login page below, choose the username field,
          password field, and sign-in button, then AuthFlowGuard will try those
          steps and verify the account page in separate signed-in and signed-out
          browser sessions. Your Setup credentials are reused automatically.
        </p>
        {scan?.error && <p className="form-error">{scan.error}</p>}
        <div className="field observation-url-field">
          <label htmlFor="observation-url">Login page address</label>
          <input
            id="observation-url"
            onChange={(event) => setObservationUrl(event.target.value)}
            required
            type="url"
            value={observationUrl}
          />
          <small>
            Use the login page here if the scan target was only used to trigger
            this help step.
          </small>
        </div>
        <button
          className="secondary-button"
          disabled={isObserving || scan?.state !== "awaiting_guidance"}
          onClick={() => void observePage()}
          type="button"
        >
          {isObserving ? "Finding fields..." : "Find login fields"}
        </button>
      </section>

      <section className="panel controls-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">B</p>
            <h2>Fields and buttons found on this page</h2>
          </div>
          <span className="selection-count">
            {observation?.controls.length ?? 0} found
          </span>
        </div>
        {observation ? (
          <>
            <p className="panel-help">
              {observation.title || "Untitled page"} · {observation.url}
            </p>
            <div className="observed-controls">
              {observation.controls.map((control) => (
                <div
                  className="observed-control"
                  key={control.observed_control_id}
                >
                  <code>{control.observed_control_id}</code>
                  <span>{controlLabel(control)}</span>
                  <small>{control.visible ? "visible" : "hidden"}</small>
                </div>
              ))}
            </div>
          </>
        ) : (
          <p className="history-empty">
            Find the login fields to choose from the controls on this page.
          </p>
        )}
      </section>

      <section className="panel flow-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">C</p>
            <h2>Choose the sign-in controls</h2>
          </div>
          <span className="required-label">Setup details reused</span>
        </div>
        <p className="panel-help">
          Choose the recognizable controls below. The selected values are saved
          as safe references; live usernames and passwords never enter the flow.
        </p>
        <div className="guided-questions">
          <label className="field">
            <span>Which field is your username or email?</span>
            <select
              aria-label="Username or email field"
              onChange={(event) =>
                updateAction(1, "controlId", event.target.value)
              }
              required
              value={actions[1].controlId}
            >
              <option value="">Choose a field</option>
              {(observation?.controls ?? [])
                .filter(
                  (control) =>
                    control.visible &&
                    control.tag === "input" &&
                    control.type !== "password",
                )
                .map((control) => (
                  <option
                    key={control.observed_control_id}
                    value={control.observed_control_id}
                  >
                    {controlLabel(control)}
                  </option>
                ))}
            </select>
          </label>
          <label className="field">
            <span>Which field is your password?</span>
            <select
              aria-label="Password field"
              onChange={(event) =>
                updateAction(2, "controlId", event.target.value)
              }
              required
              value={actions[2].controlId}
            >
              <option value="">Choose a field</option>
              {(observation?.controls ?? [])
                .filter(
                  (control) =>
                    control.visible &&
                    control.tag === "input" &&
                    control.type === "password",
                )
                .map((control) => (
                  <option
                    key={control.observed_control_id}
                    value={control.observed_control_id}
                  >
                    {controlLabel(control)}
                  </option>
                ))}
            </select>
          </label>
          <label className="field">
            <span>Which button signs you in?</span>
            <select
              aria-label="Sign-in button"
              onChange={(event) =>
                updateAction(3, "controlId", event.target.value)
              }
              required
              value={actions[3].controlId}
            >
              <option value="">Choose a button</option>
              {(observation?.controls ?? [])
                .filter(
                  (control) =>
                    control.visible &&
                    (control.tag === "button" ||
                      (control.tag === "input" &&
                        ["submit", "button"].includes(control.type ?? ""))),
                )
                .map((control) => (
                  <option
                    key={control.observed_control_id}
                    value={control.observed_control_id}
                  >
                    {controlLabel(control)}
                  </option>
                ))}
            </select>
          </label>
        </div>
      </section>

      <section className="panel marker-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">D</p>
            <h2>Protected-resource proof</h2>
          </div>
        </div>
        <p className="panel-help">
          AuthFlowGuard checks that the signed-in account page contains a marker
          that is absent in a fresh anonymous browser session.
        </p>
        <details className="advanced-settings" open>
          <summary>Advanced: change how login is checked</summary>
          <p className="panel-help">
            Change these only when the Setup values do not describe the target.
            A selector is required because a dashboard URL or title alone does
            not prove that authentication succeeded.
          </p>
          <div className="credential-fields">
            <div className="field">
              <label htmlFor="guided-protected-resource">
                Protected resource URL
              </label>
              <input
                id="guided-protected-resource"
                onChange={(event) => setProtectedResource(event.target.value)}
                placeholder="Leave blank to use Setup value"
                type="url"
                value={protectedResource}
              />
            </div>
            <div className="field">
              <label htmlFor="guided-marker-selector">
                Authenticated marker selector
              </label>
              <input
                id="guided-marker-selector"
                onChange={(event) => setMarkerSelector(event.target.value)}
                required
                value={markerSelector}
              />
            </div>
            <div className="field">
              <label htmlFor="guided-marker-description">
                Marker description
              </label>
              <input
                id="guided-marker-description"
                onChange={(event) => setMarkerDescription(event.target.value)}
                required
                value={markerDescription}
              />
            </div>
          </div>
        </details>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <button
          className="primary-button"
          disabled={isSubmitting}
          type="submit"
        >
          {isSubmitting
            ? "Saving guided flow..."
            : "Save and verify guided flow"}
          <span aria-hidden="true">→</span>
        </button>
      </section>
    </form>
  );
}

type TestingViewProps = {
  scanId: string;
  scan: ScanStatus | null;
  scanError: string | null;
  selectedChecks: string[];
  onScanChange: (scan: ScanStatus) => void;
  onOpenDiscovery: () => void;
  onOpenResults: () => void;
};

export function TestingView({
  scanId,
  scan,
  scanError,
  selectedChecks,
  onScanChange,
  onOpenDiscovery,
  onOpenResults,
}: TestingViewProps) {
  const [error, setError] = useState<string | null>(null);
  const [isCancelling, setIsCancelling] = useState(false);

  async function cancelScan() {
    setIsCancelling(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}/cancel`,
        { method: "POST" },
      );
      if (!response.ok) {
        throw new Error("The scan could not be cancelled.");
      }
      onScanChange((await response.json()) as ScanStatus);
    } catch (cancelError) {
      setError(
        cancelError instanceof Error
          ? cancelError.message
          : "Unable to cancel scan.",
      );
    } finally {
      setIsCancelling(false);
    }
  }

  if (!scanId) {
    return (
      <EmptyWorkspace
        code="TESTING_IDLE"
        heading="No scan is running"
        message="Start a scan from Setup to see live execution status here."
      />
    );
  }

  const checksToShow =
    selectedChecks.length > 0
      ? selectedChecks
      : (scan?.results ?? []).map((result) =>
          result.check_id.replaceAll("_", "-"),
        );
  const visibleError = error ?? scanError;
  const stateTone =
    scan?.state === "completed"
      ? "success"
      : scan?.state === "failed"
        ? "danger"
        : scan?.state === "awaiting_guidance"
          ? "warning"
          : "neutral";

  return (
    <div className="testing-layout">
      <section className="panel scan-overview-panel">
        <div className="scan-overview-header">
          <div>
            <p className="eyebrow">Current assessment</p>
            <h2>
              {scan?.target_url ? displayHost(scan.target_url) : "Loading scan"}
            </h2>
          </div>
          <StatusBadge label={formatScanState(scan?.state)} tone={stateTone} />
        </div>
        <dl className="scan-summary" aria-live="polite">
          <div>
            <dt>Scan ID</dt>
            <dd>
              <code title={scanId}>
                {scanId.length > 18
                  ? `${scanId.slice(0, 8)}…${scanId.slice(-6)}`
                  : scanId}
              </code>
            </dd>
          </div>
          <div>
            <dt>Started</dt>
            <dd>{formatDate(scan?.created_at)}</dd>
          </div>
          <div>
            <dt>Evidence</dt>
            <dd>{scan?.evidence_count ?? 0} packages</dd>
          </div>
          <div>
            <dt>Results</dt>
            <dd>{scan?.result_count ?? 0} completed</dd>
          </div>
        </dl>
      </section>

      {visibleError && (
        <p className="form-error" role="alert">
          {visibleError}
        </p>
      )}
      {scan?.state === "awaiting_guidance" && (
        <section className="semantic-callout semantic-callout-warning">
          <strong>Automatic discovery needs your guidance.</strong>
          <p>
            Identify the login controls in Discovery and AuthFlowGuard will
            replay the saved flow in fresh authenticated and anonymous contexts.
          </p>
          <button
            className="secondary-button"
            onClick={onOpenDiscovery}
            type="button"
          >
            Open Discovery
          </button>
        </section>
      )}
      {scan?.state === "failed" && (
        <section className="semantic-callout semantic-callout-danger">
          <strong>The scan stopped before completing.</strong>
          <p>{scan.error ?? "Review the scan setup and try again."}</p>
        </section>
      )}

      <section className="panel status-table-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">01</p>
            <h2>Security check plan</h2>
          </div>
          <span className="selection-count">{checksToShow.length} checks</span>
        </div>
        {checksToShow.length === 0 ? (
          <p className="history-empty">
            Check-level progress is available for scans started in this browser
            session.
          </p>
        ) : (
          <div className="check-status-list">
            {checksToShow.map((checkId) => {
              const definition = checkDefinition(checkId);
              const result = scan?.results.find(
                (item) => item.check_id.replaceAll("_", "-") === definition.id,
              );
              const derived = result
                ? outcomeDefinition(result.outcome)
                : scan?.state === "awaiting_guidance"
                  ? { label: "Waiting for guidance", tone: "warning" }
                  : scan?.state === "running" || scan?.state === "created"
                    ? { label: "Pending", tone: "neutral" }
                    : { label: "Not completed", tone: "neutral" };
              return (
                <div className="check-status-row" key={definition.id}>
                  <code>{definition.code}</code>
                  <div>
                    <strong>{definition.label}</strong>
                    <small>{definition.reference}</small>
                  </div>
                  <StatusBadge label={derived.label} tone={derived.tone} />
                </div>
              );
            })}
          </div>
        )}
      </section>

      <div className="testing-actions">
        {scan?.state === "running" && (
          <button
            className="danger-button"
            disabled={isCancelling}
            onClick={() => void cancelScan()}
            type="button"
          >
            {isCancelling ? "Cancelling..." : "Cancel scan"}
          </button>
        )}
        {scan?.state === "completed" && (
          <button
            className="primary-button"
            onClick={onOpenResults}
            type="button"
          >
            Review results <span aria-hidden="true">→</span>
          </button>
        )}
      </div>
    </div>
  );
}

type ResultsViewProps = {
  scanId: string;
  onScanIdChange: (scanId: string) => void;
};

export function ResultsView({ scanId, onScanIdChange }: ResultsViewProps) {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [pastScans, setPastScans] = useState<ScanStatus[]>([]);
  const [isHistoryLoading, setIsHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [initialScanId] = useState(scanId);

  useEffect(() => {
    let requestIsActive = true;

    async function loadPastScans() {
      try {
        const response = await fetch("/api/scans");
        if (!response.ok) {
          throw new Error("Past scans could not be loaded.");
        }
        const body: unknown = await response.json();
        if (requestIsActive) {
          setPastScans(Array.isArray(body) ? (body as ScanStatus[]) : []);
          setHistoryError(null);
        }
      } catch (loadError) {
        if (requestIsActive) {
          setHistoryError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load past scans.",
          );
        }
      } finally {
        if (requestIsActive) {
          setIsHistoryLoading(false);
        }
      }
    }

    void loadPastScans();
    return () => {
      requestIsActive = false;
    };
  }, []);

  useEffect(() => {
    if (!initialScanId) return;
    let requestIsActive = true;
    async function loadInitialScan() {
      setIsLoading(true);
      try {
        const response = await fetch(
          `/api/scans/${encodeURIComponent(initialScanId)}`,
        );
        if (!response.ok) throw new Error("The scan could not be found.");
        if (requestIsActive) setScan((await response.json()) as ScanStatus);
      } catch (loadError) {
        if (requestIsActive) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load scan.",
          );
        }
      } finally {
        if (requestIsActive) setIsLoading(false);
      }
    }
    void loadInitialScan();
    return () => {
      requestIsActive = false;
    };
  }, [initialScanId]);

  async function loadScan(requestedScanId: string) {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/scans/${encodeURIComponent(requestedScanId)}`,
      );
      if (!response.ok) {
        throw new Error("The scan could not be found.");
      }
      setScan((await response.json()) as ScanStatus);
    } catch (loadError) {
      setScan(null);
      setError(
        loadError instanceof Error ? loadError.message : "Unable to load scan.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  async function loadResults(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const requestedScanId = scanId.trim();
    if (!requestedScanId) {
      setError("Enter a scan ID first.");
      return;
    }
    await loadScan(requestedScanId);
  }

  const outcomeCounts = (scan?.results ?? []).reduce<Record<string, number>>(
    (counts, result) => ({
      ...counts,
      [result.outcome]: (counts[result.outcome] ?? 0) + 1,
    }),
    {},
  );

  return (
    <div className="results-layout">
      <section className="panel results-history-panel">
        <div className="section-heading">
          <div>
            <h2>Past runs</h2>
          </div>
          <span className="selection-count">{pastScans.length} saved</span>
        </div>
        <p className="panel-help">
          Select a saved run or search directly by its Scan ID.
        </p>
        <form className="result-loader" onSubmit={loadResults}>
          <label htmlFor="scan-id">Scan ID</label>
          <input
            id="scan-id"
            onChange={(event) => onScanIdChange(event.target.value)}
            placeholder="Paste a scan ID"
            value={scanId}
          />
          <button
            className="secondary-button"
            disabled={isLoading}
            type="submit"
          >
            {isLoading ? "Loading..." : "Load results"}
          </button>
        </form>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        {historyError && <p className="form-error">{historyError}</p>}
        {isHistoryLoading ? (
          <p className="history-empty">Loading past runs...</p>
        ) : pastScans.length === 0 ? (
          <p className="history-empty">No saved scans yet.</p>
        ) : (
          <div className="scan-history">
            {pastScans.map((pastScan) => (
              <button
                className={`history-row ${scan?.scan_id === pastScan.scan_id ? "history-row-selected" : ""}`}
                aria-pressed={scan?.scan_id === pastScan.scan_id}
                key={pastScan.scan_id}
                onClick={() => {
                  onScanIdChange(pastScan.scan_id);
                  void loadScan(pastScan.scan_id);
                }}
                type="button"
              >
                <span>
                  <strong>{pastScan.scan_id}</strong>
                  <small>{pastScan.target_url ?? "Target unavailable"}</small>
                </span>
                <span className="history-meta">
                  <StatusBadge label={formatScanState(pastScan.state)} />
                  <small>{pastScan.result_count} result(s)</small>
                </span>
              </button>
            ))}
          </div>
        )}
      </section>

      {scan === null ? (
        <section className="panel empty-workspace">
          <div className="empty-code">NO_RESULTS</div>
          <div>
            <h2>Evidence will appear here</h2>
            <p>
              Select a past run or enter a Scan ID to review findings,
              limitations, and offline report downloads.
            </p>
          </div>
        </section>
      ) : (
        <section className="panel results-panel">
          <div className="results-header">
            <div>
              <p className="eyebrow">Assessment evidence</p>
              <h2>Scan results</h2>
              <p className="results-target">
                {scan.target_url ?? "Target unavailable"}
              </p>
            </div>
            <StatusBadge
              label={formatScanState(scan.state)}
              tone={
                scan.state === "completed"
                  ? "success"
                  : scan.state === "failed"
                    ? "danger"
                    : "neutral"
              }
            />
          </div>
          <dl className="scan-summary results-summary">
            <div>
              <dt>Evidence</dt>
              <dd>{scan.evidence_count} packages</dd>
            </div>
            <div>
              <dt>Findings</dt>
              <dd>{outcomeCounts.finding_confirmed ?? 0}</dd>
            </div>
            <div>
              <dt>No issue observed</dt>
              <dd>{outcomeCounts.no_issue_observed ?? 0}</dd>
            </div>
            <div>
              <dt>Inconclusive</dt>
              <dd>{outcomeCounts.inconclusive ?? 0}</dd>
            </div>
          </dl>
          <p className="result-context">
            Authentication profile:{" "}
            <strong>{scan.profile_source ?? "Not verified"}</strong> · Started{" "}
            {formatDate(scan.created_at)}
          </p>
          <div className="result-actions">
            <a
              className="secondary-button"
              href={`/api/scans/${encodeURIComponent(scan.scan_id)}/report/json`}
            >
              Download JSON
            </a>
            <a
              className="secondary-button"
              href={`/api/scans/${encodeURIComponent(scan.scan_id)}/report/html`}
            >
              Open HTML report
            </a>
          </div>
          {scan.results.length === 0 ? (
            <p>No completed results are available yet.</p>
          ) : (
            <div className="result-list">
              {scan.results.map((result, index) => (
                <article
                  className="result-card"
                  key={result.result_id ?? `${result.check_id}-${index}`}
                >
                  {(() => {
                    const check = checkDefinition(result.check_id);
                    const outcome = outcomeDefinition(result.outcome);
                    return (
                      <>
                        <header className="result-card-header">
                          <div>
                            <p className="eyebrow">
                              {check.code} · {result.owasp_reference}
                            </p>
                            <h3>{check.label}</h3>
                          </div>
                          <StatusBadge
                            label={outcome.label}
                            tone={outcome.tone}
                          />
                        </header>
                        <p className="result-explanation">
                          {result.explanation}
                        </p>
                        {(result.coverage_limitations?.length ?? 0) > 0 && (
                          <div className="limitations-block">
                            <strong>Coverage limitations</strong>
                            <ul>
                              {result.coverage_limitations!.map(
                                (limitation) => (
                                  <li key={limitation}>{limitation}</li>
                                ),
                              )}
                            </ul>
                          </div>
                        )}
                        {(result.evidence_references?.length ?? 0) > 0 && (
                          <details className="evidence-details">
                            <summary>
                              {result.evidence_references!.length} evidence
                              reference(s)
                            </summary>
                            <ul>
                              {result.evidence_references!.map((reference) => (
                                <li key={reference}>
                                  <code>{reference}</code>
                                </li>
                              ))}
                            </ul>
                          </details>
                        )}
                        {(result.analyser_version || result.created_at) && (
                          <p className="result-metadata">
                            {result.analyser_version && (
                              <>Analyser {result.analyser_version}</>
                            )}
                            {result.analyser_version &&
                              result.created_at &&
                              " · "}
                            {result.created_at && formatDate(result.created_at)}
                          </p>
                        )}
                      </>
                    );
                  })()}
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

type EmptyWorkspaceProps = {
  code: string;
  heading: string;
  message: string;
};

export function EmptyWorkspace({
  code,
  heading,
  message,
}: EmptyWorkspaceProps) {
  return (
    <section className="panel empty-workspace">
      <div className="empty-code">{code}</div>
      <div>
        <h2>{heading}</h2>
        <p>{message}</p>
      </div>
    </section>
  );
}
