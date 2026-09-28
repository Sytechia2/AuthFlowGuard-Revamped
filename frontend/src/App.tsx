import { FormEvent, useEffect, useState } from "react";

type ViewId = "setup" | "discovery" | "testing" | "results";
type ConnectionStatus = "checking" | "connected" | "offline";

type WorkflowView = {
  id: ViewId;
  label: string;
  description: string;
};

type SecurityCheck = {
  id: string;
  label: string;
  reference: string;
};

type ScanResult = {
  result_id?: string;
  check_id: string;
  outcome: string;
  owasp_reference: string;
  explanation: string;
};

type SystemCapabilities = {
  bedrock_configured: boolean;
  model_id: string;
  model_name: string;
  pricing_configured: boolean;
  note: string;
  default_limits: {
    maximum_ai_decisions: number;
    maximum_active_seconds: number;
    maximum_inference_cost_usd: number;
  };
  server_max_limits: {
    maximum_ai_decisions: number;
    maximum_active_seconds: number;
    maximum_inference_cost_usd: number;
  };
};

type DiscoveryProvenance = {
  requested_mode: "bedrock" | "rules";
  actual_engine: string | null;
  usage_source: string;
  reused_profile: boolean;
  guidance_used: boolean;
  model_id: string | null;
};

type UsageSummary = {
  input_tokens?: number;
  output_tokens?: number;
  settled_cost_usd?: string;
  outstanding_reserved_cost_usd?: string;
  limit_usd?: string;
  uncertain_requests?: number;
  estimator_violations?: number;
  accounting_error?: boolean;
};

type ScanStatus = {
  scan_id: string;
  state: string;
  target_url?: string;
  created_at?: string;
  event_count: number;
  evidence_count: number;
  result_count: number;
  results: ScanResult[];
  error?: string | null;
  error_code?: string | null;
  profile_source?: "automatic" | "guided" | null;
  guidance_required?: boolean;
  phase?: string;
  decision_count?: number;
  model_request_count?: number;
  total_input_tokens?: number;
  total_output_tokens?: number;
  estimated_cost_usd?: number;
  unresolved_reservations_usd?: number;
  stop_reason?: string | null;
  provenance?: DiscoveryProvenance | null;
  discovery_mode?: "bedrock" | "rules";
  reuse_saved_profile?: boolean;
  cancel_requested?: boolean;
  state_changed_at?: string;
  started_at?: string | null;
  finished_at?: string | null;
  partial_results_available?: boolean;
  reanalysis_available?: boolean;
  report_available?: boolean;
  worker_active?: boolean;
  worker_generation?: number;
  worker_cleanup?: "graceful" | "forced" | "crashed" | null;
  worker_cleanup_seconds?: number | null;
  usage?: UsageSummary;
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
  text?: string | null;
  value_present: boolean | null;
  visible: boolean;
};

type SuggestionSource = "rules" | "ai";

// Controls the backend suggests for each sign-in question. The backend has
// already checked that each one fits its role; the developer still confirms.
type SuggestedControls = {
  username: string | null;
  password: string | null;
  submit: string | null;
  source: SuggestionSource | null;
  status?: string;
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
  suggested_controls?: SuggestedControls | null;
};

function controlLabel(control: SafeControl): string {
  const label =
    control.aria_label ??
    control.name ??
    control.id ??
    control.placeholder ??
    control.text ??
    (control.type === "password" ? "Password field" : "Unnamed control");
  const kind = control.type ? ` (${control.type})` : "";
  return `${label}${kind}`;
}

function isUsernameOption(control: SafeControl): boolean {
  return (
    control.visible && control.tag === "input" && control.type !== "password"
  );
}

function isPasswordOption(control: SafeControl): boolean {
  return (
    control.visible && control.tag === "input" && control.type === "password"
  );
}

function isSubmitOption(control: SafeControl): boolean {
  return (
    control.visible &&
    (control.tag === "button" ||
      (control.tag === "input" &&
        ["submit", "button", "image"].includes(control.type ?? "")))
  );
}

const suggestionNotes: Record<SuggestionSource, string> = {
  ai: "Suggested by AI — check before continuing.",
  rules: "Detected from the page's labels — check before continuing.",
};

// The step index of each sign-in question in the guided flow.
const suggestedSteps: {
  step: number;
  role: "username" | "password" | "submit";
  isOption: (control: SafeControl) => boolean;
}[] = [
  { step: 1, role: "username", isOption: isUsernameOption },
  { step: 2, role: "password", isOption: isPasswordOption },
  { step: 3, role: "submit", isOption: isSubmitOption },
];

// Pre-select only a suggestion that is one of the dropdown's own options.
function suggestedControlIds(
  observation: GuidanceObservation,
): Map<number, string> {
  const suggested = observation.suggested_controls;
  const chosen = new Map<number, string>();
  if (!suggested?.source) return chosen;
  for (const { step, role, isOption } of suggestedSteps) {
    const controlId = suggested[role];
    const control = observation.controls.find(
      (candidate) => candidate.observed_control_id === controlId,
    );
    if (control && isOption(control)) {
      chosen.set(step, control.observed_control_id);
    }
  }
  return chosen;
}

const workflowViews: WorkflowView[] = [
  {
    id: "setup",
    label: "Setup",
    description: "Set target and scope",
  },
  {
    id: "discovery",
    label: "Discovery",
    description: "Verify login flows",
  },
  {
    id: "testing",
    label: "Testing",
    description: "Run security checks",
  },
  {
    id: "results",
    label: "Results",
    description: "Review evidence",
  },
];

const securityChecks: SecurityCheck[] = [
  {
    id: "login-enumeration",
    label: "Login account enumeration",
    reference: "WSTG-IDNT-04",
  },
  {
    id: "registration-enumeration",
    label: "Registration account enumeration",
    reference: "WSTG-IDNT-04",
  },
  {
    id: "reset-request-enumeration",
    label: "Reset-request account enumeration",
    reference: "WSTG-IDNT-04",
  },
  {
    id: "login-throttling",
    label: "Login throttling and lockout",
    reference: "WSTG-ATHN-03",
  },
  {
    id: "session-fixation",
    label: "Session fixation",
    reference: "WSTG-SESS-03",
  },
  {
    id: "logout-invalidation",
    label: "Logout invalidation",
    reference: "WSTG-SESS-06",
  },
];

function App() {
  const [activeView, setActiveView] = useState<ViewId>("setup");
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("checking");
  const [scanId, setScanId] = useState("");

  useEffect(() => {
    let requestIsActive = true;
    async function checkBackend() {
      try {
        const response = await fetch("/api/health");
        const body = (await response.json()) as { status?: string };
        if (requestIsActive) {
          setConnectionStatus(
            response.ok && body.status === "ok" ? "connected" : "offline",
          );
        }
      } catch {
        if (requestIsActive) {
          setConnectionStatus("offline");
        }
      }
    }
    void checkBackend();
    return () => {
      requestIsActive = false;
    };
  }, []);

  const currentView = workflowViews.find((view) => view.id === activeView)!;

  return (
    <div className="app-shell">
      <Sidebar
        activeView={activeView}
        connectionStatus={connectionStatus}
        onSelectView={setActiveView}
      />
      <main className="workspace">
        <header className="workspace-header">
          <div>
            <p className="eyebrow">Authentication assessment</p>
            <h1>{currentView.label}</h1>
            <p>{currentView.description}</p>
          </div>
          <div className="local-badge">Local execution</div>
        </header>

        {activeView === "setup" && (
          <SetupView
            onStarted={(startedScanId) => {
              setScanId(startedScanId);
              setActiveView("testing");
            }}
          />
        )}
        {activeView === "discovery" && (
          <DiscoveryView
            scanId={scanId}
            onSubmitted={() => setActiveView("testing")}
          />
        )}
        {activeView === "testing" && (
          <TestingView
            scanId={scanId}
            onOpenDiscovery={() => setActiveView("discovery")}
            onOpenResults={() => setActiveView("results")}
          />
        )}
        {activeView === "results" && (
          <ResultsView scanId={scanId} onScanIdChange={setScanId} />
        )}
      </main>
    </div>
  );
}

type SidebarProps = {
  activeView: ViewId;
  connectionStatus: ConnectionStatus;
  onSelectView: (view: ViewId) => void;
};

function Sidebar({ activeView, connectionStatus, onSelectView }: SidebarProps) {
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
          <span>AI security workspace</span>
        </div>
      </div>

      <nav aria-label="Assessment workflow">
        {workflowViews.map((view) => (
          <button
            className={`nav-item ${activeView === view.id ? "nav-item-active" : ""}`}
            key={view.id}
            onClick={() => onSelectView(view.id)}
            type="button"
          >
            <span>
              <strong>{view.label}</strong>
              <small>{view.description}</small>
            </span>
          </button>
        ))}
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

type SetupViewProps = {
  onStarted: (scanId: string) => void;
};

function SetupView({ onStarted }: SetupViewProps) {
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
  const [capabilities, setCapabilities] = useState<SystemCapabilities | null>(
    null,
  );
  const [discoveryMode, setDiscoveryMode] = useState<"bedrock" | "rules">(
    "bedrock",
  );
  const [reuseSavedProfile, setReuseSavedProfile] = useState<boolean>(false);
  const [maxDecisions, setMaxDecisions] = useState<number>(40);
  const [maxSeconds, setMaxSeconds] = useState<number>(900);
  const [maxCostUsd, setMaxCostUsd] = useState<number>(0.25);
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadCapabilities() {
      try {
        const response = await fetch("/api/capabilities");
        if (response.ok) {
          const data = (await response.json()) as SystemCapabilities;
          setCapabilities(data);
          if (!data.bedrock_configured) {
            setDiscoveryMode("rules");
            setReuseSavedProfile(true);
          } else {
            setDiscoveryMode("bedrock");
            setReuseSavedProfile(false);
          }
        }
      } catch {
        setDiscoveryMode("rules");
        setReuseSavedProfile(true);
      }
    }
    void loadCapabilities();
  }, []);

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
          discovery_mode: discoveryMode,
          reuse_saved_profile: reuseSavedProfile,
          limits: {
            maximum_ai_decisions: maxDecisions,
            maximum_active_seconds: maxSeconds,
            maximum_inference_cost_usd: maxCostUsd,
          },
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
      onStarted(created.scan_id);
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

      <section className="panel discovery-engine-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">B</p>
            <h2>Discovery engine</h2>
          </div>
          <span className="required-label">Required</span>
        </div>

        <div
          className="discovery-modes"
          role="radiogroup"
          aria-label="Discovery engine"
        >
          <label
            className={`mode-card ${discoveryMode === "bedrock" ? "mode-card-selected" : ""}`}
          >
            <input
              type="radio"
              name="discovery-mode"
              value="bedrock"
              checked={discoveryMode === "bedrock"}
              onChange={() => {
                setDiscoveryMode("bedrock");
                setReuseSavedProfile(false);
              }}
            />
            <div className="mode-card-body">
              <strong>Bedrock AI discovery</strong>
              <small>
                Autonomous browser exploration using Amazon Bedrock Claude model
                with bounded execution.
              </small>
            </div>
          </label>

          <label
            className={`mode-card ${discoveryMode === "rules" ? "mode-card-selected" : ""}`}
          >
            <input
              type="radio"
              name="discovery-mode"
              value="rules"
              checked={discoveryMode === "rules"}
              onChange={() => {
                setDiscoveryMode("rules");
                setReuseSavedProfile(true);
              }}
            />
            <div className="mode-card-body">
              <strong>Deterministic rules</strong>
              <small>
                Heuristic discovery following standard authentication forms with
                manual guidance fallback.
              </small>
            </div>
          </label>
        </div>

        {capabilities && (
          <div
            className={`capability-banner ${
              capabilities.bedrock_configured
                ? "capability-banner-success"
                : "capability-banner-warning"
            }`}
            role={capabilities.bedrock_configured ? undefined : "alert"}
          >
            <span aria-hidden="true">
              {capabilities.bedrock_configured ? "✓" : "!"}
            </span>
            <div>
              <strong>
                {capabilities.bedrock_configured
                  ? `Bedrock online: ${capabilities.model_name || capabilities.model_id}`
                  : "Bedrock not configured on backend"}
              </strong>
              <p>
                {capabilities.bedrock_configured
                  ? `Model: ${capabilities.model_id}. Pricing configured. AWS credentials validated.`
                  : capabilities.note ||
                    "AWS Bedrock credentials are not configured on the backend server. Choose deterministic rules or configure credentials."}
              </p>
            </div>
          </div>
        )}

        <div className="profile-reuse-setting">
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={reuseSavedProfile}
              onChange={(e) => setReuseSavedProfile(e.target.checked)}
            />
            <span className="checkbox-copy">
              <strong>Reuse verified authentication profile</strong>
              <small>
                Skip exploration and reuse the verified profile if already known
                for this target.
              </small>
            </span>
          </label>
        </div>

        <details
          className="advanced-settings"
          open={discoveryMode === "bedrock"}
        >
          <summary>Bounded execution limits</summary>
          <p className="panel-help">
            Exploration automatically halts when any limit is reached. Model
            requests are priced and budgeted.
          </p>
          <div className="credential-fields">
            <div className="field">
              <label htmlFor="max-decisions">Maximum decisions</label>
              <input
                id="max-decisions"
                type="number"
                min={1}
                max={
                  capabilities?.server_max_limits?.maximum_ai_decisions ?? 100
                }
                value={maxDecisions}
                onChange={(e) =>
                  setMaxDecisions(Math.max(1, Number(e.target.value)))
                }
              />
              <small>AI navigation action cap.</small>
            </div>
            <div className="field">
              <label htmlFor="max-seconds">Active time limit (seconds)</label>
              <input
                id="max-seconds"
                type="number"
                min={10}
                max={
                  capabilities?.server_max_limits?.maximum_active_seconds ??
                  1800
                }
                value={maxSeconds}
                onChange={(e) =>
                  setMaxSeconds(Math.max(10, Number(e.target.value)))
                }
              />
              <small>Wall-clock runtime limit.</small>
            </div>
            <div className="field">
              <label htmlFor="max-cost">Max inference budget (USD)</label>
              <input
                id="max-cost"
                type="number"
                step="0.01"
                min={0.01}
                max={
                  capabilities?.server_max_limits?.maximum_inference_cost_usd ??
                  10.0
                }
                value={maxCostUsd}
                onChange={(e) =>
                  setMaxCostUsd(Math.max(0.01, Number(e.target.value)))
                }
              />
              <small>Budget limit for model spend.</small>
            </div>
          </div>
        </details>
      </section>

      <section className="panel checks-panel">
        <div className="section-heading">
          <div>
            <p className="section-number">C</p>
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
            <p className="section-number">D</p>
            <h2>Runtime login data</h2>
          </div>
          <span className="required-label">Local only</span>
        </div>

        <p className="panel-help">
          These values are used for this scan only. They are sent to the local
          backend and discarded after execution.
        </p>
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
          <p className="eyebrow">Current foundation</p>
          <h2>Ready to run locally</h2>
          <p>
            The first complete slice discovers a conventional login, verifies
            access to the protected resource, and checks login account
            enumeration with isolated browser contexts.
          </p>
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

type CancelScanButtonProps = {
  scanId: string;
  scan: ScanStatus | null;
  onUpdated: (scan: ScanStatus) => void;
  onError: (message: string | null) => void;
};

function CancelScanButton({
  scanId,
  scan,
  onUpdated,
  onError,
}: CancelScanButtonProps) {
  const [isCancelling, setIsCancelling] = useState(false);
  const canCancel =
    scan?.state === "running" || scan?.state === "awaiting_guidance";
  const cancellationPending = isCancelling || scan?.cancel_requested === true;

  if (!canCancel) return null;

  async function cancelScan() {
    setIsCancelling(true);
    onError(null);
    try {
      const response = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}/cancel`,
        { method: "POST" },
      );
      if (!response.ok) {
        throw new Error("The scan could not be cancelled.");
      }
      onUpdated((await response.json()) as ScanStatus);
    } catch (cancelError) {
      onError(
        cancelError instanceof Error
          ? cancelError.message
          : "Unable to cancel scan.",
      );
    } finally {
      setIsCancelling(false);
    }
  }

  return (
    <button
      className="secondary-button cancel-button"
      disabled={cancellationPending}
      onClick={() => void cancelScan()}
      type="button"
    >
      {cancellationPending ? "Cancelling..." : "Cancel scan"}
    </button>
  );
}

function DiscoveryView({ scanId, onSubmitted }: DiscoveryViewProps) {
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
  const [suggestionSource, setSuggestionSource] =
    useState<SuggestionSource | null>(null);

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
    const requestedUrl = observationUrl.trim();
    setIsObserving(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}/guidance/observe`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: requestedUrl }),
        },
      );
      if (!response.ok)
        throw new Error("The target page could not be observed.");
      const observed = (await response.json()) as GuidanceObservation;
      setObservation(observed);
      // Navigate to the address the user typed: the observed URL can lose a
      // hash route such as #/login and replay would open the app's home page.
      const navigateUrl = requestedUrl || (observed.url ?? "");
      // Pre-select the suggested controls. The developer can change any of
      // them and must still submit the flow themselves.
      const suggestedIds = suggestedControlIds(observed);
      setActions((currentActions) =>
        currentActions.map((action, index) =>
          index === 0
            ? { ...action, url: navigateUrl }
            : { ...action, controlId: suggestedIds.get(index) ?? "" },
        ),
      );
      setSuggestionSource(
        suggestedIds.size > 0
          ? (observed.suggested_controls?.source ?? null)
          : null,
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
        <div className="button-row">
          <button
            className="secondary-button"
            disabled={
              isObserving ||
              scan?.state !== "awaiting_guidance" ||
              scan.cancel_requested === true
            }
            onClick={() => void observePage()}
            type="button"
          >
            {isObserving ? "Finding fields..." : "Find login fields"}
          </button>
          <CancelScanButton
            onError={setError}
            onUpdated={setScan}
            scan={scan}
            scanId={scanId}
          />
        </div>
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
        {suggestionSource && (
          <p className="suggestion-note" role="status">
            {suggestionNotes[suggestionSource]}
          </p>
        )}
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
                .filter(isUsernameOption)
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
                .filter(isPasswordOption)
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
                .filter(isSubmitOption)
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
          disabled={
            isSubmitting ||
            scan?.state !== "awaiting_guidance" ||
            scan.cancel_requested === true
          }
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
  onOpenDiscovery: () => void;
  onOpenResults: () => void;
};

function TestingView({
  scanId,
  onOpenDiscovery,
  onOpenResults,
}: TestingViewProps) {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) {
      return;
    }

    let requestIsActive = true;
    async function loadScan() {
      try {
        const response = await fetch(
          `/api/scans/${encodeURIComponent(scanId)}`,
        );
        if (!response.ok) {
          throw new Error("The scan status could not be loaded.");
        }
        if (requestIsActive) {
          setScan((await response.json()) as ScanStatus);
          setError(null);
        }
      } catch (loadError) {
        if (requestIsActive) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load scan status.",
          );
        }
      }
    }

    void loadScan();
    const interval = window.setInterval(() => void loadScan(), 1500);
    return () => {
      requestIsActive = false;
      window.clearInterval(interval);
    };
  }, [scanId]);

  if (!scanId) {
    return (
      <EmptyWorkspace
        code="TESTING_IDLE"
        heading="No scan is running"
        message="Start a scan from Setup to see live execution status here."
      />
    );
  }

  return (
    <section className="panel status-table-panel">
      <div className="section-heading">
        <div>
          <p className="section-number">C</p>
          <h2>Check status</h2>
        </div>
        <div className="status-badges">
          {scan?.phase && (
            <span className="phase-pill">
              Phase: {scan.phase.replaceAll("_", " ")}
            </span>
          )}
          {scan?.provenance?.actual_engine && (
            <span className="engine-pill">
              Engine: {scan.provenance.actual_engine}
            </span>
          )}
          <span className="status-pill">{scan?.state ?? "loading"}</span>
        </div>
      </div>
      <p>
        Scan ID: <code>{scanId}</code>
      </p>
      <div className="scan-metrics" aria-live="polite">
        <span>{scan?.event_count ?? 0} events</span>
        <span>{scan?.evidence_count ?? 0} evidence packages</span>
        <span>{scan?.result_count ?? 0} results</span>
        {scan?.profile_source && <span>discovery: {scan.profile_source}</span>}
        {scan?.usage && !scan.usage.accounting_error && (
          <span>
            AI cost: ${scan.usage.settled_cost_usd ?? "0.00000000"}
            {scan.usage.outstanding_reserved_cost_usd !== "0.00000000" &&
              ` + $${scan.usage.outstanding_reserved_cost_usd} reserved`}
          </span>
        )}
      </div>

      {(scan?.discovery_mode === "bedrock" ||
        (scan?.decision_count ?? 0) > 0 ||
        scan?.provenance?.actual_engine === "bedrock") && (
        <div className="ai-metrics-panel">
          <div className="ai-metrics-heading">
            <strong>AI Exploration Metrics</strong>
            {scan?.stop_reason && (
              <span className="stop-reason-pill">Stop: {scan.stop_reason}</span>
            )}
          </div>
          <div className="ai-metrics-grid">
            <div className="ai-metric-card">
              <span className="ai-metric-value">
                {scan?.decision_count ?? 0}
              </span>
              <span className="ai-metric-label">Decisions</span>
            </div>
            <div className="ai-metric-card">
              <span className="ai-metric-value">
                {scan?.model_request_count ?? 0}
              </span>
              <span className="ai-metric-label">Model Calls</span>
            </div>
            <div className="ai-metric-card">
              <span className="ai-metric-value">
                {(
                  (scan?.total_input_tokens ?? 0) +
                  (scan?.total_output_tokens ?? 0)
                ).toLocaleString()}
              </span>
              <span className="ai-metric-label">
                Tokens ({scan?.total_input_tokens ?? 0} in /{" "}
                {scan?.total_output_tokens ?? 0} out)
              </span>
            </div>
            <div className="ai-metric-card">
              <span className="ai-metric-value">
                ${(scan?.estimated_cost_usd ?? 0).toFixed(4)}
              </span>
              <span className="ai-metric-label">Observed Cost</span>
            </div>
            <div className="ai-metric-card">
              <span className="ai-metric-value">
                ${(scan?.unresolved_reservations_usd ?? 0).toFixed(4)}
              </span>
              <span className="ai-metric-label">Pending Resv.</span>
            </div>
          </div>
        </div>
      )}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <CancelScanButton
        onError={setError}
        onUpdated={setScan}
        scan={scan}
        scanId={scanId}
      />
      {scan?.state === "awaiting_guidance" && (
        <div className="guidance-callout">
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
        </div>
      )}
      {scan?.state === "completed" && (
        <button
          className="secondary-button"
          onClick={onOpenResults}
          type="button"
        >
          Open results
        </button>
      )}
      {scan?.state === "failed" && (
        <p className="form-error">The scan stopped before completing.</p>
      )}
    </section>
  );
}

type ResultsViewProps = {
  scanId: string;
  onScanIdChange: (scanId: string) => void;
};

function ResultsView({ scanId, onScanIdChange }: ResultsViewProps) {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [pastScans, setPastScans] = useState<ScanStatus[]>([]);
  const [isHistoryLoading, setIsHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);

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
                className="history-row"
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
                  <em className="status-pill">{pastScan.state}</em>
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
          <div className="section-heading">
            <div>
              <h2>Scan results</h2>
            </div>
            <span className="status-pill">{scan.state}</span>
          </div>
          <p>
            {scan.evidence_count} evidence package(s), {scan.event_count}{" "}
            event(s), and {scan.result_count} result(s) saved.
          </p>
          <p>
            Authentication profile: {scan.profile_source ?? "not verified yet"}
          </p>
          {scan.usage && !scan.usage.accounting_error && (
            <p>
              AI usage: {scan.usage.input_tokens ?? 0} input /{" "}
              {scan.usage.output_tokens ?? 0} output tokens; estimated cost $
              {scan.usage.settled_cost_usd ?? "0.00000000"} of $
              {scan.usage.limit_usd ?? "unknown"}
              {(scan.usage.uncertain_requests ?? 0) > 0 &&
                `; ${scan.usage.uncertain_requests} uncertain request(s) remain reserved`}
              .
            </p>
          )}
          <div className="result-actions">
            <a
              href={`/api/scans/${encodeURIComponent(scan.scan_id)}/report/json`}
            >
              Download JSON
            </a>
            <a
              href={`/api/scans/${encodeURIComponent(scan.scan_id)}/report/html`}
            >
              Open HTML report
            </a>
          </div>

          <div className="provenance-panel">
            <div className="section-heading">
              <div>
                <h3>Discovery provenance & assurance</h3>
              </div>
              <span className="engine-pill">
                Engine:{" "}
                {scan.provenance?.actual_engine ??
                  scan.discovery_mode ??
                  "rules"}
              </span>
            </div>
            <div className="provenance-grid">
              <div className="provenance-item">
                <span className="provenance-label">Requested mode</span>
                <strong className="provenance-value">
                  {scan.provenance?.requested_mode ??
                    scan.discovery_mode ??
                    "rules"}
                </strong>
              </div>
              <div className="provenance-item">
                <span className="provenance-label">Actual engine</span>
                <strong className="provenance-value">
                  {scan.provenance?.actual_engine ?? "rules"}
                </strong>
              </div>
              <div className="provenance-item">
                <span className="provenance-label">Profile reused</span>
                <strong className="provenance-value">
                  {scan.provenance?.reused_profile ? "Yes" : "No"}
                </strong>
              </div>
              <div className="provenance-item">
                <span className="provenance-label">Usage source</span>
                <strong className="provenance-value">
                  {scan.provenance?.usage_source ?? "none"}
                </strong>
              </div>
              <div className="provenance-item">
                <span className="provenance-label">Model ID</span>
                <strong className="provenance-value">
                  {scan.provenance?.model_id ?? "N/A"}
                </strong>
              </div>
              <div className="provenance-item">
                <span className="provenance-label">Decisions / Requests</span>
                <strong className="provenance-value">
                  {scan.decision_count ?? 0} decisions /{" "}
                  {scan.model_request_count ?? 0} requests
                </strong>
              </div>
              <div className="provenance-item">
                <span className="provenance-label">Tokens</span>
                <strong className="provenance-value">
                  {(
                    (scan.total_input_tokens ?? 0) +
                    (scan.total_output_tokens ?? 0)
                  ).toLocaleString()}{" "}
                  total ({scan.total_input_tokens ?? 0} in /{" "}
                  {scan.total_output_tokens ?? 0} out)
                </strong>
              </div>
              <div className="provenance-item">
                <span className="provenance-label">Inference spend</span>
                <strong className="provenance-value">
                  ${(scan.estimated_cost_usd ?? 0).toFixed(4)} USD
                </strong>
              </div>
            </div>
            <div className="security-notice">
              <span aria-hidden="true">🔒</span>
              <p>
                <strong>Offline assurance:</strong> All security checks, test
                execution, and evidence reporting are executed 100%
                deterministically and offline. Runtime secrets and
                authentication credentials were strictly scrubbed and never
                transmitted to external model providers.
              </p>
            </div>
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
                  <p className="eyebrow">{result.owasp_reference}</p>
                  <h3>
                    {result.check_id === "registration_enumeration" &&
                      "CHK-002 "}
                    {result.check_id === "reset_request_enumeration" &&
                      "CHK-003 "}
                    {result.check_id === "login_throttling" && "CHK-004 "}
                    {result.check_id === "session_fixation" && "CHK-005 "}
                    {result.check_id === "logout_invalidation" && "CHK-006 "}
                    {result.check_id}
                  </h3>
                  <strong>{result.outcome}</strong>
                  <p>{result.explanation}</p>
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

function EmptyWorkspace({ code, heading, message }: EmptyWorkspaceProps) {
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

export default App;
