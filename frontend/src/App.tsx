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
  check_id: string;
  outcome: string;
  owasp_reference: string;
  explanation: string;
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
};

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
    label: "Login account enumeration",
    reference: "WSTG-IDNT-04",
  },
  {
    id: "registration-enumeration",
    label: "Registration account enumeration",
    reference: "WSTG-IDNT-04",
  },
  {
    id: "reset-enumeration",
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
        {activeView === "discovery" && <DiscoveryView />}
        {activeView === "testing" && (
          <TestingView
            scanId={scanId}
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
        throw new Error("The backend rejected the scan setup.");
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
              nonexistent_username: nonexistentUsername,
              failure_password: failurePassword,
            },
            username_reference: "username",
            password_reference: "password",
            nonexistent_identifier_reference: "nonexistent_username",
            failure_password_reference: "failure_password",
            protected_resource: protectedResource.trim(),
            account_marker_selector: accountMarkerSelector.trim(),
            account_marker_description: accountMarkerDescription.trim(),
          }),
        },
      );
      if (!startResponse.ok) {
        throw new Error("The backend could not start the scan.");
      }
      setPassword("");
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
            <label htmlFor="nonexistent-username">
              Nonexistent account username
            </label>
            <input
              id="nonexistent-username"
              onChange={(event) => setNonexistentUsername(event.target.value)}
              required
              value={nonexistentUsername}
            />
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

function DiscoveryView() {
  return (
    <EmptyWorkspace
      code="DISCOVERY_IDLE"
      heading="No discovery session yet"
      message="Complete the target setup to begin observing and verifying authentication controls."
    />
  );
}

type TestingViewProps = {
  scanId: string;
  onOpenResults: () => void;
};

function TestingView({ scanId, onOpenResults }: TestingViewProps) {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isCancelling, setIsCancelling] = useState(false);

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
      setScan((await response.json()) as ScanStatus);
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

  return (
    <section className="panel status-table-panel">
      <div className="section-heading">
        <div>
          <p className="section-number">C</p>
          <h2>Check status</h2>
        </div>
        <span className="status-pill">{scan?.state ?? "loading"}</span>
      </div>
      <p>
        Scan ID: <code>{scanId}</code>
      </p>
      <div className="scan-metrics" aria-live="polite">
        <span>{scan?.event_count ?? 0} events</span>
        <span>{scan?.evidence_count ?? 0} evidence packages</span>
        <span>{scan?.result_count ?? 0} results</span>
      </div>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {scan?.state === "running" && (
        <button
          className="secondary-button"
          disabled={isCancelling}
          onClick={() => void cancelScan()}
          type="button"
        >
          {isCancelling ? "Cancelling..." : "Cancel scan"}
        </button>
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
          {scan.results.length === 0 ? (
            <p>No completed results are available yet.</p>
          ) : (
            <div className="result-list">
              {scan.results.map((result) => (
                <article
                  className="result-card"
                  key={`${result.check_id}-${result.owasp_reference}`}
                >
                  <p className="eyebrow">{result.owasp_reference}</p>
                  <h3>{result.check_id}</h3>
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
