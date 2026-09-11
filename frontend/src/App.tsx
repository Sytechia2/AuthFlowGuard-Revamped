import { FormEvent, useEffect, useState } from "react";

type ViewId = "setup" | "discovery" | "testing" | "results";
type ConnectionStatus = "checking" | "connected" | "offline";

type WorkflowView = {
  id: ViewId;
  step: string;
  label: string;
  description: string;
};

type SecurityCheck = {
  id: string;
  label: string;
  reference: string;
};

const workflowViews: WorkflowView[] = [
  {
    id: "setup",
    step: "01",
    label: "Setup",
    description: "Define the target and test scope",
  },
  {
    id: "discovery",
    step: "02",
    label: "Discovery",
    description: "Verify authentication flows",
  },
  {
    id: "testing",
    step: "03",
    label: "Testing",
    description: "Run controlled security checks",
  },
  {
    id: "results",
    step: "04",
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
            <p className="eyebrow">
              {currentView.step} / Authentication assessment
            </p>
            <h1>{currentView.label}</h1>
            <p>{currentView.description}</p>
          </div>
          <div className="local-badge">Local execution</div>
        </header>

        {activeView === "setup" && (
          <SetupView onContinue={() => setActiveView("discovery")} />
        )}
        {activeView === "discovery" && <DiscoveryView />}
        {activeView === "testing" && <TestingView />}
        {activeView === "results" && <ResultsView />}
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
    checking: "Checking backend",
    connected: "Backend connected",
    offline: "Backend offline",
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
            <span className="nav-step">{view.step}</span>
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
          <small>127.0.0.1:8080</small>
        </div>
      </div>
    </aside>
  );
}

type SetupViewProps = {
  onContinue: () => void;
};

function SetupView({ onContinue }: SetupViewProps) {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:3000");
  const [permittedOrigins, setPermittedOrigins] = useState(
    "http://127.0.0.1:3000",
  );
  const [selectedChecks, setSelectedChecks] = useState<string[]>(
    securityChecks.map((check) => check.id),
  );

  function toggleCheck(checkId: string) {
    if (selectedChecks.includes(checkId)) {
      setSelectedChecks(selectedChecks.filter((id) => id !== checkId));
      return;
    }

    setSelectedChecks([...selectedChecks, checkId]);
  }

  function submitSetup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onContinue();
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

      <section className="panel readiness-panel">
        <div>
          <p className="eyebrow">Current foundation</p>
          <h2>Ready to configure</h2>
          <p>
            Browser observation and validated actions are available. Automated
            discovery and scan execution are the next implementation steps.
          </p>
        </div>
        <button
          className="primary-button"
          disabled={selectedChecks.length === 0}
          type="submit"
        >
          Continue to discovery
          <span aria-hidden="true">→</span>
        </button>
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

function TestingView() {
  return (
    <section className="panel status-table-panel">
      <div className="section-heading">
        <div>
          <p className="section-number">C</p>
          <h2>Check status</h2>
        </div>
        <span className="selection-count">0 of 6 complete</span>
      </div>
      <div className="status-table">
        {securityChecks.map((check) => (
          <div className="status-row" key={check.id}>
            <span className="status-dot status-dot-idle" aria-hidden="true" />
            <strong>{check.label}</strong>
            <span>{check.reference}</span>
            <span className="status-pill">Not started</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ResultsView() {
  return (
    <EmptyWorkspace
      code="NO_RESULTS"
      heading="Evidence will appear here"
      message="Completed findings, limitations, and offline report downloads will be listed after a scan."
    />
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
