import { useEffect, useState } from "react";
import {
  ConnectionStatus,
  DiscoveryView,
  ResultsView,
  ScanStatus,
  SetupView,
  Sidebar,
  TestingView,
  ViewId,
} from "./components/Workspace";

const viewHeadings: Record<ViewId, { label: string; description: string }> = {
  setup: { label: "Setup", description: "Define the target and test scope" },
  discovery: { label: "Discovery", description: "Verify authentication flows" },
  testing: { label: "Testing", description: "Run controlled security checks" },
  results: { label: "Results", description: "Review evidence and coverage" },
};

function App() {
  const [activeView, setActiveView] = useState<ViewId>("setup");
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("checking");
  const [scanId, setScanId] = useState("");
  const [selectedChecks, setSelectedChecks] = useState<string[]>([]);
  const [currentScan, setCurrentScan] = useState<ScanStatus | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

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
        if (requestIsActive) setConnectionStatus("offline");
      }
    }
    void checkBackend();
    return () => {
      requestIsActive = false;
    };
  }, []);

  useEffect(() => {
    if (!scanId || activeView !== "testing") return;
    let requestIsActive = true;
    async function loadScan() {
      try {
        const response = await fetch(
          `/api/scans/${encodeURIComponent(scanId)}`,
        );
        if (!response.ok)
          throw new Error("The scan status could not be loaded.");
        if (requestIsActive) {
          setCurrentScan((await response.json()) as ScanStatus);
          setScanError(null);
        }
      } catch (loadError) {
        if (requestIsActive) {
          setScanError(
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
  }, [activeView, scanId]);

  const currentView = viewHeadings[activeView];

  return (
    <div className="app-shell">
      <Sidebar
        activeView={activeView}
        connectionStatus={connectionStatus}
        scan={currentScan}
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
            onStarted={(startedScanId, checks) => {
              setScanId(startedScanId);
              setSelectedChecks(checks);
              setCurrentScan(null);
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
            scan={currentScan}
            scanError={scanError}
            selectedChecks={selectedChecks}
            onScanChange={setCurrentScan}
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

export default App;
