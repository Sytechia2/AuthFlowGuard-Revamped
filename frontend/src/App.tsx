import {
  ArrowLeft,
  ArrowRight,
  Ban,
  Check,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  CircleDashed,
  Download,
  ExternalLink,
  FileJson,
  FileText,
  Info,
  List,
  LoaderCircle,
  Pencil,
  Plus,
  Search,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  X,
} from "lucide-react";
import {
  FormEvent,
  Fragment,
  ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  checkCatalog,
  CheckInfo,
  checkInfo,
  compareRatings,
  countRatings,
  outcomeLabel,
  Rating,
  ratingFor,
  ratingLabels,
  reportSeverity,
  reportStatus,
} from "./checks";
import { checkDetail, methodology } from "./checkDetails";

type ConnectionStatus = "checking" | "connected" | "offline";

type Route =
  | { page: "scans" }
  | { page: "new" }
  | { page: "scan"; scanId: string }
  | { page: "checks" }
  | { page: "check"; checkId: string };

type ScanResult = {
  result_id?: string;
  check_id: string;
  outcome: string;
  owasp_reference: string;
  explanation: string;
  coverage_limitations?: string[];
  created_at?: string;
  analyser_version?: string;
  evidence_references?: string[];
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

// The non-secret login proof a scan verifies sign-in with, while the backend
// still knows it. The selector is only known while the scan is paused.
type VerificationSettings = {
  protected_resource: string | null;
  account_marker_selector: string | null;
  account_marker_description: string | null;
};

type ExecutionProgress = {
  active_check: string | null;
  completed_checks: string[];
  cancelled_checks: string[];
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
  execution_progress?: ExecutionProgress;
  verification?: VerificationSettings | null;
};

type EvidenceItem = {
  evidence_id: string;
  check_id: string;
  event_ids?: string[];
  control_comparisons?: string[];
  errors?: string[];
  observations?: unknown;
  coverage?: {
    attempted_steps?: string[];
    completed_steps?: string[];
    limitations?: string[];
  };
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
  registration_link?: string | null;
  reset_link?: string | null;
  link_sources?: Partial<Record<LinkRole, SuggestionSource>>;
};

type LinkRole = "registration_link" | "reset_link";

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

const ACTIVE_STATES = new Set(["created", "running", "awaiting_guidance"]);

function isActive(scan: ScanStatus | null): boolean {
  return scan !== null && ACTIVE_STATES.has(scan.state);
}

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

// A link or button that may open the registration or reset form. The
// backend decides whether the choice is usable before saving it.
function isLinkOption(control: SafeControl): boolean {
  return control.visible && (control.tag === "a" || isSubmitOption(control));
}

type LinkChoice = { controlId: string; source: SuggestionSource | null };

// Pre-select a suggested link only when it is one of the dropdown's options.
function suggestedLinkChoices(
  observation: GuidanceObservation,
): Record<LinkRole, LinkChoice> {
  const suggested = observation.suggested_controls;
  const choice = (role: LinkRole): LinkChoice => {
    const controlId = suggested?.[role] ?? null;
    const control = observation.controls.find(
      (candidate) => candidate.observed_control_id === controlId,
    );
    return control && isLinkOption(control)
      ? {
          controlId: control.observed_control_id,
          source: suggested?.link_sources?.[role] ?? null,
        }
      : { controlId: "", source: null };
  };
  return {
    registration_link: choice("registration_link"),
    reset_link: choice("reset_link"),
  };
}

const linkQuestions: { role: LinkRole; question: string; label: string }[] = [
  {
    role: "registration_link",
    question: "Which link opens registration?",
    label: "Registration link",
  },
  {
    role: "reset_link",
    question: "Which link opens password reset?",
    label: "Password reset link",
  },
];

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

// ---- Routing -------------------------------------------------------------

function parseRoute(hash: string): Route {
  const path = hash.replace(/^#/, "");
  if (path === "/new") return { page: "new" };
  if (path === "/checks") return { page: "checks" };
  const match = /^\/scans\/([^/]+)$/.exec(path);
  if (match) return { page: "scan", scanId: decodeURIComponent(match[1]) };
  const checkMatch = /^\/checks\/([^/]+)$/.exec(path);
  if (checkMatch) {
    return { page: "check", checkId: decodeURIComponent(checkMatch[1]) };
  }
  return { page: "scans" };
}

function routeHash(route: Route): string {
  if (route.page === "new") return "#/new";
  if (route.page === "scan")
    return `#/scans/${encodeURIComponent(route.scanId)}`;
  if (route.page === "checks") return "#/checks";
  if (route.page === "check")
    return `#/checks/${encodeURIComponent(route.checkId)}`;
  return "#/scans";
}

// ---- Scan names (kept in this browser only) -------------------------------

type ScanNote = { name?: string; checks?: string[] };

const SCAN_NOTES_KEY = "authflowguard.scanNotes";

function readScanNotes(): Record<string, ScanNote> {
  try {
    const raw = window.localStorage.getItem(SCAN_NOTES_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, ScanNote>)
      : {};
  } catch {
    return {};
  }
}

function writeScanNote(scanId: string, note: ScanNote) {
  try {
    const notes = readScanNotes();
    notes[scanId] = { ...notes[scanId], ...note };
    window.localStorage.setItem(SCAN_NOTES_KEY, JSON.stringify(notes));
  } catch {
    // Names are a convenience; the scan works without them.
  }
}

function removeScanNotes(scanIds: string[]) {
  try {
    const notes = readScanNotes();
    for (const scanId of scanIds) delete notes[scanId];
    window.localStorage.setItem(SCAN_NOTES_KEY, JSON.stringify(notes));
  } catch {
    // A leftover name only costs a few bytes of browser storage.
  }
}

function targetHost(targetUrl?: string): string {
  if (!targetUrl) return "unknown target";
  try {
    return new URL(targetUrl).host;
  } catch {
    return targetUrl;
  }
}

function scanTitle(scanId: string, targetUrl?: string): string {
  const name = readScanNotes()[scanId]?.name?.trim();
  return name || `Scan of ${targetHost(targetUrl)}`;
}

// ---- Formatting -------------------------------------------------------------

const monthNames = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const time = [date.getHours(), date.getMinutes()]
    .map((part) => String(part).padStart(2, "0"))
    .join(":");
  return `${date.getDate()} ${monthNames[date.getMonth()]} ${date.getFullYear()} ${time}`;
}

function formatDuration(start?: string | null, end?: string | null): string {
  if (!start || !end) return "—";
  const seconds = Math.round(
    (new Date(end).getTime() - new Date(start).getTime()) / 1000,
  );
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const minutes = Math.floor(seconds / 60);
  return minutes > 0 ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
}

function formatUsd(value?: string | number | null, digits = 4): string {
  const amount = typeof value === "string" ? Number(value) : (value ?? 0);
  if (!Number.isFinite(amount)) return "$0";
  // Budgets read as $0.25, spend keeps enough digits to show fractions of a cent.
  return `$${Number(amount.toFixed(digits))}`;
}

function modelName(modelId?: string | null): string {
  if (!modelId) return "";
  const base = modelId
    .replace(/^[a-z]+\./, "")
    .replace(/-v\d+(:\d+)?$/, "")
    .replace(/[:].*$/, "");
  return base
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

const stateLabels: Record<string, string> = {
  created: "Queued",
  running: "Running",
  awaiting_guidance: "Needs your help",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

function StatusPill({ state }: { state: string }) {
  return (
    <span className={`status-pill status-${state}`}>
      {state === "running" && (
        <LoaderCircle aria-hidden="true" className="spin" size={13} />
      )}
      {stateLabels[state] ?? state}
    </span>
  );
}

function RatingBadge({ rating }: { rating: Rating }) {
  return (
    <span className={`rating-badge rating-${rating}`}>
      {ratingLabels[rating]}
    </span>
  );
}

// ---- App shell --------------------------------------------------------------

function App() {
  const [route, setRoute] = useState<Route>(() =>
    parseRoute(window.location.hash),
  );
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("checking");

  useEffect(() => {
    // Plain links between pages change the hash; open them at the top.
    const onHashChange = () => {
      setRoute(parseRoute(window.location.hash));
      window.scrollTo?.(0, 0);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

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

  const navigate = useCallback((next: Route) => {
    const hash = routeHash(next);
    if (window.location.hash !== hash) window.location.hash = hash;
    setRoute(next);
    window.scrollTo?.(0, 0);
  }, []);

  return (
    <div className="app-shell">
      <Sidebar
        connectionStatus={connectionStatus}
        navigate={navigate}
        route={route}
      />
      <main className="workspace">
        {route.page === "scans" && <ScansPage navigate={navigate} />}
        {route.page === "new" && (
          <NewScanPage
            navigate={navigate}
            onStarted={(scanId) => navigate({ page: "scan", scanId })}
          />
        )}
        {route.page === "scan" && (
          <ScanPage
            key={route.scanId}
            navigate={navigate}
            scanId={route.scanId}
          />
        )}
        {route.page === "checks" && <ChecksPage navigate={navigate} />}
        {route.page === "check" && (
          <CheckPage
            checkId={route.checkId}
            key={route.checkId}
            navigate={navigate}
          />
        )}
      </main>
    </div>
  );
}

function BrandMark() {
  return (
    <svg
      aria-hidden="true"
      className="brand-mark"
      fill="none"
      viewBox="0 0 24 24"
    >
      <path
        d="M12 2.5 4.5 5.4v6.1c0 4.6 3.1 8.6 7.5 9.9 4.4-1.3 7.5-5.3 7.5-9.9V5.4L12 2.5Z"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
      <circle cx="12" cy="10.2" fill="currentColor" r="2.1" />
      <path
        d="M12 12v3.6"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="2"
      />
    </svg>
  );
}

type SidebarProps = {
  connectionStatus: ConnectionStatus;
  route: Route;
  navigate: (route: Route) => void;
};

function Sidebar({ connectionStatus, route, navigate }: SidebarProps) {
  const statusLabels: Record<ConnectionStatus, string> = {
    checking: "Checking local API",
    connected: "Local API online",
    offline: "Local API offline",
  };
  const scansActive = route.page === "scans" || route.page === "scan";
  const checksActive = route.page === "checks" || route.page === "check";

  return (
    <aside className="sidebar">
      <a
        className="brand"
        href="#/scans"
        onClick={(event) => {
          event.preventDefault();
          navigate({ page: "scans" });
        }}
      >
        <BrandMark />
        <strong>AuthFlowGuard</strong>
      </a>

      <nav aria-label="Main" className="nav">
        <button
          aria-current={scansActive ? "page" : undefined}
          className={`nav-item ${scansActive ? "nav-item-active" : ""}`}
          onClick={() => navigate({ page: "scans" })}
          type="button"
        >
          <List aria-hidden="true" size={18} />
          Scans
        </button>
        <button
          aria-current={route.page === "new" ? "page" : undefined}
          className={`nav-item ${route.page === "new" ? "nav-item-active" : ""}`}
          onClick={() => navigate({ page: "new" })}
          type="button"
        >
          <Plus aria-hidden="true" size={18} />
          New scan
        </button>
        <button
          aria-current={checksActive ? "page" : undefined}
          className={`nav-item ${checksActive ? "nav-item-active" : ""}`}
          onClick={() => navigate({ page: "checks" })}
          type="button"
        >
          <ShieldCheck aria-hidden="true" size={18} />
          Checks
        </button>
      </nav>

      <div
        className={`connection connection-${connectionStatus}`}
        role="status"
      >
        <span className="status-dot" aria-hidden="true" />
        <span>{statusLabels[connectionStatus]}</span>
      </div>
    </aside>
  );
}

function Breadcrumb({
  current,
  navigate,
  parent = { label: "Scans", route: { page: "scans" } },
}: {
  current: string;
  navigate: (route: Route) => void;
  parent?: { label: string; route: Route };
}) {
  return (
    <nav aria-label="Breadcrumb" className="breadcrumb">
      <a
        href={routeHash(parent.route)}
        onClick={(event) => {
          event.preventDefault();
          navigate(parent.route);
        }}
      >
        {parent.label}
      </a>
      <span aria-hidden="true">/</span>
      <span aria-current="page">{current}</span>
    </nav>
  );
}

// ---- Scans list -------------------------------------------------------------

function SeverityChips({ results }: { results: ScanResult[] }) {
  const counts = countRatings(results);
  const shown = (
    ["critical", "high", "medium", "low", "passed"] as Rating[]
  ).filter((rating) => counts[rating] > 0);
  if (shown.length === 0) return <span className="muted">—</span>;
  return (
    <span className="severity-chips">
      {shown.map((rating) => (
        <span
          className={`severity-chip rating-${rating}`}
          key={rating}
          title={`${counts[rating]} ${ratingLabels[rating]}`}
        >
          {counts[rating]}
          <span className="visually-hidden"> {ratingLabels[rating]}</span>
        </span>
      ))}
    </span>
  );
}

function ScansPage({ navigate }: { navigate: (route: Route) => void }) {
  const [scans, setScans] = useState<ScanStatus[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanIdQuery, setScanIdQuery] = useState("");
  const [queryError, setQueryError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const selectAllRef = useRef<HTMLInputElement>(null);

  // A scan that is still working must be cancelled before it can be deleted.
  const deletableIds = scans
    .filter((scan) => !isActive(scan))
    .map((scan) => scan.scan_id);
  const selectedCount = deletableIds.filter((id) => selected.has(id)).length;
  const allSelected =
    deletableIds.length > 0 && selectedCount === deletableIds.length;

  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = selectedCount > 0 && !allSelected;
    }
  }, [selectedCount, allSelected]);

  function toggleSelected(scanId: string, checked: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      if (checked) next.add(scanId);
      else next.delete(scanId);
      return next;
    });
  }

  async function deleteSelected() {
    const ids = deletableIds.filter((id) => selected.has(id));
    if (ids.length === 0) return;
    const confirmed = window.confirm(
      ids.length === 1
        ? "Delete 1 scan? Its evidence, results, and reports will be permanently removed."
        : `Delete ${ids.length} scans? Their evidence, results, and reports will be permanently removed.`,
    );
    if (!confirmed) return;
    setIsDeleting(true);
    setDeleteError(null);
    const deleted: string[] = [];
    const failed: string[] = [];
    const details = new Set<string>();
    // One at a time: the backend holds one lock while it removes scan files.
    for (const scanId of ids) {
      try {
        const response = await fetch(
          `/api/scans/${encodeURIComponent(scanId)}`,
          { method: "DELETE" },
        );
        if (response.ok) {
          deleted.push(scanId);
          continue;
        }
        const body: unknown = await response.json().catch(() => null);
        if (
          body !== null &&
          typeof body === "object" &&
          "detail" in body &&
          typeof body.detail === "string"
        ) {
          details.add(body.detail);
        }
      } catch {
        details.add("The local API could not be reached.");
      }
      failed.push(scanId);
    }
    const removed = new Set(deleted);
    setScans((current) => current.filter((scan) => !removed.has(scan.scan_id)));
    setSelected(new Set(failed));
    removeScanNotes(deleted);
    if (failed.length > 0) {
      const count = failed.length === 1 ? "1 scan" : `${failed.length} scans`;
      setDeleteError(
        `${count} could not be deleted.${details.size > 0 ? ` ${[...details].join(" ")}` : ""}`,
      );
    }
    setIsDeleting(false);
  }

  useEffect(() => {
    let requestIsActive = true;
    async function loadScans() {
      try {
        const response = await fetch("/api/scans");
        if (!response.ok) {
          throw new Error("Past scans could not be loaded.");
        }
        const body: unknown = await response.json();
        if (requestIsActive) {
          setScans(Array.isArray(body) ? (body as ScanStatus[]) : []);
          setError(null);
        }
      } catch (loadError) {
        if (requestIsActive) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load past scans.",
          );
        }
      } finally {
        if (requestIsActive) setIsLoading(false);
      }
    }
    void loadScans();
    return () => {
      requestIsActive = false;
    };
  }, []);

  function openById(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const requested = scanIdQuery.trim();
    if (!requested) {
      setQueryError("Enter a scan ID first.");
      return;
    }
    navigate({ page: "scan", scanId: requested });
  }

  return (
    <div className="page page-wide">
      <header className="page-header">
        <div className="page-title">
          <h1>Scans</h1>
          <p className="page-subtitle">
            Authentication scans run on this computer, newest first.
          </p>
        </div>
        <div className="page-actions">
          <button
            className="button button-primary"
            onClick={() => navigate({ page: "new" })}
            type="button"
          >
            <Plus aria-hidden="true" size={16} />
            New scan
          </button>
        </div>
      </header>

      <section className="card">
        <div className="table-toolbar">
          <div className="toolbar-start">
            <h2 className="card-title">
              All scans <span className="count">{scans.length}</span>
            </h2>
            {selectedCount > 0 && (
              <div className="selection-actions">
                <button
                  className="button button-danger"
                  disabled={isDeleting}
                  onClick={() => void deleteSelected()}
                  type="button"
                >
                  <Trash2 aria-hidden="true" size={16} />
                  {isDeleting
                    ? "Deleting…"
                    : `Delete selected (${selectedCount})`}
                </button>
                <button
                  className="button button-secondary"
                  disabled={isDeleting}
                  onClick={() => setSelected(new Set())}
                  type="button"
                >
                  Clear selection
                </button>
              </div>
            )}
          </div>
          <form className="id-search" onSubmit={openById}>
            <label className="visually-hidden" htmlFor="scan-id">
              Scan ID
            </label>
            <Search aria-hidden="true" className="input-icon" size={16} />
            <input
              id="scan-id"
              onChange={(event) => {
                setScanIdQuery(event.target.value);
                setQueryError(null);
              }}
              placeholder="Open a scan by ID"
              value={scanIdQuery}
            />
            <button className="button button-secondary" type="submit">
              Open scan
            </button>
          </form>
        </div>
        {queryError && (
          <p className="form-error inset" role="alert">
            {queryError}
          </p>
        )}
        {error && <p className="form-error inset">{error}</p>}
        {deleteError && (
          <p className="form-error inset" role="alert">
            {deleteError}
          </p>
        )}
        {isLoading ? (
          <p className="empty-row">Loading scans…</p>
        ) : scans.length === 0 ? (
          <div className="empty-state">
            <h2>No scans yet</h2>
            <p>
              Start a scan of a website you own or are authorised to test. Its
              findings and evidence will be listed here.
            </p>
            <button
              className="button button-primary"
              onClick={() => navigate({ page: "new" })}
              type="button"
            >
              <Plus aria-hidden="true" size={16} />
              New scan
            </button>
          </div>
        ) : (
          <table className="data-table scans-table">
            <thead>
              <tr>
                <th className="select-cell" scope="col">
                  <input
                    aria-label="Select all scans"
                    checked={allSelected}
                    disabled={deletableIds.length === 0 || isDeleting}
                    onChange={(event) =>
                      setSelected(
                        new Set(event.target.checked ? deletableIds : []),
                      )
                    }
                    ref={selectAllRef}
                    type="checkbox"
                  />
                </th>
                <th scope="col">Scan</th>
                <th scope="col">Status</th>
                <th scope="col">Findings</th>
                <th scope="col">Started</th>
                <th aria-label="Open" scope="col" />
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const title = scanTitle(scan.scan_id, scan.target_url);
                const active = isActive(scan);
                const isSelected = !active && selected.has(scan.scan_id);
                return (
                  <tr
                    className={`clickable-row ${isSelected ? "row-selected" : ""}`}
                    key={scan.scan_id}
                    onClick={() =>
                      navigate({ page: "scan", scanId: scan.scan_id })
                    }
                  >
                    <td
                      className="select-cell"
                      onClick={(event) => event.stopPropagation()}
                    >
                      <input
                        aria-label={`Select ${title}`}
                        checked={isSelected}
                        disabled={active || isDeleting}
                        onChange={(event) =>
                          toggleSelected(scan.scan_id, event.target.checked)
                        }
                        title={
                          active
                            ? "Cancel the scan before deleting it"
                            : undefined
                        }
                        type="checkbox"
                      />
                    </td>
                    <td>
                      <button
                        className="row-link"
                        onClick={(event) => {
                          event.stopPropagation();
                          navigate({ page: "scan", scanId: scan.scan_id });
                        }}
                        type="button"
                      >
                        {title}
                      </button>
                      <span className="mono subtle">
                        {scan.target_url ?? "Target unavailable"}
                      </span>
                    </td>
                    <td>
                      <StatusPill state={scan.state} />
                    </td>
                    <td>
                      <SeverityChips results={scan.results ?? []} />
                    </td>
                    <td className="nowrap">
                      {formatDate(scan.started_at ?? scan.created_at)}
                    </td>
                    <td className="chevron-cell">
                      <ChevronRight aria-hidden="true" size={18} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

// ---- Check reference ------------------------------------------------------

// How each check works, for administrators who need to verify a verdict.
// The words come from checkDetails.ts; codes, severities and
// recommendations from checks.ts.

function ChecksPage({ navigate }: { navigate: (route: Route) => void }) {
  return (
    <div className="page page-wide">
      <header className="page-header">
        <div className="page-title">
          <h1>Checks</h1>
          <p className="page-subtitle">
            What each check tests, how it runs and how its verdict is decided.
          </p>
        </div>
      </header>

      <div className="checks-overview">
        <section aria-labelledby="methodology-title" className="card doc-card">
          <h2 className="card-title" id="methodology-title">
            How every check works
          </h2>
          <ul className="doc-list doc-list-columns">
            {methodology.map((fact) => (
              <li key={fact}>{fact}</li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="catalog-title" className="card">
          <div className="table-toolbar">
            <h2 className="card-title" id="catalog-title">
              All checks <span className="count">{checkCatalog.length}</span>
            </h2>
          </div>
          <table className="data-table catalog-table">
            <thead>
              <tr>
                <th scope="col">Code</th>
                <th scope="col">Check</th>
                <th scope="col">OWASP reference</th>
                <th scope="col">If found</th>
                <th scope="col">What it answers</th>
              </tr>
            </thead>
            <tbody>
              {checkCatalog.map((check) => {
                const route: Route = { page: "check", checkId: check.id };
                return (
                  <tr
                    className="clickable-row"
                    key={check.id}
                    onClick={() => navigate(route)}
                  >
                    <td>{check.code}</td>
                    <td>
                      <a
                        className="row-link"
                        href={routeHash(route)}
                        onClick={(event) => {
                          event.preventDefault();
                          event.stopPropagation();
                          navigate(route);
                        }}
                      >
                        {check.label}
                      </a>
                      <span className="compact-meta muted">
                        {checkDetail(check.id)?.question}
                      </span>
                    </td>
                    <td className="subtle">{check.reference}</td>
                    <td>
                      <RatingBadge rating={check.failureSeverity} />
                    </td>
                    <td className="catalog-question">
                      {checkDetail(check.id)?.question}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}

function DocList({ items }: { items: string[] }) {
  return (
    <ul className="doc-list">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

function CheckPage({
  checkId,
  navigate,
}: {
  checkId: string;
  navigate: (route: Route) => void;
}) {
  const info = checkInfo(checkId);
  const detail = checkDetail(checkId);
  const checksRoute: Route = { page: "checks" };

  if (!info || !detail) {
    return (
      <div className="page page-narrow">
        <Breadcrumb
          current={checkId}
          navigate={navigate}
          parent={{ label: "Checks", route: checksRoute }}
        />
        <div className="card empty-state">
          <h1>Check not found</h1>
          <p>There is no check called {checkId}. Choose one from the list.</p>
          <button
            className="button button-secondary"
            onClick={() => navigate(checksRoute)}
            type="button"
          >
            <ArrowLeft aria-hidden="true" size={16} />
            Back to checks
          </button>
        </div>
      </div>
    );
  }

  const verdictRules: {
    label: string;
    rating: Rating;
    rule: string;
  }[] = [
    {
      label: "Finding",
      rating: info.failureSeverity,
      rule: detail.verdicts.finding,
    },
    { label: "No issue", rating: "passed", rule: detail.verdicts.noIssue },
    {
      label: "Inconclusive",
      rating: "inconclusive",
      rule: detail.verdicts.inconclusive,
    },
  ];
  const sections: { id: string; title: string; body: ReactNode }[] = [
    {
      id: "answers",
      title: "What it answers",
      body: (
        <>
          <p className="doc-lead">{detail.question}</p>
          <p>{detail.risk}</p>
        </>
      ),
    },
    {
      id: "needs",
      title: "What it needs",
      body: <DocList items={detail.prerequisites} />,
    },
    {
      id: "procedure",
      title: "How it checks",
      body: (
        <ol className="doc-list doc-steps">
          {detail.procedure.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      ),
    },
    {
      id: "signals",
      title: "What it compares",
      body: <DocList items={detail.signals} />,
    },
    {
      id: "evidence",
      title: "What it records",
      body: <DocList items={detail.evidence} />,
    },
    {
      id: "verdicts",
      title: "How the verdict is decided",
      body: (
        <dl className="verdict-rules">
          {verdictRules.map((verdict) => (
            <div key={verdict.label}>
              <dt>
                {/* The badge already says Inconclusive; don't repeat it. */}
                {verdict.label !== ratingLabels[verdict.rating] && (
                  <span>{verdict.label}</span>
                )}
                <RatingBadge rating={verdict.rating} />
              </dt>
              <dd>{verdict.rule}</dd>
            </div>
          ))}
        </dl>
      ),
    },
    {
      id: "safeguards",
      title: "Safeguards",
      body: <DocList items={detail.safeguards} />,
    },
    {
      id: "limitations",
      title: "What it does not establish",
      body: <DocList items={detail.limitations} />,
    },
    {
      id: "recommendation",
      title: "Recommendation if found",
      body: <p>{info.recommendation}</p>,
    },
    {
      id: "source",
      title: "Source code",
      body: (
        <ul className="source-list">
          {detail.sourceFiles.map((path) => (
            <li key={path}>
              <code>{path}</code>
            </li>
          ))}
        </ul>
      ),
    },
  ];
  const index = checkCatalog.findIndex((check) => check.id === checkId);
  const previous = index > 0 ? checkCatalog[index - 1] : undefined;
  const next =
    index >= 0 && index < checkCatalog.length - 1
      ? checkCatalog[index + 1]
      : undefined;
  const pagerLink = (check: CheckInfo, direction: "previous" | "next") => {
    const route: Route = { page: "check", checkId: check.id };
    return (
      <a
        className={`pager-link pager-${direction}`}
        href={routeHash(route)}
        onClick={(event) => {
          event.preventDefault();
          navigate(route);
        }}
      >
        <small>
          {direction === "previous" ? "Previous check" : "Next check"}
        </small>
        <span>
          {direction === "previous" && (
            <ArrowLeft aria-hidden="true" size={16} />
          )}
          {check.code} {check.label}
          {direction === "next" && <ArrowRight aria-hidden="true" size={16} />}
        </span>
      </a>
    );
  };

  return (
    <div className="page page-narrow">
      <Breadcrumb
        current={`${info.code} ${info.label}`}
        navigate={navigate}
        parent={{ label: "Checks", route: checksRoute }}
      />
      <header className="page-header">
        <div className="page-title">
          <h1>
            <span className="subtle">{info.code}</span> {info.label}
          </h1>
          <div className="check-meta">
            <span className="check-meta-item">
              If found <RatingBadge rating={info.failureSeverity} />
            </span>
            <a
              className="check-meta-item"
              href={detail.owaspUrl}
              rel="noreferrer"
              target="_blank"
            >
              OWASP {info.reference}
              <ExternalLink aria-hidden="true" size={14} />
            </a>
          </div>
        </div>
      </header>

      <div className="check-layout">
        <article aria-label={`How ${info.label} works`} className="card doc">
          {sections.map((section) => (
            <section
              aria-labelledby={`check-section-${section.id}-title`}
              className="doc-section"
              id={`check-section-${section.id}`}
              key={section.id}
            >
              <h2
                className="card-title"
                id={`check-section-${section.id}-title`}
              >
                {section.title}
              </h2>
              {section.body}
            </section>
          ))}
        </article>
        <nav aria-label="On this page" className="settings-nav check-toc">
          <span className="toc-title">On this page</span>
          {sections.map((section) => (
            <button
              key={section.id}
              onClick={() =>
                document
                  .getElementById(`check-section-${section.id}`)
                  ?.scrollIntoView?.({ behavior: "smooth", block: "start" })
              }
              type="button"
            >
              {section.title}
            </button>
          ))}
        </nav>
      </div>

      <nav aria-label="Other checks" className="pager">
        {previous ? pagerLink(previous, "previous") : <span />}
        {next ? pagerLink(next, "next") : <span />}
      </nav>
    </div>
  );
}

// ---- New scan ---------------------------------------------------------------

type NewScanPageProps = {
  navigate: (route: Route) => void;
  onStarted: (scanId: string) => void;
};

const settingsSections = [
  { id: "section-target", label: "Target" },
  { id: "section-discovery", label: "Discovery" },
  { id: "section-checks", label: "Checks" },
  { id: "section-account", label: "Test account" },
  { id: "section-proof", label: "Login proof" },
];

function NewScanPage({ navigate, onStarted }: NewScanPageProps) {
  const [scanName, setScanName] = useState("");
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
    checkCatalog.map((check) => check.formId),
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
      writeScanNote(created.scan_id, {
        ...(scanName.trim() ? { name: scanName.trim() } : {}),
        checks: selectedBackendChecks,
      });
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

  const modelLabel =
    capabilities?.model_name || modelName(capabilities?.model_id) || "Bedrock";

  return (
    <div className="page page-narrow">
      <Breadcrumb current="New scan" navigate={navigate} />
      <header className="page-header">
        <div className="page-title">
          <h1>New scan</h1>
          <p className="page-subtitle">
            Test how a website handles sign-in, sessions and logout.
          </p>
        </div>
      </header>

      <form className="settings-layout" onSubmit={submitSetup}>
        <nav aria-label="Scan settings" className="settings-nav">
          {settingsSections.map((section) => (
            <button
              key={section.id}
              onClick={() =>
                document
                  .getElementById(section.id)
                  ?.scrollIntoView?.({ behavior: "smooth", block: "start" })
              }
              type="button"
            >
              {section.label}
            </button>
          ))}
        </nav>

        <div className="settings-sections">
          <section
            aria-labelledby="section-target-title"
            className="card settings-card"
            id="section-target"
          >
            <h2 className="card-title" id="section-target-title">
              Target
            </h2>
            <div className="form-grid">
              <div className="field">
                <label htmlFor="scan-name">Scan name</label>
                <input
                  aria-describedby="scan-name-help"
                  id="scan-name"
                  onChange={(event) => setScanName(event.target.value)}
                  placeholder="e.g. Staging login and session checks"
                  value={scanName}
                />
                <small id="scan-name-help">
                  Optional. Saved in this browser only.
                </small>
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
              <div className="field field-wide">
                <label htmlFor="permitted-origins">Permitted origins</label>
                <textarea
                  aria-describedby="permitted-origins-help"
                  id="permitted-origins"
                  onChange={(event) => setPermittedOrigins(event.target.value)}
                  required
                  rows={2}
                  value={permittedOrigins}
                />
                <small id="permitted-origins-help">
                  One frontend or API origin per line. Requests outside this
                  list are blocked.
                </small>
              </div>
            </div>
            <p className="notice notice-warning">
              <TriangleAlert aria-hidden="true" size={16} />
              Only test websites you own or have explicit permission to assess.
              Scans make real failed sign-in attempts.
            </p>
          </section>

          <section
            aria-labelledby="section-discovery-title"
            className="card settings-card"
            id="section-discovery"
          >
            <h2 className="card-title" id="section-discovery-title">
              Discovery
            </h2>
            <p className="card-help">
              How AuthFlowGuard finds the sign-in form before the checks run.
            </p>
            <div
              className="option-list"
              role="radiogroup"
              aria-label="Discovery engine"
            >
              <label
                className={`option ${discoveryMode === "bedrock" ? "option-selected" : ""}`}
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
                <span className="option-copy">
                  <strong>Bedrock AI discovery</strong>
                  <small>
                    Amazon Bedrock ({modelLabel}) suggests the sign-in controls;
                    AuthFlowGuard checks each suggestion before using it.
                  </small>
                </span>
              </label>
              <label
                className={`option ${discoveryMode === "rules" ? "option-selected" : ""}`}
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
                <span className="option-copy">
                  <strong>Deterministic rules</strong>
                  <small>
                    Finds standard sign-in forms from their labels, and asks you
                    when it cannot.
                  </small>
                </span>
              </label>
            </div>

            {capabilities && (
              <p
                className={`notice ${
                  capabilities.bedrock_configured
                    ? "notice-success"
                    : "notice-warning"
                }`}
                role={capabilities.bedrock_configured ? undefined : "alert"}
              >
                {capabilities.bedrock_configured ? (
                  <CircleCheck aria-hidden="true" size={16} />
                ) : (
                  <TriangleAlert aria-hidden="true" size={16} />
                )}
                <span>
                  <strong>
                    {capabilities.bedrock_configured
                      ? `Bedrock online: ${capabilities.model_name || capabilities.model_id}`
                      : "Bedrock not configured on backend"}
                  </strong>{" "}
                  {capabilities.bedrock_configured
                    ? `Model ${capabilities.model_id}, pricing configured.`
                    : capabilities.note ||
                      "AWS Bedrock credentials are not configured on the backend server. Choose deterministic rules or configure credentials."}
                </span>
              </p>
            )}

            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={reuseSavedProfile}
                onChange={(e) => setReuseSavedProfile(e.target.checked)}
              />
              <span className="option-copy">
                <strong>Reuse verified authentication profile</strong>
                <small>
                  Skip discovery when this target already has a verified sign-in
                  profile.
                </small>
              </span>
            </label>

            <details className="disclosure" open={discoveryMode === "bedrock"}>
              <summary>
                <ChevronDown aria-hidden="true" size={16} />
                AI limits
              </summary>
              <p className="card-help">
                Discovery stops when any limit is reached. Every model request
                is priced against the budget.
              </p>
              <div className="form-grid form-grid-3">
                <div className="field">
                  <label htmlFor="max-decisions">Maximum decisions</label>
                  <input
                    id="max-decisions"
                    type="number"
                    min={1}
                    max={
                      capabilities?.server_max_limits?.maximum_ai_decisions ??
                      100
                    }
                    value={maxDecisions}
                    onChange={(e) =>
                      setMaxDecisions(Math.max(1, Number(e.target.value)))
                    }
                  />
                </div>
                <div className="field">
                  <label htmlFor="max-seconds">
                    Active time limit (seconds)
                  </label>
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
                </div>
                <div className="field">
                  <label htmlFor="max-cost">Max inference budget (USD)</label>
                  <input
                    id="max-cost"
                    type="number"
                    step="0.01"
                    min={0.01}
                    max={
                      capabilities?.server_max_limits
                        ?.maximum_inference_cost_usd ?? 10.0
                    }
                    value={maxCostUsd}
                    onChange={(e) =>
                      setMaxCostUsd(Math.max(0.01, Number(e.target.value)))
                    }
                  />
                </div>
              </div>
            </details>
          </section>

          <section
            aria-labelledby="section-checks-title"
            className="card settings-card"
            id="section-checks"
          >
            <div className="card-heading">
              <h2 className="card-title" id="section-checks-title">
                Checks
              </h2>
              <span className="count-label">
                {selectedChecks.length} selected
              </span>
            </div>
            <table className="data-table checks-table">
              <thead>
                <tr>
                  <th scope="col">
                    <span className="visually-hidden">Run</span>
                  </th>
                  <th scope="col">Code</th>
                  <th scope="col">Check</th>
                  <th scope="col">OWASP reference</th>
                  <th scope="col">If found</th>
                  <th scope="col">
                    <span className="visually-hidden">How it works</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {checkCatalog.map((check) => {
                  const inputId = `check-${check.formId}`;
                  return (
                    <tr key={check.formId}>
                      <td>
                        <input
                          checked={selectedChecks.includes(check.formId)}
                          id={inputId}
                          onChange={() => toggleCheck(check.formId)}
                          type="checkbox"
                        />
                      </td>
                      <td className="nowrap">{check.code}</td>
                      <td>
                        <label htmlFor={inputId}>{check.label}</label>
                      </td>
                      <td className="nowrap subtle">{check.reference}</td>
                      <td>
                        <RatingBadge rating={check.failureSeverity} />
                      </td>
                      <td>
                        {/* A new tab keeps this form and its secrets intact. */}
                        <a
                          aria-label={`How ${check.label} works`}
                          className="info-link"
                          href={routeHash({ page: "check", checkId: check.id })}
                          rel="noreferrer"
                          target="_blank"
                        >
                          <Info aria-hidden="true" size={15} />
                          How it works
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>

          <section
            aria-labelledby="section-account-title"
            className="card settings-card"
            id="section-account"
          >
            <h2 className="card-title" id="section-account-title">
              Test account
            </h2>
            <p className="card-help">
              Used for this scan only: sent to the local backend and discarded
              afterwards. Never use production credentials.
            </p>
            <div className="form-grid">
              <div className="field">
                <label htmlFor="known-username">Known account username</label>
                <input
                  autoComplete="off"
                  id="known-username"
                  onChange={(event) => setKnownUsername(event.target.value)}
                  required
                  value={knownUsername}
                />
              </div>
              <div className="field">
                <label htmlFor="known-password">Known account password</label>
                <input
                  autoComplete="off"
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
                  autoComplete="off"
                  id="nonexistent-username"
                  onChange={(event) =>
                    setNonexistentUsername(event.target.value)
                  }
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
                  autoComplete="off"
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
              <div className="field">
                <label htmlFor="second-factor">
                  One-time verification code
                </label>
                <input
                  autoComplete="off"
                  id="second-factor"
                  onChange={(event) => setSecondFactor(event.target.value)}
                  placeholder="Only for two-step login flows"
                  value={secondFactor}
                />
                <small>Optional; kept in memory only for this scan.</small>
              </div>
            </div>
          </section>

          <section
            aria-labelledby="section-proof-title"
            className="card settings-card"
            id="section-proof"
          >
            <h2 className="card-title" id="section-proof-title">
              Login proof
            </h2>
            <p className="card-help">
              A page and element that only a signed-in user sees. AuthFlowGuard
              confirms the element is present when signed in and absent in a
              fresh anonymous session.
            </p>
            <div className="form-grid">
              <div className="field field-wide">
                <label htmlFor="protected-resource">
                  Protected resource URL
                </label>
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
                  className="mono"
                  id="account-marker-selector"
                  onChange={(event) =>
                    setAccountMarkerSelector(event.target.value)
                  }
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
        </div>

        <footer className="action-bar">
          <p className="action-summary">
            {selectedChecks.length} of {checkCatalog.length} checks ·{" "}
            {discoveryMode === "bedrock"
              ? `Bedrock AI, budget ${formatUsd(maxCostUsd, 2)}`
              : "Deterministic rules"}
          </p>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <div className="action-buttons">
            <button
              className="button button-secondary"
              onClick={() => navigate({ page: "scans" })}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button button-primary"
              disabled={selectedChecks.length === 0 || isStarting}
              type="submit"
            >
              {isStarting ? (
                <>
                  <LoaderCircle aria-hidden="true" className="spin" size={16} />
                  Starting scan…
                </>
              ) : (
                "Start scan"
              )}
            </button>
          </div>
        </footer>
      </form>
    </div>
  );
}

// ---- Scan page --------------------------------------------------------------

type ScanPageProps = {
  scanId: string;
  navigate: (route: Route) => void;
};

type TabId = "findings" | "evidence" | "ai" | "report";

const tabs: { id: TabId; label: string }[] = [
  { id: "findings", label: "Findings" },
  { id: "evidence", label: "Evidence" },
  { id: "ai", label: "AI discovery" },
  { id: "report", label: "Report" },
];

function ScanPage({ scanId, navigate }: ScanPageProps) {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("findings");
  const [isDeleting, setIsDeleting] = useState(false);
  const [title, setTitle] = useState(() => scanTitle(scanId));

  const [reloadCount, setReloadCount] = useState(0);
  const refresh = () => setReloadCount((count) => count + 1);

  // Load the scan, and keep polling while it is still working; polling stops
  // once the scan reaches a final state.
  const scanIsActive = isActive(scan);
  useEffect(() => {
    let requestIsActive = true;
    const load = () =>
      fetch(`/api/scans/${encodeURIComponent(scanId)}`)
        .then(async (response) => {
          if (!response.ok) throw new Error("The scan could not be found.");
          return (await response.json()) as ScanStatus;
        })
        .then((loaded) => {
          if (!requestIsActive) return;
          setScan(loaded);
          setTitle(scanTitle(loaded.scan_id, loaded.target_url));
          setLoadError(null);
        })
        .catch((error: unknown) => {
          if (!requestIsActive) return;
          setLoadError(
            error instanceof Error ? error.message : "Unable to load the scan.",
          );
        });
    void load();
    const interval = scanIsActive
      ? window.setInterval(() => void load(), 1500)
      : undefined;
    return () => {
      requestIsActive = false;
      window.clearInterval(interval);
    };
  }, [scanId, scanIsActive, reloadCount]);

  async function deleteScan(target: ScanStatus) {
    const confirmed = window.confirm(
      `Delete scan ${target.scan_id}? Its evidence, results, and reports will be permanently removed.`,
    );
    if (!confirmed) return;
    setIsDeleting(true);
    setActionError(null);
    try {
      const response = await fetch(
        `/api/scans/${encodeURIComponent(target.scan_id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        const body: unknown = await response.json().catch(() => null);
        const detail =
          body !== null &&
          typeof body === "object" &&
          "detail" in body &&
          typeof body.detail === "string"
            ? body.detail
            : "The scan could not be deleted.";
        throw new Error(detail);
      }
      navigate({ page: "scans" });
    } catch (deleteError) {
      setActionError(
        deleteError instanceof Error
          ? deleteError.message
          : "Unable to delete scan.",
      );
    } finally {
      setIsDeleting(false);
    }
  }

  if (loadError && scan === null) {
    return (
      <div className="page page-wide">
        <Breadcrumb current={scanId} navigate={navigate} />
        <div className="card empty-state">
          <h1>Scan not found</h1>
          <p>{loadError} Check the scan ID, or choose a scan from the list.</p>
          <button
            className="button button-secondary"
            onClick={() => navigate({ page: "scans" })}
            type="button"
          >
            <ArrowLeft aria-hidden="true" size={16} />
            Back to scans
          </button>
        </div>
      </div>
    );
  }

  if (scan === null) {
    return (
      <div className="page page-wide">
        <Breadcrumb current={title} navigate={navigate} />
        <p className="empty-row" role="status">
          <LoaderCircle aria-hidden="true" className="spin" size={16} />
          Loading scan…
        </p>
      </div>
    );
  }

  const reportBase = `/api/scans/${encodeURIComponent(scan.scan_id)}/report`;
  const canDelete = !isActive(scan);
  const awaitingGuidance = scan.state === "awaiting_guidance";

  return (
    <div className="page page-wide">
      <Breadcrumb current={title} navigate={navigate} />
      <header className="page-header scan-header">
        <div className="page-title">
          <div className="title-row">
            <ScanTitle
              onRename={(name) => {
                writeScanNote(scan.scan_id, { name });
                setTitle(scanTitle(scan.scan_id, scan.target_url));
              }}
              status={<StatusPill state={scan.state} />}
              title={title}
            />
          </div>
          <p className="mono target-url">{scan.target_url}</p>
        </div>
        <div className="page-actions">
          {awaitingGuidance ? null : isActive(scan) ? (
            <CancelScanButton
              onError={setActionError}
              onUpdated={setScan}
              scan={scan}
              scanId={scan.scan_id}
            />
          ) : (
            <>
              <a className="button button-primary" href={`${reportBase}/json`}>
                Download JSON
              </a>
              <a
                className="button button-secondary"
                href={`${reportBase}/html`}
                rel="noreferrer"
                target="_blank"
              >
                Open HTML report
              </a>
              <button
                className="button button-secondary"
                disabled={isDeleting || !canDelete}
                onClick={() => void deleteScan(scan)}
                type="button"
              >
                {isDeleting ? "Deleting…" : "Delete scan"}
              </button>
            </>
          )}
          <button
            className="button button-primary"
            onClick={() => navigate({ page: "new" })}
            type="button"
          >
            New scan
          </button>
        </div>
      </header>

      {actionError && (
        <p className="form-error" role="alert">
          {actionError}
        </p>
      )}
      {scan.state === "failed" && (
        <p className="notice notice-danger" role="alert">
          <TriangleAlert aria-hidden="true" size={16} />
          <span>
            <strong>The scan stopped before completing.</strong>{" "}
            {scan.error ?? ""}
          </span>
        </p>
      )}
      {scan.state === "cancelled" && (
        <p className="notice notice-neutral">
          <Ban aria-hidden="true" size={16} />
          This scan was cancelled. Checks that finished before cancelling are
          listed below.
        </p>
      )}

      {awaitingGuidance ? (
        <GuidancePanel onSubmitted={refresh} scan={scan} />
      ) : (
        <>
          <div aria-label="Scan sections" className="tabs" role="tablist">
            {tabs.map((tab) => (
              <button
                aria-controls={`panel-${tab.id}`}
                aria-selected={activeTab === tab.id}
                className="tab"
                id={`tab-${tab.id}`}
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                role="tab"
                type="button"
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div
            aria-labelledby={`tab-${activeTab}`}
            className="scan-body"
            id={`panel-${activeTab}`}
            role="tabpanel"
          >
            <div className="scan-main">
              {activeTab === "findings" && (
                <>
                  {isActive(scan) && <ScanProgress scan={scan} />}
                  <FindingsSummary scan={scan} />
                </>
              )}
              {activeTab === "evidence" && <EvidenceTab scan={scan} />}
              {activeTab === "ai" && <AiDiscoveryTab scan={scan} />}
              {activeTab === "report" && (
                <ReportTab
                  canDelete={canDelete}
                  isDeleting={isDeleting}
                  onDelete={() => void deleteScan(scan)}
                  reportBase={reportBase}
                  scan={scan}
                />
              )}
            </div>
            <ScanDetails scan={scan} />
          </div>
        </>
      )}
    </div>
  );
}

function ScanTitle({
  title,
  status,
  onRename,
}: {
  title: string;
  status: ReactNode;
  onRename: (name: string) => void;
}) {
  const [isEditing, setIsEditing] = useState(false);
  const [draft, setDraft] = useState(title);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isEditing) inputRef.current?.select();
  }, [isEditing]);

  if (isEditing) {
    return (
      <form
        className="rename-form"
        onSubmit={(event) => {
          event.preventDefault();
          onRename(draft.trim());
          setIsEditing(false);
        }}
      >
        <label className="visually-hidden" htmlFor="scan-rename">
          Scan name
        </label>
        <input
          id="scan-rename"
          onChange={(event) => setDraft(event.target.value)}
          ref={inputRef}
          value={draft}
        />
        <button aria-label="Save name" className="icon-button" type="submit">
          <Check aria-hidden="true" size={16} />
        </button>
        <button
          aria-label="Cancel renaming"
          className="icon-button"
          onClick={() => setIsEditing(false)}
          type="button"
        >
          <X aria-hidden="true" size={16} />
        </button>
        {status}
      </form>
    );
  }

  return (
    <>
      <h1 className="scan-title">{title}</h1>
      {status}
      <button
        aria-label="Rename scan"
        className="icon-button rename-button"
        onClick={() => {
          setDraft(title);
          setIsEditing(true);
        }}
        type="button"
      >
        <Pencil aria-hidden="true" size={15} />
      </button>
    </>
  );
}

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
      className="button button-secondary"
      disabled={cancellationPending}
      onClick={() => void cancelScan()}
      type="button"
    >
      {cancellationPending ? "Cancelling…" : "Cancel scan"}
    </button>
  );
}

// ---- Live progress ----------------------------------------------------------

const phaseSteps = [
  { id: "discovering", label: "Find sign-in" },
  { id: "verifying", label: "Verify session" },
  { id: "checking", label: "Run checks" },
  { id: "completed", label: "Report" },
];

function phaseIndex(phase?: string): number {
  if (!phase) return 0;
  if (phase.startsWith("discover") || phase === "created") return 0;
  const index = phaseSteps.findIndex((step) => step.id === phase);
  return index === -1 ? 0 : index;
}

function ScanProgress({ scan }: { scan: ScanStatus }) {
  const current = phaseIndex(scan.phase);
  const progress = scan.execution_progress;
  const planned = readScanNotes()[scan.scan_id]?.checks ?? [];
  const completed = new Set(progress?.completed_checks ?? []);
  const checkIds = Array.from(
    new Set([
      ...planned,
      ...(progress?.completed_checks ?? []),
      ...(progress?.active_check ? [progress.active_check] : []),
    ]),
  );
  const tokens =
    (scan.total_input_tokens ?? 0) + (scan.total_output_tokens ?? 0);

  return (
    <section aria-live="polite" className="card progress-card">
      <div className="card-heading">
        <h2 className="card-title">Scan in progress</h2>
        {scan.phase && (
          <span className="count-label">
            Phase: {scan.phase.replaceAll("_", " ")}
          </span>
        )}
      </div>
      <ol className="stepper">
        {phaseSteps.map((step, index) => (
          <li
            className={
              index < current
                ? "step-done"
                : index === current
                  ? "step-current"
                  : "step-pending"
            }
            key={step.id}
          >
            <span className="step-marker" aria-hidden="true">
              {index < current ? <Check size={13} /> : index + 1}
            </span>
            {step.label}
          </li>
        ))}
      </ol>

      {checkIds.length > 0 && (
        <ul className="check-progress">
          {checkIds.map((checkId) => {
            const info = checkInfo(checkId);
            const isDone = completed.has(checkId);
            const isRunning = progress?.active_check === checkId;
            return (
              <li key={checkId}>
                {isDone ? (
                  <CircleCheck
                    aria-hidden="true"
                    className="icon-done"
                    size={16}
                  />
                ) : isRunning ? (
                  <LoaderCircle
                    aria-hidden="true"
                    className="spin icon-running"
                    size={16}
                  />
                ) : (
                  <span aria-hidden="true" className="icon-pending" />
                )}
                <span>{info?.code}</span>
                <span>{info?.label ?? checkId}</span>
                <span className="subtle">
                  {isDone ? "Done" : isRunning ? "Running" : "Waiting"}
                </span>
              </li>
            );
          })}
        </ul>
      )}

      {(scan.discovery_mode === "bedrock" ||
        (scan.decision_count ?? 0) > 0) && (
        <dl className="inline-stats">
          <div>
            <dt>AI decisions</dt>
            <dd>{scan.decision_count ?? 0}</dd>
          </div>
          <div>
            <dt>Model calls</dt>
            <dd>{scan.model_request_count ?? 0}</dd>
          </div>
          <div>
            <dt>Tokens</dt>
            <dd>{tokens.toLocaleString()}</dd>
          </div>
          <div>
            <dt>AI cost</dt>
            <dd>{formatUsd(scan.estimated_cost_usd)}</dd>
          </div>
          {(scan.unresolved_reservations_usd ?? 0) > 0 && (
            <div>
              <dt>Reserved</dt>
              <dd>{formatUsd(scan.unresolved_reservations_usd)}</dd>
            </div>
          )}
        </dl>
      )}
      <p className="card-help">
        {scan.event_count.toLocaleString()} events and {scan.evidence_count}{" "}
        evidence packages recorded so far.
      </p>
    </section>
  );
}

// ---- Findings ---------------------------------------------------------------

const tileRatings: Rating[] = ["critical", "high", "medium", "low", "passed"];

function FindingsSummary({ scan }: { scan: ScanStatus }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const counts = countRatings(scan.results);
  const unrated = counts.inconclusive + counts.other;
  const rows = scan.results
    .map((result) => ({
      result,
      rating: ratingFor(result.check_id, result.outcome),
      info: checkInfo(result.check_id),
    }))
    .sort(
      (a, b) =>
        compareRatings(a.rating, b.rating) ||
        (a.info?.code ?? "").localeCompare(b.info?.code ?? ""),
    );
  const total = scan.results.length;
  const barRatings = [...tileRatings, "inconclusive", "other"] as Rating[];
  const barLabel = barRatings
    .filter((rating) => counts[rating] > 0)
    .map((rating) => `${counts[rating]} ${ratingLabels[rating]}`)
    .join(", ");

  if (total === 0) {
    return (
      <section className="card empty-state">
        <h2>No results yet</h2>
        <p>
          {isActive(scan)
            ? "Findings appear here as each check finishes."
            : "This scan finished without recording any check results."}
        </p>
      </section>
    );
  }

  return (
    <>
      <section className="card severity-card">
        <h2 className="card-label">Severity counts</h2>
        <div
          aria-label={`Severity: ${barLabel}`}
          className="severity-bar"
          role="img"
        >
          {barRatings
            .filter((rating) => counts[rating] > 0)
            .map((rating) => (
              <span
                className={`severity-segment rating-${rating}`}
                key={rating}
                style={{ flexGrow: counts[rating] }}
              />
            ))}
        </div>
      </section>

      <ul className="severity-tiles">
        {tileRatings.map((rating) => (
          <li className={`severity-tile tile-${rating}`} key={rating}>
            <span className="tile-label">{ratingLabels[rating]}</span>
            <span className="tile-count">{counts[rating]}</span>
          </li>
        ))}
        {unrated > 0 && (
          <li className="severity-tile tile-inconclusive">
            <span className="tile-label">Inconclusive</span>
            <span className="tile-count">{unrated}</span>
          </li>
        )}
      </ul>

      <section aria-label="Findings" className="card table-card">
        <table className="data-table findings-table">
          <colgroup>
            <col className="col-severity" />
            <col className="col-code" />
            <col />
            <col className="col-ref" />
            <col className="col-result" />
            <col className="col-chevron" />
          </colgroup>
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col">Code</th>
              <th scope="col">Check</th>
              <th scope="col">OWASP reference</th>
              <th scope="col">Result</th>
              <th scope="col">
                <span className="visually-hidden">Details</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ result, rating, info }, index) => {
              const rowKey = result.result_id ?? `${result.check_id}-${index}`;
              const isOpen = expanded === rowKey;
              const label = info
                ? `${info.code} ${info.label}`
                : result.check_id;
              return (
                <Fragment key={rowKey}>
                  <tr
                    className={`clickable-row ${isOpen ? "row-open" : ""}`}
                    onClick={() => setExpanded(isOpen ? null : rowKey)}
                  >
                    <td>
                      <RatingBadge rating={rating} />
                    </td>
                    <td className="nowrap">{info?.code ?? "—"}</td>
                    <td>
                      <h3 className="cell-title">
                        {info?.label ?? result.check_id}
                      </h3>
                      <p aria-hidden="true" className="compact-meta">
                        <span className="subtle">{result.owasp_reference}</span>
                        <span className="clamp-2">{result.explanation}</span>
                      </p>
                    </td>
                    <td className="nowrap">{result.owasp_reference}</td>
                    <td className="result-cell">
                      <span className="clamp-2">{result.explanation}</span>
                    </td>
                    <td className="chevron-cell">
                      <button
                        aria-expanded={isOpen}
                        aria-label={`Details for ${label}`}
                        className="icon-button"
                        onClick={(event) => {
                          event.stopPropagation();
                          setExpanded(isOpen ? null : rowKey);
                        }}
                        type="button"
                      >
                        <ChevronDown
                          aria-hidden="true"
                          className={isOpen ? "rotated" : undefined}
                          size={20}
                          strokeWidth={2.25}
                        />
                      </button>
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="detail-row">
                      <td colSpan={6}>
                        <FindingDetail
                          info={info}
                          rating={rating}
                          result={result}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </section>
    </>
  );
}

function FindingDetail({
  result,
  rating,
  info,
}: {
  result: ScanResult;
  rating: Rating;
  info: ReturnType<typeof checkInfo>;
}) {
  const limitations = result.coverage_limitations ?? [];
  return (
    <div className="finding-detail">
      <div>
        <h4>What we observed</h4>
        <p>{result.explanation}</p>
        <p className="subtle">
          Outcome: {outcomeLabel(result.outcome)}
          {rating !== "passed" && rating !== "inconclusive" && info
            ? ` · ${ratingLabels[rating]} severity`
            : ""}
        </p>
        {checkDetail(result.check_id) && (
          <p>
            <a href={routeHash({ page: "check", checkId: result.check_id })}>
              How this check works
            </a>
          </p>
        )}
      </div>
      {info && result.outcome === "finding_confirmed" && (
        <div>
          <h4>Recommendation</h4>
          <p>
            {info.recommendation}{" "}
            <span className="subtle">OWASP {info.reference}</span>
          </p>
        </div>
      )}
      {limitations.length > 0 && (
        <div>
          <h4>Coverage limits</h4>
          <ul>
            {limitations.map((limitation) => (
              <li key={limitation}>{limitation}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function ScanDetails({ scan }: { scan: ScanStatus }) {
  const engine = scan.provenance?.actual_engine ?? scan.discovery_mode;
  const model = modelName(scan.provenance?.model_id);
  const discovery =
    engine === "bedrock"
      ? `Amazon Bedrock${model ? ` - ${model}` : ""}`
      : engine === "rules"
        ? "Deterministic rules"
        : "Not started";
  const profile =
    scan.profile_source === "guided"
      ? "guided (sign-in controls confirmed by a person)"
      : scan.profile_source === "automatic"
        ? "automatic"
        : null;
  const usage = scan.usage;
  const tokens =
    (usage?.input_tokens ?? scan.total_input_tokens ?? 0) +
    (usage?.output_tokens ?? scan.total_output_tokens ?? 0);

  return (
    <aside aria-labelledby="details-title" className="card details-card">
      <h2 className="card-title" id="details-title">
        Scan details
      </h2>
      <dl className="details-list">
        <div>
          <dt>Target</dt>
          <dd className="mono">{scan.target_url ?? "—"}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{stateLabels[scan.state] ?? scan.state}</dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>{formatDate(scan.started_at ?? scan.created_at)}</dd>
        </div>
        <div>
          <dt>Duration</dt>
          <dd>
            {isActive(scan)
              ? "In progress"
              : formatDuration(scan.started_at, scan.finished_at)}
          </dd>
        </div>
        <div>
          <dt>Discovery</dt>
          <dd>
            {discovery}
            {profile ? `, ${profile}` : ""}
          </dd>
        </div>
        {tokens > 0 && (
          <div>
            <dt>AI usage</dt>
            <dd>{tokens.toLocaleString()} tokens</dd>
          </div>
        )}
        {usage && !usage.accounting_error && usage.limit_usd && (
          <div>
            <dt>Cost</dt>
            <dd>
              {formatUsd(usage.settled_cost_usd)} of a{" "}
              {formatUsd(usage.limit_usd, 2)} budget
            </dd>
          </div>
        )}
        <div>
          <dt>Evidence</dt>
          <dd>
            {scan.evidence_count} evidence packages,{" "}
            {scan.event_count.toLocaleString()} recorded events
          </dd>
        </div>
        <div>
          <dt>Scan ID</dt>
          <dd className="mono small">{scan.scan_id}</dd>
        </div>
      </dl>
    </aside>
  );
}

// ---- Other tabs -------------------------------------------------------------

type EvidenceReport = {
  metadata?: { selected_checks?: unknown };
  evidence?: EvidenceItem[];
  results?: ScanResult[];
};

// One check as the HTML report shows it: its latest result and evidence
// package. Mirrors _check_rows in backend/authflowguard/reports.py.
type EvidenceRow = {
  checkId: string;
  result: ScanResult | undefined;
  evidence: EvidenceItem | undefined;
  limitations: string[];
};

function evidenceRows(
  report: EvidenceReport,
  fallbackResults: ScanResult[],
): EvidenceRow[] {
  const results = report.results ?? fallbackResults;
  const evidence = report.evidence ?? [];
  const resultsByCheck = new Map(
    results.map((result) => [result.check_id, result]),
  );
  const evidenceByCheck = new Map(
    evidence.map((item) => [item.check_id, item]),
  );
  const selected = Array.isArray(report.metadata?.selected_checks)
    ? report.metadata.selected_checks.map(String)
    : [];
  const order = checkCatalog.map((check) => check.id);
  const position = (checkId: string) => {
    const index = order.indexOf(checkId);
    return index === -1 ? order.length : index;
  };
  const checkIds = [
    ...new Set([
      ...selected,
      ...resultsByCheck.keys(),
      ...evidenceByCheck.keys(),
    ]),
  ].sort((a, b) => position(a) - position(b));
  return checkIds.map((checkId) => {
    const result = resultsByCheck.get(checkId);
    const item = evidenceByCheck.get(checkId);
    return {
      checkId,
      result,
      evidence: item,
      limitations: [
        ...new Set([
          ...(result?.coverage_limitations ?? []),
          ...(item?.coverage?.limitations ?? []),
        ]),
      ],
    };
  });
}

function EvidenceTab({ scan }: { scan: ScanStatus }) {
  const [report, setReport] = useState<EvidenceReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scan.report_available) return;
    let requestIsActive = true;
    void fetch(`/api/scans/${encodeURIComponent(scan.scan_id)}/report/json`)
      .then(async (response) => {
        if (!response.ok) throw new Error("The evidence could not be loaded.");
        return (await response.json()) as EvidenceReport;
      })
      .then((loaded) => {
        if (requestIsActive) setReport(loaded);
      })
      .catch((loadError: unknown) => {
        if (requestIsActive)
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load evidence.",
          );
      });
    return () => {
      requestIsActive = false;
    };
  }, [scan.scan_id, scan.report_available]);

  if (!scan.report_available) {
    return (
      <section className="card empty-state">
        <h2>Evidence appears when the scan finishes</h2>
        <p>
          {scan.evidence_count} evidence packages and {scan.event_count} events
          are recorded so far.
        </p>
      </section>
    );
  }
  if (error) return <p className="form-error">{error}</p>;
  if (report === null)
    return (
      <p className="empty-row" role="status">
        Loading evidence…
      </p>
    );

  const rows = evidenceRows(report, scan.results);
  if (rows.length === 0) {
    return (
      <section className="card empty-state">
        <h2>No results have been saved</h2>
        <p>This scan finished without recording a result for any check.</p>
      </section>
    );
  }

  return (
    <div className="evidence-list">
      {rows.map((row) => (
        <EvidenceCard key={row.checkId} row={row} />
      ))}
    </div>
  );
}

function EvidenceCard({ row }: { row: EvidenceRow }) {
  const { checkId, result, evidence, limitations } = row;
  const info = checkInfo(checkId);
  const severity = reportSeverity(checkId, result?.outcome);
  const attempted = evidence?.coverage?.attempted_steps ?? [];
  const completed = evidence?.coverage?.completed_steps ?? [];
  // Attempted steps in order, then any completed step not listed as attempted.
  const steps = [...new Set([...attempted, ...completed])];
  const comparisons = evidence?.control_comparisons ?? [];
  const errors = evidence?.errors ?? [];
  const eventCount = evidence?.event_ids?.length ?? 0;
  const fields: { label: string; value: ReactNode }[] = [
    {
      label: "Check",
      value: (
        <>
          {info?.code ? `${info.code} ` : ""}
          <span className="mono">{checkId}</span>
        </>
      ),
    },
    { label: "Status", value: reportStatus(result?.outcome) },
    {
      label: "Severity",
      value:
        severity === "info" ? (
          "Info"
        ) : severity === "n/a" ? (
          "N/A"
        ) : (
          <RatingBadge rating={severity === "unrated" ? "other" : severity} />
        ),
    },
    {
      label: "Outcome",
      value: <span className="mono">{result?.outcome ?? "not_run"}</span>,
    },
    {
      label: "Summary",
      value: result?.explanation ?? "No result was recorded for this check.",
    },
    {
      label: "OWASP reference",
      value: result?.owasp_reference || info?.reference || "—",
    },
    { label: "Recommendation", value: info?.recommendation ?? "—" },
    {
      label: "Evidence package",
      value: evidence ? (
        <span className="mono">{evidence.evidence_id}</span>
      ) : (
        "—"
      ),
    },
    { label: "Analyser version", value: result?.analyser_version || "—" },
    { label: "Recorded at", value: formatDate(result?.created_at) },
  ];
  const hasGroups =
    comparisons.length > 0 || limitations.length > 0 || errors.length > 0;

  return (
    <section
      aria-labelledby={`evidence-${checkId}`}
      className="card evidence-card"
    >
      <div className="card-heading">
        <h2 className="card-title" id={`evidence-${checkId}`}>
          <span className="subtle">{info?.code}</span> {info?.label ?? checkId}
        </h2>
        {result ? (
          <RatingBadge rating={ratingFor(result.check_id, result.outcome)} />
        ) : (
          <span className="rating-badge rating-other">Not run</span>
        )}
      </div>
      <p className="subtle">
        {eventCount} recorded events · {completed.length} of {attempted.length}{" "}
        steps completed
      </p>
      <dl className="evidence-fields">
        {fields.map((field) => (
          <div key={field.label}>
            <dt>{field.label}</dt>
            <dd>{field.value}</dd>
          </div>
        ))}
      </dl>
      {hasGroups && (
        <div className="evidence-groups">
          {comparisons.length > 0 && (
            <EvidenceList items={comparisons} title="Controls compared" />
          )}
          {limitations.length > 0 && (
            <EvidenceList items={limitations} title="Coverage limitations" />
          )}
          {errors.length > 0 && (
            <EvidenceList items={errors} title="Execution errors" />
          )}
        </div>
      )}
      {steps.length > 0 && (
        <div className="evidence-group">
          <h3>Steps</h3>
          <ul className="step-list">
            {steps.map((step) => {
              const done = completed.includes(step);
              return (
                <li className={done ? "step-ok" : "step-missed"} key={step}>
                  {done ? (
                    <CircleCheck aria-hidden="true" size={15} />
                  ) : (
                    <CircleDashed aria-hidden="true" size={15} />
                  )}
                  <span>{step}</span>
                  <small>{done ? "Completed" : "Not completed"}</small>
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {evidence ? (
        <details className="disclosure snapshot">
          <summary>
            <ChevronDown aria-hidden="true" size={16} />
            Evidence snapshot
          </summary>
          <pre className="snapshot-json">
            {JSON.stringify(sortedKeys(evidence.observations ?? {}), null, 2)}
          </pre>
        </details>
      ) : (
        <p className="subtle">No evidence package was saved for this check.</p>
      )}
    </section>
  );
}

// The report prints observations with sorted keys; match it so the two read
// the same.
function sortedKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortedKeys);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, entry]) => [key, sortedKeys(entry)]),
    );
  }
  return value;
}

function EvidenceList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="evidence-group">
      <h3>{title}</h3>
      <ul>
        {items.map((item, index) => (
          <li key={`${index}-${item}`}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

const engineLabels: Record<string, string> = {
  bedrock: "Amazon Bedrock",
  rules: "Deterministic rules",
};

const modeLabels: Record<string, string> = {
  bedrock: "Bedrock AI discovery",
  rules: "Deterministic rules",
};

const usageSourceLabels: Record<string, string> = {
  live: "Measured from Amazon Bedrock",
  mock: "Simulated (no AWS calls)",
  none: "No model calls",
};

const profileLabels: Record<string, string> = {
  automatic: "Found automatically",
  guided: "Guided (confirmed by a person)",
};

function AiDiscoveryTab({ scan }: { scan: ScanStatus }) {
  const provenance = scan.provenance;
  const engine = provenance?.actual_engine ?? scan.discovery_mode ?? "rules";
  const model = modelName(provenance?.model_id);
  const engineLabel = `${engineLabels[engine] ?? engine}${
    engine === "bedrock" && model ? ` (${model})` : ""
  }`;
  const mode = provenance?.requested_mode ?? scan.discovery_mode ?? "rules";
  const usageSource = provenance?.usage_source ?? "none";
  const items: { label: string; value: ReactNode }[] = [
    { label: "Requested mode", value: modeLabels[mode] ?? mode },
    { label: "Engine used", value: engineLabel },
    {
      label: "Model",
      value: provenance?.model_id ? (
        <span className="mono">{provenance.model_id}</span>
      ) : (
        "None"
      ),
    },
    {
      label: "Sign-in profile",
      value: scan.profile_source
        ? (profileLabels[scan.profile_source] ?? scan.profile_source)
        : "Not verified",
    },
    {
      label: "Saved profile reused",
      value: provenance?.reused_profile ? "Yes" : "No",
    },
    {
      label: "Decisions / model calls",
      value: `${scan.decision_count ?? 0} / ${scan.model_request_count ?? 0}`,
    },
    {
      label: "Tokens",
      value: `${(scan.total_input_tokens ?? 0).toLocaleString()} in / ${(scan.total_output_tokens ?? 0).toLocaleString()} out`,
    },
    { label: "Inference spend", value: formatUsd(scan.estimated_cost_usd) },
    {
      label: "Usage figures",
      value: usageSourceLabels[usageSource] ?? usageSource,
    },
  ];

  return (
    <section className="card">
      <div className="card-heading">
        <h2 className="card-title">Discovery provenance</h2>
        <span className="engine-pill">{engineLabel}</span>
      </div>
      <dl className="fact-grid">
        {items.map((item) => (
          <div key={item.label}>
            <dt>{item.label}</dt>
            <dd>{item.value}</dd>
          </div>
        ))}
      </dl>
      {scan.stop_reason && (
        <p className="subtle">AI stopped because: {scan.stop_reason}</p>
      )}
      <p className="notice notice-neutral">
        <CircleCheck aria-hidden="true" size={16} />
        <span>
          AI only suggests which controls to use; deterministic analysers decide
          every verdict from recorded evidence. Passwords and other runtime
          secrets are never sent to the model.
        </span>
      </p>
    </section>
  );
}

function ReportTab({
  scan,
  reportBase,
  canDelete,
  isDeleting,
  onDelete,
}: {
  scan: ScanStatus;
  reportBase: string;
  canDelete: boolean;
  isDeleting: boolean;
  onDelete: () => void;
}) {
  return (
    <section aria-labelledby="report-title" className="card report-panel">
      <h2 className="card-title report-panel-title" id="report-title">
        Reports
      </h2>
      <div className="report-row">
        <FileText aria-hidden="true" className="report-icon" size={20} />
        <div>
          <h3>HTML report</h3>
          <p className="card-help">
            Executive summary, pass/fail per check, severity, OWASP
            recommendations and evidence. Printable.
          </p>
        </div>
        <a
          className="button button-secondary"
          href={`${reportBase}/html`}
          rel="noreferrer"
          target="_blank"
        >
          <ExternalLink aria-hidden="true" size={16} />
          Open HTML report
        </a>
      </div>
      <div className="report-row">
        <FileJson aria-hidden="true" className="report-icon" size={20} />
        <div>
          <h3>JSON report</h3>
          <p className="card-help">
            Every result, evidence package and scan setting, for other tools.
          </p>
        </div>
        <a className="button button-secondary" href={`${reportBase}/json`}>
          <Download aria-hidden="true" size={16} />
          Download JSON
        </a>
      </div>
      <div className="report-row report-danger">
        <Trash2 aria-hidden="true" className="report-icon" size={20} />
        <div>
          <h3>Delete this scan</h3>
          <p className="card-help">
            Permanently removes {scan.evidence_count} evidence packages, the
            results and both reports from this computer.
          </p>
        </div>
        <button
          className="button button-danger"
          disabled={isDeleting || !canDelete}
          onClick={onDelete}
          type="button"
        >
          {isDeleting ? "Deleting…" : "Delete scan"}
        </button>
      </div>
    </section>
  );
}

// ---- Guided discovery (inside a paused scan) ---------------------------------

function GuidancePanel({
  scan,
  onSubmitted,
}: {
  scan: ScanStatus;
  onSubmitted: () => void;
}) {
  const scanId = scan.scan_id;
  const [observation, setObservation] = useState<GuidanceObservation | null>(
    null,
  );
  const [observationUrl, setObservationUrl] = useState(scan.target_url ?? "");
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
  // The login proof starts as the scan's own values. A field is sent only
  // when the developer changes it; blank or unchanged keeps the scan's value.
  const scanVerification = {
    protectedResource: scan.verification?.protected_resource ?? "",
    markerSelector: scan.verification?.account_marker_selector ?? "",
    markerDescription: scan.verification?.account_marker_description ?? "",
  };
  const [protectedResource, setProtectedResource] = useState(
    scanVerification.protectedResource,
  );
  const [markerSelector, setMarkerSelector] = useState(
    scanVerification.markerSelector,
  );
  const [markerDescription, setMarkerDescription] = useState(
    scanVerification.markerDescription,
  );
  const changedValue = (draft: string, original: string) => {
    const value = draft.trim();
    return value && value !== original ? value : null;
  };
  const effectiveSelector =
    markerSelector.trim() || scanVerification.markerSelector;
  const effectiveResource =
    protectedResource.trim() || scanVerification.protectedResource;
  const [isObserving, setIsObserving] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cancelState, setCancelState] = useState<ScanStatus>(scan);
  const [suggestionSource, setSuggestionSource] =
    useState<SuggestionSource | null>(null);
  // The developer's answers about the page's other links: a control id, or
  // "" for none, and where a pre-filled answer came from.
  const [linkChoices, setLinkChoices] = useState<Record<LinkRole, LinkChoice>>({
    registration_link: { controlId: "", source: null },
    reset_link: { controlId: "", source: null },
  });

  const current = cancelState.cancel_requested ? cancelState : scan;
  const canAct =
    current.state === "awaiting_guidance" && current.cancel_requested !== true;

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
      setLinkChoices(suggestedLinkChoices(observed));
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
      const resourceChange = changedValue(
        protectedResource,
        scanVerification.protectedResource,
      );
      const selectorChange = changedValue(
        markerSelector,
        scanVerification.markerSelector,
      );
      const descriptionChange = changedValue(
        markerDescription,
        scanVerification.markerDescription,
      );
      const response = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}/guidance`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            actions: payload,
            ...(resourceChange ? { protected_resource: resourceChange } : {}),
            ...(selectorChange
              ? { account_marker_selector: selectorChange }
              : {}),
            ...(descriptionChange
              ? { account_marker_description: descriptionChange }
              : {}),
            ...(observation
              ? {
                  feature_links: {
                    registration_link:
                      linkChoices.registration_link.controlId || null,
                    reset_link: linkChoices.reset_link.controlId || null,
                  },
                }
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

  const controlOptions = (filter: (control: SafeControl) => boolean) =>
    (observation?.controls ?? []).filter(filter).map((control) => (
      <option
        key={control.observed_control_id}
        value={control.observed_control_id}
      >
        {controlLabel(control)}
      </option>
    ));

  return (
    <form className="guidance" onSubmit={submitGuidance}>
      <section
        className="notice notice-action"
        aria-labelledby="guidance-title"
      >
        <TriangleAlert aria-hidden="true" size={18} />
        <div>
          <h2 id="guidance-title">Help us log in</h2>
          <p>
            The scan paused because it could not identify the sign-in controls
            with confidence. Find the login page, confirm the username field,
            password field and sign-in button, and AuthFlowGuard verifies them
            in separate signed-in and signed-out browser sessions. Your test
            account details are reused automatically.
          </p>
          {scan.error && <p className="form-error">{scan.error}</p>}
        </div>
      </section>

      <div className="guidance-grid">
        <section className="card guidance-step">
          <h3 className="step-title">
            <span className="step-number">1</span>Find the login page
          </h3>
          <div className="field">
            <label htmlFor="observation-url">Login page address</label>
            <div className="input-row">
              <input
                id="observation-url"
                onChange={(event) => setObservationUrl(event.target.value)}
                required
                type="url"
                value={observationUrl}
              />
              <button
                className="button button-secondary"
                disabled={isObserving || !canAct}
                onClick={() => void observePage()}
                type="button"
              >
                {isObserving ? (
                  <>
                    <LoaderCircle
                      aria-hidden="true"
                      className="spin"
                      size={16}
                    />
                    Finding fields…
                  </>
                ) : (
                  "Find login fields"
                )}
              </button>
            </div>
            <small>
              Use the login page here if the scan target was only used to
              trigger this help step.
            </small>
          </div>
          <div className="observed">
            <h4>
              Fields and buttons found on this page{" "}
              <span className="count">{observation?.controls.length ?? 0}</span>
            </h4>
            {observation ? (
              <>
                <p className="subtle">
                  {observation.title || "Untitled page"} · {observation.url}
                </p>
                <ul className="observed-controls">
                  {observation.controls.map((control) => (
                    <li key={control.observed_control_id}>
                      <code>{control.observed_control_id}</code>
                      <span>{controlLabel(control)}</span>
                      <small>{control.visible ? "visible" : "hidden"}</small>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p className="subtle">
                Find the login fields to choose from the controls on this page.
              </p>
            )}
          </div>
        </section>

        <section className="card guidance-step">
          <h3 className="step-title">
            <span className="step-number">2</span>Confirm the sign-in controls
          </h3>
          {suggestionSource && (
            <p className="suggestion-note" role="status">
              {suggestionNotes[suggestionSource]}
            </p>
          )}
          <div className="form-stack">
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
                {controlOptions(isUsernameOption)}
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
                {controlOptions(isPasswordOption)}
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
                {controlOptions(isSubmitOption)}
              </select>
            </label>
            {linkQuestions.map(({ role, question, label }) => {
              const source = linkChoices[role].source;
              return (
                <label className="field" key={role}>
                  <span>{question}</span>
                  <select
                    aria-label={label}
                    onChange={(event) => {
                      const controlId = event.target.value;
                      setLinkChoices((currentChoices) => ({
                        ...currentChoices,
                        [role]: { controlId, source: null },
                      }));
                    }}
                    value={linkChoices[role].controlId}
                  >
                    <option value="">None</option>
                    {controlOptions(isLinkOption)}
                  </select>
                  {source && (
                    <small className="suggestion-note">
                      {suggestionNotes[source]}
                    </small>
                  )}
                </label>
              );
            })}
          </div>
        </section>
      </div>

      <section className="card guidance-step">
        <h3 className="step-title">
          <span className="step-number">3</span>Confirm the login proof
        </h3>
        <p className="login-proof">
          {effectiveSelector ? (
            <>
              Login proof: <code>{effectiveSelector}</code>
              {effectiveResource ? (
                <>
                  {" "}
                  on <span className="mono">{effectiveResource}</span>
                </>
              ) : null}
            </>
          ) : (
            "Login proof: the selector and page from New scan are reused."
          )}
        </p>
        <details className="disclosure">
          <summary>
            <ChevronDown aria-hidden="true" size={16} />
            Advanced: change how login is checked
          </summary>
          <p className="card-help">
            Change these only when the New scan values do not describe the
            target; a blank field reuses the scan's value. The selector proves
            sign-in, because a dashboard URL or title alone does not.
          </p>
          <div className="form-grid form-grid-3">
            <div className="field">
              <label htmlFor="guided-protected-resource">
                Protected resource URL
              </label>
              <input
                id="guided-protected-resource"
                onChange={(event) => setProtectedResource(event.target.value)}
                placeholder="Leave blank to reuse the scan's value"
                type="url"
                value={protectedResource}
              />
            </div>
            <div className="field">
              <label htmlFor="guided-marker-selector">
                Authenticated marker selector
              </label>
              <input
                className="mono"
                id="guided-marker-selector"
                onChange={(event) => setMarkerSelector(event.target.value)}
                placeholder="Leave blank to reuse the scan's value"
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
                placeholder="Leave blank to reuse the scan's value"
                value={markerDescription}
              />
            </div>
          </div>
        </details>
      </section>

      <footer className="action-bar">
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="action-buttons">
          <CancelScanButton
            onError={setError}
            onUpdated={setCancelState}
            scan={current}
            scanId={scanId}
          />
          <button
            className="button button-primary"
            disabled={isSubmitting || !canAct}
            type="submit"
          >
            {isSubmitting
              ? "Saving guided flow…"
              : "Save and verify guided flow"}
          </button>
        </div>
      </footer>
    </form>
  );
}

export default App;
