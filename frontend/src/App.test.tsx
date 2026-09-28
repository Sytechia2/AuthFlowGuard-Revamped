import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import App from "./App";

const defaultCapabilities = {
  bedrock_configured: true,
  model_id: "us.anthropic.claude-3-5-haiku-20241022-v1:0",
  model_name: "Claude 3.5 Haiku",
  pricing_configured: true,
  note: "Ready",
  default_limits: {
    maximum_ai_decisions: 40,
    maximum_active_seconds: 900,
    maximum_inference_cost_usd: 0.25,
  },
  server_max_limits: {
    maximum_ai_decisions: 100,
    maximum_active_seconds: 1800,
    maximum_inference_cost_usd: 5.0,
  },
};

type MockRoute = {
  url: string | RegExp;
  method?: string;
  response: unknown;
  status?: number;
};

function setupMockFetch(routes: MockRoute[] = []) {
  const fetchMock = vi
    .fn()
    .mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input.toString();
        const method = init?.method ?? "GET";

        if (url === "/api/health") {
          const healthRoute = routes.find(
            (r) =>
              r.url === "/api/health" && (!r.method || r.method === method),
          );
          if (healthRoute) {
            return {
              ok: (healthRoute.status ?? 200) < 400,
              status: healthRoute.status ?? 200,
              json: async () => healthRoute.response,
            };
          }
          return {
            ok: true,
            status: 200,
            json: async () => ({ status: "ok" }),
          };
        }

        if (url === "/api/capabilities") {
          const capRoute = routes.find(
            (r) =>
              r.url === "/api/capabilities" &&
              (!r.method || r.method === method),
          );
          if (capRoute) {
            return {
              ok: (capRoute.status ?? 200) < 400,
              status: capRoute.status ?? 200,
              json: async () => capRoute.response,
            };
          }
          return {
            ok: true,
            status: 200,
            json: async () => defaultCapabilities,
          };
        }

        const matched = routes.find((r) => {
          const matchUrl =
            typeof r.url === "string" ? r.url === url : r.url.test(url);
          const matchMethod =
            !r.method || r.method.toUpperCase() === method.toUpperCase();
          return matchUrl && matchMethod;
        });

        if (matched) {
          const resp =
            typeof matched.response === "function"
              ? (matched.response as (init?: RequestInit) => unknown)(init)
              : matched.response;
          return {
            ok: (matched.status ?? 200) < 400,
            status: matched.status ?? 200,
            json: async () => resp,
          };
        }

        return { ok: true, status: 200, json: async () => ({}) };
      },
    );

  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function mockHealthResponse(ok: boolean, status: string) {
  setupMockFetch([
    {
      url: "/api/health",
      status: ok ? 200 : 500,
      response: { status },
    },
  ]);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("backend connection status", () => {
  test("shows connected only when the health response is successful", async () => {
    mockHealthResponse(true, "ok");

    render(<App />);

    expect(screen.getByRole("status")).toHaveTextContent("Checking local API");
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Local API online");
    });
    expect(fetch).toHaveBeenCalledWith("/api/health");
  });

  test.each([
    [false, "ok"],
    [true, "unexpected"],
  ])(
    "shows offline for an unusable health response",
    async (responseIsOk, status) => {
      mockHealthResponse(responseIsOk, status);

      render(<App />);

      await waitFor(() => {
        expect(screen.getByRole("status")).toHaveTextContent(
          "Local API offline",
        );
      });
    },
  );

  test("shows offline when the health request fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("connection refused")),
    );

    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Local API offline");
    });
  });
});

describe("setup workflow", () => {
  test("tracks selected checks and prevents continuing with none", async () => {
    mockHealthResponse(true, "ok");
    render(<App />);

    const checkboxes = screen
      .getAllByRole("checkbox")
      .filter((cb) => cb.getAttribute("name") !== "discovery-mode");
    // 6 security checks plus 1 reuse profile checkbox = 7 checkboxes total
    expect(checkboxes.length).toBeGreaterThanOrEqual(6);
    expect(screen.getByText("6 selected")).toBeInTheDocument();

    // uncheck the 6 security checks
    const checkBoxesOnly = screen
      .getAllByRole("checkbox")
      .filter((cb) => !cb.closest(".profile-reuse-setting"));
    for (const checkbox of checkBoxesOnly) {
      fireEvent.click(checkbox);
    }

    expect(screen.getByText("0 selected")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /start local scan/i }),
    ).toBeDisabled();
  });

  test("renders discovery modes, capability banner, and execution limits", async () => {
    setupMockFetch();
    render(<App />);

    await waitFor(() => {
      expect(
        screen.getByRole("radio", { name: /bedrock ai discovery/i }),
      ).toBeInTheDocument();
    });

    expect(
      screen.getByRole("radio", { name: /deterministic rules/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/bedrock online:/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/maximum decisions/i)).toHaveValue(40);
    expect(screen.getByLabelText(/active time limit/i)).toHaveValue(900);
    expect(screen.getByLabelText(/max inference budget/i)).toHaveValue(0.25);
  });

  test("falls back to rules when Bedrock is not configured on backend", async () => {
    setupMockFetch([
      {
        url: "/api/capabilities",
        response: {
          ...defaultCapabilities,
          bedrock_configured: false,
          note: "AWS credentials missing.",
        },
      },
    ]);
    render(<App />);

    await waitFor(() => {
      expect(
        screen.getByText(/bedrock not configured on backend/i),
      ).toBeInTheDocument();
    });

    const rulesRadio = screen.getByRole("radio", {
      name: /deterministic rules/i,
    });
    expect(rulesRadio).toBeChecked();
  });

  test("submits setup and starts a local scan with Bedrock settings", async () => {
    const fetchMock = setupMockFetch([
      {
        url: "/api/scans",
        method: "POST",
        response: { scan_id: "scan-123", state: "created" },
        status: 201,
      },
      {
        url: "/api/scans/scan-123/start",
        method: "POST",
        response: { scan_id: "scan-123", state: "running" },
      },
      {
        url: "/api/scans/scan-123",
        response: {
          scan_id: "scan-123",
          state: "running",
          event_count: 0,
          evidence_count: 0,
          result_count: 0,
          results: [],
        },
      },
    ]);

    render(<App />);

    fireEvent.change(screen.getByLabelText("Target URL"), {
      target: { value: "https://staging.example.test/login" },
    });
    fireEvent.change(screen.getByLabelText("Permitted origins"), {
      target: { value: "https://staging.example.test" },
    });
    fireEvent.change(screen.getByLabelText("Known account username"), {
      target: { value: "developer@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Known account password"), {
      target: { value: "known-password" },
    });
    fireEvent.change(screen.getByLabelText("Nonexistent account username"), {
      target: { value: "missing@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Invalid password"), {
      target: { value: "wrong-password" },
    });
    fireEvent.change(screen.getByLabelText("Protected resource URL"), {
      target: { value: "https://staging.example.test/account" },
    });
    fireEvent.click(screen.getByRole("button", { name: /start local scan/i }));

    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: "Check status" }),
      ).toBeInTheDocument();
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/scans",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/scans/scan-123/start",
      expect.objectContaining({ method: "POST" }),
    );

    const createCall = fetchMock.mock.calls.find(
      ([url]) => url === "/api/scans",
    );
    const payload = JSON.parse(String(createCall?.[1]?.body)) as {
      selected_checks: string[];
      discovery_mode: string;
      reuse_saved_profile: boolean;
      limits: {
        maximum_ai_decisions: number;
        maximum_active_seconds: number;
        maximum_inference_cost_usd: number;
      };
    };
    expect(payload.discovery_mode).toBe("bedrock");
    expect(payload.reuse_saved_profile).toBe(false);
    expect(payload.limits.maximum_ai_decisions).toBe(40);
    expect(payload.selected_checks).toContain("registration_enumeration");
    expect(payload.selected_checks).toContain("reset_request_enumeration");
    expect(payload.selected_checks).not.toContain("reset_enumeration");
  });

  test("opens Discovery for a paused scan and submits guided actions", async () => {
    const fetchMock = setupMockFetch([
      {
        url: "/api/scans",
        method: "POST",
        response: { scan_id: "guided-scan", state: "created" },
        status: 201,
      },
      {
        url: "/api/scans/guided-scan/start",
        method: "POST",
        response: { scan_id: "guided-scan", state: "running" },
      },
      {
        url: "/api/scans/guided-scan",
        response: {
          scan_id: "guided-scan",
          state: "awaiting_guidance",
          target_url: "https://staging.example.test/login",
          error: "Expected one submit control, found 2",
          event_count: 0,
          evidence_count: 0,
          result_count: 0,
          results: [],
        },
      },
      {
        url: "/api/scans/guided-scan/guidance/observe",
        method: "POST",
        response: {
          // The observed page URL has no fragment, like the backend's
          // record of a hash-routed single-page app.
          url: "https://staging.example.test/",
          title: "Sign in",
          controls: [
            {
              observed_control_id: "control-5",
              tag: "input",
              id: "username",
              name: "username",
              type: "email",
              placeholder: null,
              autocomplete: "username",
              aria_label: null,
              value_present: false,
              visible: true,
            },
            {
              observed_control_id: "control-6",
              tag: "input",
              id: "password",
              name: "password",
              type: "password",
              placeholder: null,
              autocomplete: "current-password",
              aria_label: null,
              value_present: false,
              visible: true,
            },
            {
              observed_control_id: "control-7",
              tag: "button",
              id: null,
              name: null,
              type: "submit",
              placeholder: null,
              autocomplete: null,
              aria_label: null,
              value_present: null,
              visible: true,
            },
          ],
        },
      },
      {
        url: "/api/scans/guided-scan/guidance",
        method: "POST",
        response: {
          scan_id: "guided-scan",
          state: "running",
        },
      },
    ]);

    render(<App />);

    fireEvent.change(screen.getByLabelText("Target URL"), {
      target: { value: "https://staging.example.test/login" },
    });
    fireEvent.change(screen.getByLabelText("Permitted origins"), {
      target: { value: "https://staging.example.test" },
    });
    fireEvent.change(screen.getByLabelText("Known account username"), {
      target: { value: "developer@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Known account password"), {
      target: { value: "known-password" },
    });
    fireEvent.change(screen.getByLabelText("Nonexistent account username"), {
      target: { value: "missing@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Invalid password"), {
      target: { value: "wrong-password" },
    });
    fireEvent.change(screen.getByLabelText("Protected resource URL"), {
      target: { value: "https://staging.example.test/account" },
    });
    fireEvent.click(screen.getByRole("button", { name: /start local scan/i }));

    await waitFor(() => {
      expect(
        screen.getByRole("button", { name: "Open Discovery" }),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByRole("button", { name: "Cancel scan" }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open Discovery" }));
    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: "Help us log in" }),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByRole("button", { name: "Cancel scan" }),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Login page address"), {
      target: { value: "  https://staging.example.test/#/login  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Find login fields" }));
    await waitFor(() => {
      expect(screen.getByText("control-5")).toBeInTheDocument();
    });
    fireEvent.change(screen.getByLabelText("Username or email field"), {
      target: { value: "control-5" },
    });
    fireEvent.change(screen.getByLabelText("Password field"), {
      target: { value: "control-6" },
    });
    fireEvent.change(screen.getByLabelText("Sign-in button"), {
      target: { value: "control-7" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: /save and verify guided flow/i }),
    );

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scans/guided-scan/guidance",
        expect.objectContaining({ method: "POST" }),
      );
    });
    const requestBody = (url: string) => {
      const call = fetchMock.mock.calls.find(([input]) => input === url) as
        [string, RequestInit] | undefined;
      return JSON.parse(String(call?.[1].body)) as {
        url?: string;
        actions?: { action_type: string; url?: string }[];
      };
    };
    expect(requestBody("/api/scans/guided-scan/guidance/observe").url).toBe(
      "https://staging.example.test/#/login",
    );
    // Replay must open the hash route the user typed, not the app's home page.
    expect(requestBody("/api/scans/guided-scan/guidance").actions?.[0]).toEqual(
      expect.objectContaining({
        action_type: "navigate",
        url: "https://staging.example.test/#/login",
      }),
    );
  });

  test("navigation switches between testing and results views", () => {
    mockHealthResponse(true, "ok");
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: /testing/i }));
    expect(
      screen.getByRole("heading", { name: "No scan is running" }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /results/i }));
    expect(
      screen.getByRole("heading", { name: "Evidence will appear here" }),
    ).toBeInTheDocument();
  });

  test("displays live AI exploration metrics and badges in Testing view", async () => {
    setupMockFetch([
      {
        url: "/api/scans/ai-scan-456",
        response: {
          scan_id: "ai-scan-456",
          state: "running",
          phase: "discovering_auth",
          discovery_mode: "bedrock",
          decision_count: 5,
          model_request_count: 6,
          total_input_tokens: 3500,
          total_output_tokens: 250,
          estimated_cost_usd: 0.0145,
          unresolved_reservations_usd: 0.002,
          provenance: {
            requested_mode: "bedrock",
            actual_engine: "bedrock",
            usage_source: "bedrock_reported",
            reused_profile: false,
            guidance_used: false,
            model_id: "us.anthropic.claude-3-5-haiku-20241022-v1:0",
          },
          event_count: 12,
          evidence_count: 1,
          result_count: 0,
          results: [],
        },
      },
    ]);

    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /results/i }));
    fireEvent.change(screen.getByLabelText("Scan ID"), {
      target: { value: "ai-scan-456" },
    });
    fireEvent.click(screen.getByRole("button", { name: /load results/i }));

    // Switch to Testing tab to view live metrics for this scan
    fireEvent.click(screen.getByRole("button", { name: /testing/i }));

    await waitFor(() => {
      expect(screen.getByText("Phase: discovering auth")).toBeInTheDocument();
      expect(screen.getByText("Engine: bedrock")).toBeInTheDocument();
      expect(screen.getByText("AI Exploration Metrics")).toBeInTheDocument();
      expect(screen.getByText("$0.0145")).toBeInTheDocument();
      expect(screen.getByText("Pending Resv.")).toBeInTheDocument();
    });
  });

  test("loads scan results and exposes offline report links and provenance", async () => {
    setupMockFetch([
      {
        url: "/api/scans",
        response: [],
      },
      {
        url: "/api/scans/scan-123",
        response: {
          scan_id: "scan-123",
          state: "completed",
          event_count: 78,
          evidence_count: 6,
          result_count: 6,
          discovery_mode: "bedrock",
          decision_count: 8,
          model_request_count: 9,
          total_input_tokens: 12000,
          total_output_tokens: 800,
          estimated_cost_usd: 0.0452,
          provenance: {
            requested_mode: "bedrock",
            actual_engine: "bedrock",
            usage_source: "bedrock_reported",
            reused_profile: false,
            guidance_used: false,
            model_id: "us.anthropic.claude-3-5-haiku-20241022-v1:0",
          },
          results: [
            {
              check_id: "login_enumeration",
              outcome: "finding_confirmed",
              owasp_reference: "WSTG-IDNT-04",
              explanation: "Repeatable account differences were observed.",
            },
            {
              check_id: "registration_enumeration",
              outcome: "no_issue_observed",
              owasp_reference: "WSTG-IDNT-04",
              explanation: "Registration responses matched.",
            },
            {
              check_id: "reset_request_enumeration",
              outcome: "inconclusive",
              owasp_reference: "WSTG-IDNT-04",
              explanation: "Reset evidence was incomplete.",
            },
            {
              check_id: "login_throttling",
              outcome: "no_issue_observed",
              owasp_reference: "WSTG-ATHN-03",
              explanation: "The valid login was restricted after failures.",
            },
            {
              check_id: "session_fixation",
              outcome: "no_issue_observed",
              owasp_reference: "WSTG-SESS-03",
              explanation: "The original session was rejected after login.",
            },
            {
              check_id: "logout_invalidation",
              outcome: "no_issue_observed",
              owasp_reference: "WSTG-SESS-06",
              explanation: "The old session was rejected after logout.",
            },
          ],
        },
      },
    ]);

    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /results/i }));
    fireEvent.change(screen.getByLabelText("Scan ID"), {
      target: { value: "scan-123" },
    });
    fireEvent.click(screen.getByRole("button", { name: /load results/i }));

    await waitFor(() => {
      expect(screen.getByText("finding_confirmed")).toBeInTheDocument();
    });
    expect(screen.getByRole("link", { name: "Download JSON" })).toHaveAttribute(
      "href",
      "/api/scans/scan-123/report/json",
    );
    expect(
      screen.getByRole("heading", { name: "CHK-002 registration_enumeration" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", {
        name: "CHK-003 reset_request_enumeration",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "CHK-004 login_throttling" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "CHK-005 session_fixation" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "CHK-006 logout_invalidation" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("no_issue_observed")).toHaveLength(4);
    expect(screen.getByText("inconclusive")).toBeInTheDocument();

    // Verify Discovery Provenance & Offline Assurance
    expect(
      screen.getByText("Discovery provenance & assurance"),
    ).toBeInTheDocument();
    expect(screen.getByText(/offline assurance:/i)).toBeInTheDocument();
    expect(screen.getByText("$0.0452 USD")).toBeInTheDocument();
  });

  test("shows saved runs and loads one without manual ID entry", async () => {
    setupMockFetch([
      {
        url: "/api/scans",
        response: [
          {
            scan_id: "past-scan-123",
            state: "completed",
            target_url: "http://127.0.0.1:8001/login",
            event_count: 78,
            evidence_count: 1,
            result_count: 1,
            results: [],
          },
        ],
      },
      {
        url: "/api/scans/past-scan-123",
        response: {
          scan_id: "past-scan-123",
          state: "completed",
          event_count: 78,
          evidence_count: 1,
          result_count: 1,
          results: [],
        },
      },
    ]);

    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /results/i }));

    await waitFor(() => {
      expect(screen.getByText("past-scan-123")).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: /past-scan-123/ }));

    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: "Scan results" }),
      ).toBeInTheDocument();
    });
    expect(screen.getAllByText("completed")).toHaveLength(2);
  });
});
