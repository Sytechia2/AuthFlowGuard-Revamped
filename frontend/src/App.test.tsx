import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import App from "./App";
import { checkDetail, methodology } from "./checkDetails";

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
  window.location.hash = "";
  window.localStorage.clear();
});

// The app routes by URL hash: #/scans, #/new and #/scans/<id>.
function renderAt(hash: string) {
  window.location.hash = hash;
  return render(<App />);
}

function fillNewScanForm(origin: string, targetUrl: string) {
  fireEvent.change(screen.getByLabelText("Target URL"), {
    target: { value: targetUrl },
  });
  fireEvent.change(screen.getByLabelText("Permitted origins"), {
    target: { value: origin },
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
}

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
    renderAt("#/new");

    const checkBoxes = screen
      .getAllByRole("checkbox")
      .filter((cb) => cb.id.startsWith("check-"));
    expect(checkBoxes).toHaveLength(6);
    expect(screen.getByText("6 selected")).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: "Logout invalidation" }),
    ).toBeChecked();

    for (const checkbox of checkBoxes) {
      fireEvent.click(checkbox);
    }

    expect(screen.getByText("0 selected")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start scan" })).toBeDisabled();
  });

  test("renders discovery modes, capability banner, and execution limits", async () => {
    setupMockFetch();
    renderAt("#/new");

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
    renderAt("#/new");

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

    renderAt("#/new");

    fireEvent.change(screen.getByLabelText("Scan name"), {
      target: { value: "Staging sign-in" },
    });
    fillNewScanForm(
      "https://staging.example.test",
      "https://staging.example.test/login",
    );
    fireEvent.change(screen.getByLabelText("Protected resource URL"), {
      target: { value: "https://staging.example.test/account" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    // The new scan opens on its own page, named as the user typed.
    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: "Scan in progress" }),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByRole("heading", { level: 1, name: "Staging sign-in" }),
    ).toBeInTheDocument();
    expect(window.location.hash).toBe("#/scans/scan-123");

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

    renderAt("#/new");

    fillNewScanForm(
      "https://staging.example.test",
      "https://staging.example.test/login",
    );
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    // A paused scan shows the guided sign-in help on its own page.
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

  function suggestedControl(
    id: string,
    tag: string,
    type: string | null,
    label: string,
  ) {
    return {
      observed_control_id: id,
      tag,
      id: null,
      name: null,
      type,
      placeholder: null,
      autocomplete: null,
      aria_label: label,
      text: null,
      value_present: tag === "input" ? false : null,
      visible: true,
    };
  }

  async function openDiscoveryWithObservation(
    observation: unknown,
    scanFields: Record<string, unknown> = {},
  ) {
    const fetchMock = setupMockFetch([
      {
        url: "/api/scans",
        method: "POST",
        response: { scan_id: "suggested-scan", state: "created" },
        status: 201,
      },
      {
        url: "/api/scans/suggested-scan/start",
        method: "POST",
        response: { scan_id: "suggested-scan", state: "running" },
      },
      {
        url: "/api/scans/suggested-scan",
        response: {
          scan_id: "suggested-scan",
          state: "awaiting_guidance",
          target_url: "https://shop.example.test/#/login",
          error: "Expected one submit control, found 5",
          event_count: 0,
          evidence_count: 0,
          result_count: 0,
          results: [],
          ...scanFields,
        },
      },
      {
        url: "/api/scans/suggested-scan/guidance/observe",
        method: "POST",
        response: observation,
      },
      {
        url: "/api/scans/suggested-scan/guidance",
        method: "POST",
        response: { scan_id: "suggested-scan", state: "running" },
      },
    ]);

    renderAt("#/new");
    fillNewScanForm(
      "https://shop.example.test",
      "https://shop.example.test/#/login",
    );
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));
    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: "Help us log in" }),
      ).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: "Find login fields" }));
    await waitFor(() => {
      expect(screen.getByText("control-6")).toBeInTheDocument();
    });
    return fetchMock;
  }

  const juiceShopLikeControls = [
    suggestedControl("control-2", "input", "text", "Search"),
    suggestedControl("control-3", "button", null, "Add to Basket"),
    suggestedControl("control-5", "input", null, "Login email"),
    suggestedControl("control-6", "input", "password", "Login password"),
    suggestedControl("control-7", "button", "submit", "Login"),
    suggestedControl("control-8", "button", null, "Show password"),
  ];

  test("pre-fills AI-suggested sign-in controls and submits the user's choices", async () => {
    const fetchMock = await openDiscoveryWithObservation({
      url: "https://shop.example.test/",
      title: "Shop",
      controls: juiceShopLikeControls,
      suggested_controls: {
        username: "control-5",
        password: "control-6",
        submit: "control-7",
        source: "ai",
        status: "ai_suggested",
        rejected: [],
      },
    });

    expect(
      screen.getByText("Suggested by AI — check before continuing."),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Username or email field")).toHaveValue(
      "control-5",
    );
    expect(screen.getByLabelText("Password field")).toHaveValue("control-6");
    expect(screen.getByLabelText("Sign-in button")).toHaveValue("control-7");
    // Nothing is sent until the user presses the submit button.
    expect(
      fetchMock.mock.calls.some(
        ([input]) => input === "/api/scans/suggested-scan/guidance",
      ),
    ).toBe(false);

    fireEvent.change(screen.getByLabelText("Sign-in button"), {
      target: { value: "control-8" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: /save and verify guided flow/i }),
    );

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scans/suggested-scan/guidance",
        expect.objectContaining({ method: "POST" }),
      );
    });
    const call = fetchMock.mock.calls.find(
      ([input]) => input === "/api/scans/suggested-scan/guidance",
    ) as [string, RequestInit];
    const body = JSON.parse(String(call[1].body)) as {
      actions: { action_type: string; observed_control_id?: string }[];
    };
    expect(body.actions.map((action) => action.observed_control_id)).toEqual([
      undefined,
      "control-5",
      "control-6",
      "control-8",
    ]);
  });

  test("keeps the scan's login proof unless the user changes it", async () => {
    const fetchMock = await openDiscoveryWithObservation(
      {
        url: "https://shop.example.test/",
        title: "Shop",
        controls: juiceShopLikeControls,
        suggested_controls: {
          username: "control-5",
          password: "control-6",
          submit: "control-7",
          source: "rules",
          status: "rules_detected",
          rejected: [],
        },
      },
      {
        verification: {
          protected_resource: "https://shop.example.test/#/profile",
          account_marker_selector: "#email",
          account_marker_description: "Signed-in email",
        },
      },
    );

    // The values the scan was started with are shown, not a default.
    expect(screen.getByText(/^Login proof:/)).toHaveTextContent(
      "Login proof: #email on https://shop.example.test/#/profile",
    );
    expect(screen.getByLabelText("Authenticated marker selector")).toHaveValue(
      "#email",
    );
    expect(
      screen.getByLabelText("Authenticated marker selector"),
    ).not.toBeRequired();
    expect(screen.getByLabelText("Marker description")).toHaveValue(
      "Signed-in email",
    );

    // Only the changed description is sent; the selector and page are kept.
    fireEvent.change(screen.getByLabelText("Marker description"), {
      target: { value: "Email shown on the profile page" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: /save and verify guided flow/i }),
    );
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scans/suggested-scan/guidance",
        expect.objectContaining({ method: "POST" }),
      );
    });
    const call = fetchMock.mock.calls.find(
      ([input]) => input === "/api/scans/suggested-scan/guidance",
    ) as [string, RequestInit];
    const body = JSON.parse(String(call[1].body)) as Record<string, unknown>;
    expect(body).not.toHaveProperty("account_marker_selector");
    expect(body).not.toHaveProperty("protected_resource");
    expect(body.account_marker_description).toBe(
      "Email shown on the profile page",
    );
  });

  test("labels rules suggestions and ignores ones that are not options", async () => {
    await openDiscoveryWithObservation({
      url: "https://shop.example.test/",
      title: "Shop",
      controls: juiceShopLikeControls,
      suggested_controls: {
        username: "control-5",
        password: "control-6",
        // Not a button, so it is not an option of the sign-in dropdown.
        submit: "control-2",
        source: "rules",
        status: "rules_detected",
        rejected: [],
      },
    });

    expect(
      screen.getByText(
        "Detected from the page's labels — check before continuing.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Username or email field")).toHaveValue(
      "control-5",
    );
    expect(screen.getByLabelText("Sign-in button")).toHaveValue("");
  });

  test("shows no note and pre-fills nothing without suggestions", async () => {
    await openDiscoveryWithObservation({
      url: "https://shop.example.test/",
      title: "Shop",
      controls: juiceShopLikeControls,
      suggested_controls: {
        username: null,
        password: null,
        submit: null,
        source: null,
        status: "ai_failed",
        rejected: [],
      },
    });

    expect(
      screen.queryByText(/check before continuing/),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText("Username or email field")).toHaveValue("");
    expect(screen.getByLabelText("Password field")).toHaveValue("");
    expect(screen.getByLabelText("Registration link")).toHaveValue("");
    expect(screen.getByLabelText("Password reset link")).toHaveValue("");
  });

  test("pre-fills the registration and reset links and sends the choices", async () => {
    const fetchMock = await openDiscoveryWithObservation({
      url: "https://shop.example.test/",
      title: "Shop",
      controls: [
        ...juiceShopLikeControls,
        suggestedControl("control-9", "a", null, "Not yet a customer?"),
        suggestedControl("control-10", "a", null, "Forgot your password?"),
      ],
      suggested_controls: {
        username: "control-5",
        password: "control-6",
        submit: "control-7",
        source: "rules",
        status: "rules_detected",
        rejected: [],
        registration_link: "control-9",
        // Not a link or button, so it is not an option of the dropdown.
        reset_link: "control-2",
        link_sources: { registration_link: "ai", reset_link: "rules" },
      },
    });

    expect(screen.getByLabelText("Registration link")).toHaveValue("control-9");
    expect(screen.getByLabelText("Password reset link")).toHaveValue("");
    expect(
      screen.getByText("Suggested by AI — check before continuing."),
    ).toBeInTheDocument();

    // The developer changes the reset answer, then says there is no
    // registration link.
    fireEvent.change(screen.getByLabelText("Password reset link"), {
      target: { value: "control-10" },
    });
    fireEvent.change(screen.getByLabelText("Registration link"), {
      target: { value: "" },
    });
    expect(
      screen.queryByText("Suggested by AI — check before continuing."),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: /save and verify guided flow/i }),
    );

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scans/suggested-scan/guidance",
        expect.objectContaining({ method: "POST" }),
      );
    });
    const call = fetchMock.mock.calls.find(
      ([input]) => input === "/api/scans/suggested-scan/guidance",
    ) as [string, RequestInit];
    const body = JSON.parse(String(call[1].body)) as {
      feature_links?: unknown;
    };
    expect(body.feature_links).toEqual({
      registration_link: null,
      reset_link: "control-10",
    });
  });

  test("the sidebar moves between the scan list and a new scan", async () => {
    mockHealthResponse(true, "ok");
    render(<App />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Scans" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("No scans yet")).toBeInTheDocument();

    const nav = screen.getByRole("navigation", { name: "Main" });
    fireEvent.click(within(nav).getByRole("button", { name: "New scan" }));
    expect(
      screen.getByRole("heading", { level: 1, name: "New scan" }),
    ).toBeInTheDocument();
    expect(window.location.hash).toBe("#/new");

    fireEvent.click(within(nav).getByRole("button", { name: "Scans" }));
    expect(
      screen.getByRole("heading", { level: 1, name: "Scans" }),
    ).toBeInTheDocument();
  });

  test("shows live progress and AI metrics while a scan runs", async () => {
    window.localStorage.setItem(
      "authflowguard.scanNotes",
      JSON.stringify({
        "ai-scan-456": {
          checks: ["login_enumeration", "logout_invalidation"],
        },
      }),
    );
    setupMockFetch([
      {
        url: "/api/scans/ai-scan-456",
        response: {
          scan_id: "ai-scan-456",
          state: "running",
          target_url: "https://shop.example.test/login",
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
            model_id: "amazon.nova-micro-v1:0",
          },
          execution_progress: {
            active_check: "login_enumeration",
            completed_checks: [],
            cancelled_checks: [],
          },
          event_count: 12,
          evidence_count: 1,
          result_count: 0,
          results: [],
        },
      },
    ]);

    renderAt("#/scans/ai-scan-456");

    await waitFor(() => {
      expect(screen.getByText("Phase: discovering auth")).toBeInTheDocument();
    });
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Scan of shop.example.test",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("$0.0145")).toBeInTheDocument();
    expect(screen.getByText("3,750")).toBeInTheDocument();
    expect(screen.getByText("Reserved")).toBeInTheDocument();
    expect(screen.getByText("Amazon Bedrock - Nova Micro")).toBeInTheDocument();
    // The planned checks are listed with their state.
    const running = screen
      .getByText("Login account enumeration")
      .closest("li")!;
    expect(within(running).getByText("Running")).toBeInTheDocument();
    const waiting = screen.getByText("Logout invalidation").closest("li")!;
    expect(within(waiting).getByText("Waiting")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Cancel scan" }),
    ).toBeInTheDocument();
  });

  test("shows severity-rated findings, details, evidence and provenance", async () => {
    setupMockFetch([
      {
        url: "/api/scans",
        response: [],
      },
      {
        url: "/api/scans/scan-123/report/json",
        response: {
          metadata: { selected_checks: ["login_enumeration"] },
          results: [
            {
              check_id: "login_enumeration",
              outcome: "finding_confirmed",
              owasp_reference: "WSTG-IDNT-04",
              explanation: "Repeatable account differences were observed.",
              coverage_limitations: ["Only three pairs were compared."],
              analyser_version: "login-enumeration/2",
              created_at: "2026-10-08T09:30:00Z",
            },
          ],
          evidence: [
            {
              evidence_id: "ev-1",
              check_id: "login_enumeration",
              event_ids: ["e1", "e2"],
              observations: { status_codes: [200, 200] },
              control_comparisons: ["Pair 1: signatures were captured."],
              errors: [],
              coverage: {
                attempted_steps: ["known_login", "unknown_login"],
                completed_steps: ["known_login", "unknown_login"],
                limitations: [
                  "Only three pairs were compared.",
                  "Timing was not measured.",
                ],
              },
            },
          ],
        },
      },
      {
        url: "/api/scans/scan-123",
        response: {
          scan_id: "scan-123",
          state: "completed",
          target_url: "https://app.example/login",
          event_count: 78,
          evidence_count: 6,
          result_count: 6,
          report_available: true,
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
            model_id: "amazon.nova-micro-v1:0",
          },
          results: [
            {
              check_id: "login_enumeration",
              outcome: "finding_confirmed",
              owasp_reference: "WSTG-IDNT-04",
              explanation: "Repeatable account differences were observed.",
              coverage_limitations: ["Only three pairs were compared."],
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
              outcome: "finding_confirmed",
              owasp_reference: "WSTG-SESS-06",
              explanation: "The old session still worked after logout.",
            },
          ],
        },
      },
    ]);

    // Open the scan by its ID from the scan list.
    render(<App />);
    fireEvent.change(screen.getByLabelText("Scan ID"), {
      target: { value: "scan-123" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Open scan" }));

    const findings = await screen.findByRole("region", { name: "Findings" });
    const rows = within(findings).getAllByRole("row").slice(1);
    // Sorted by severity: Critical, Medium, Inconclusive, then passes.
    expect(
      rows.map((row) => within(row).getAllByRole("cell")[1].textContent),
    ).toEqual([
      "CHK-006",
      "CHK-001",
      "CHK-003",
      "CHK-002",
      "CHK-004",
      "CHK-005",
    ]);
    expect(within(rows[0]).getByText("Critical")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Medium")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Inconclusive")).toBeInTheDocument();
    expect(within(findings).getAllByText("Passed")).toHaveLength(3);
    expect(
      screen.getByRole("img", {
        name: "Severity: 1 Critical, 1 Medium, 3 Passed, 1 Inconclusive",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download JSON" })).toHaveAttribute(
      "href",
      "/api/scans/scan-123/report/json",
    );

    // Expanding a finding shows the recommendation and coverage limits.
    fireEvent.click(
      screen.getByRole("button", {
        name: "Details for CHK-001 Login account enumeration",
      }),
    );
    expect(screen.getByText("Recommendation")).toBeInTheDocument();
    expect(screen.getByText("Coverage limits")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
    expect(
      await screen.findByText("Pair 1: signatures were captured."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("2 recorded events · 2 of 2 steps completed"),
    ).toBeInTheDocument();
    // Each check shows the same fields as the HTML report.
    const evidenceCard = screen.getByRole("region", {
      name: "CHK-001 Login account enumeration",
    });
    const field = (label: string) =>
      within(evidenceCard).getByText(label, { selector: "dt" }).nextSibling;
    expect(field("Status")).toHaveTextContent("Fail");
    expect(field("Severity")).toHaveTextContent("Medium");
    expect(field("Recommendation")).toHaveTextContent(
      /indistinguishable login failure responses/,
    );
    expect(field("Evidence package")).toHaveTextContent("ev-1");
    expect(field("Analyser version")).toHaveTextContent("login-enumeration/2");
    expect(field("Recorded at")).toHaveTextContent("8 Oct 2026");
    // Coverage limitations are merged without repeats.
    expect(
      within(evidenceCard).getAllByText("Only three pairs were compared."),
    ).toHaveLength(1);
    expect(
      within(evidenceCard).getByText("Timing was not measured."),
    ).toBeInTheDocument();
    expect(within(evidenceCard).getAllByText("Completed")).toHaveLength(2);
    // The observations sit in a collapsed snapshot.
    const snapshot = within(evidenceCard)
      .getByText("Evidence snapshot")
      .closest("details")!;
    expect(snapshot).not.toHaveAttribute("open");
    fireEvent.click(within(snapshot).getByText("Evidence snapshot"));
    expect(snapshot).toHaveAttribute("open");
    expect(snapshot.querySelector("pre")).toHaveTextContent(
      /"status_codes": \[\s*200,\s*200\s*\]/,
    );

    fireEvent.click(screen.getByRole("tab", { name: "AI discovery" }));
    expect(screen.getByText("Discovery provenance")).toBeInTheDocument();
    expect(screen.getByText("$0.0452")).toBeInTheDocument();
    expect(
      screen.getByText(/deterministic analysers decide every verdict/i),
    ).toBeInTheDocument();
  });

  test("deletes a saved scan only after confirmation", async () => {
    let deleted = false;
    const savedScan = {
      scan_id: "scan-old",
      state: "completed",
      target_url: "https://app.example/login",
      event_count: 3,
      evidence_count: 1,
      result_count: 1,
      results: [],
    };
    const fetchMock = setupMockFetch([
      {
        url: "/api/scans",
        method: "GET",
        response: () => (deleted ? [] : [savedScan]),
      },
      { url: "/api/scans/scan-old", method: "GET", response: savedScan },
      {
        url: "/api/scans/scan-old",
        method: "DELETE",
        status: 204,
        response: () => {
          deleted = true;
          return null;
        },
      },
    ]);
    const confirmMock = vi
      .fn()
      .mockReturnValueOnce(false)
      .mockReturnValue(true);
    vi.stubGlobal("confirm", confirmMock);

    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Scan of app.example" }),
    );
    const deleteButton = await screen.findByRole("button", {
      name: "Delete scan",
    });
    const deleteCalls = () =>
      fetchMock.mock.calls.filter(
        ([, init]) => (init as RequestInit | undefined)?.method === "DELETE",
      );

    fireEvent.click(deleteButton);
    expect(deleteCalls()).toHaveLength(0);

    fireEvent.click(deleteButton);
    await waitFor(() => {
      expect(screen.getByText("No scans yet")).toBeInTheDocument();
    });
    expect(deleteCalls()).toHaveLength(1);
    expect(deleteCalls()[0][0]).toBe("/api/scans/scan-old");
    expect(window.location.hash).toBe("#/scans");
  });

  function listedScan(scanId: string, state: string, host: string) {
    return {
      scan_id: scanId,
      state,
      target_url: `https://${host}/login`,
      event_count: 1,
      evidence_count: 1,
      result_count: 0,
      results: [],
    };
  }

  test("deletes several selected scans from the list after confirmation", async () => {
    window.localStorage.setItem(
      "authflowguard.scanNotes",
      JSON.stringify({
        "scan-a": { name: "First scan" },
        "scan-c": { name: "Kept scan" },
      }),
    );
    const fetchMock = setupMockFetch([
      {
        url: "/api/scans",
        method: "GET",
        response: [
          listedScan("scan-a", "completed", "a.example"),
          listedScan("scan-b", "failed", "b.example"),
          listedScan("scan-c", "cancelled", "c.example"),
        ],
      },
      {
        url: /^\/api\/scans\/scan-[ab]$/,
        method: "DELETE",
        status: 204,
        response: null,
      },
    ]);
    const confirmMock = vi
      .fn()
      .mockReturnValueOnce(false)
      .mockReturnValue(true);
    vi.stubGlobal("confirm", confirmMock);
    const deleteCalls = () =>
      fetchMock.mock.calls
        .filter(
          ([, init]) => (init as RequestInit | undefined)?.method === "DELETE",
        )
        .map(([url]) => url as string);

    render(<App />);
    const first = await screen.findByRole("checkbox", {
      name: "Select First scan",
    });
    fireEvent.click(first);
    fireEvent.click(
      screen.getByRole("checkbox", { name: "Select Scan of b.example" }),
    );
    // Selecting does not open the scan.
    expect(window.location.hash).not.toContain("scan-");
    const selectAll = screen.getByRole("checkbox", {
      name: "Select all scans",
    }) as HTMLInputElement;
    expect(selectAll.indeterminate).toBe(true);

    const deleteButton = screen.getByRole("button", {
      name: "Delete selected (2)",
    });
    fireEvent.click(deleteButton);
    expect(confirmMock).toHaveBeenLastCalledWith(
      "Delete 2 scans? Their evidence, results, and reports will be permanently removed.",
    );
    expect(deleteCalls()).toHaveLength(0);

    fireEvent.click(deleteButton);
    await waitFor(() => {
      expect(
        screen.queryByRole("checkbox", { name: "Select First scan" }),
      ).not.toBeInTheDocument();
    });
    expect(deleteCalls()).toEqual(["/api/scans/scan-a", "/api/scans/scan-b"]);
    expect(screen.queryByText("Scan of b.example")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Kept scan" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Delete selected/ }),
    ).not.toBeInTheDocument();
    // The deleted scan's browser-only name is forgotten too.
    expect(
      JSON.parse(
        window.localStorage.getItem("authflowguard.scanNotes") ?? "{}",
      ),
    ).toEqual({ "scan-c": { name: "Kept scan" } });
  });

  test("keeps scans that fail to delete selected and explains why", async () => {
    setupMockFetch([
      {
        url: "/api/scans",
        method: "GET",
        response: [
          listedScan("scan-a", "completed", "a.example"),
          listedScan("scan-b", "completed", "b.example"),
        ],
      },
      {
        url: "/api/scans/scan-a",
        method: "DELETE",
        status: 204,
        response: null,
      },
      {
        url: "/api/scans/scan-b",
        method: "DELETE",
        status: 409,
        response: {
          detail: "The scan files are in use and could not be deleted",
        },
      },
    ]);
    vi.stubGlobal("confirm", vi.fn().mockReturnValue(true));

    render(<App />);
    fireEvent.click(
      await screen.findByRole("checkbox", { name: "Select all scans" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Delete selected (2)" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "1 scan could not be deleted. The scan files are in use and could not be deleted",
    );
    expect(screen.queryByText("Scan of a.example")).not.toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: "Select Scan of b.example" }),
    ).toBeChecked();
    expect(
      screen.getByRole("button", { name: "Delete selected (1)" }),
    ).toBeInTheDocument();
  });

  test("scans that are still working cannot be selected for deletion", async () => {
    setupMockFetch([
      {
        url: "/api/scans",
        method: "GET",
        response: [
          listedScan("scan-run", "running", "run.example"),
          listedScan("scan-wait", "awaiting_guidance", "wait.example"),
          listedScan("scan-done", "completed", "done.example"),
        ],
      },
    ]);

    render(<App />);
    for (const name of ["Scan of run.example", "Scan of wait.example"]) {
      const checkbox = await screen.findByRole("checkbox", {
        name: `Select ${name}`,
      });
      expect(checkbox).toBeDisabled();
      expect(checkbox).toHaveAttribute(
        "title",
        "Cancel the scan before deleting it",
      );
    }
    // Select all takes only the finished scan.
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all scans" }));
    expect(
      screen.getByRole("checkbox", { name: "Select Scan of done.example" }),
    ).toBeChecked();
    expect(
      screen.getByRole("checkbox", { name: "Select Scan of run.example" }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("button", { name: "Delete selected (1)" }),
    ).toBeInTheDocument();
  });

  test("lists saved scans with severity counts and opens one", async () => {
    const pastScan = {
      scan_id: "past-scan-123",
      state: "completed",
      target_url: "http://127.0.0.1:8011/login",
      event_count: 78,
      evidence_count: 1,
      result_count: 2,
      results: [
        {
          check_id: "logout_invalidation",
          outcome: "finding_confirmed",
          owasp_reference: "WSTG-SESS-06",
          explanation: "The session survived logout.",
        },
        {
          check_id: "login_enumeration",
          outcome: "no_issue_observed",
          owasp_reference: "WSTG-IDNT-04",
          explanation: "No difference.",
        },
      ],
    };
    setupMockFetch([
      { url: "/api/scans", response: [pastScan] },
      { url: "/api/scans/past-scan-123", response: pastScan },
    ]);

    render(<App />);

    const row = (
      await screen.findByText("http://127.0.0.1:8011/login")
    ).closest("tr")!;
    expect(within(row).getByText("Completed")).toBeInTheDocument();
    expect(within(row).getByTitle("1 Critical")).toBeInTheDocument();
    expect(within(row).getByTitle("1 Passed")).toBeInTheDocument();
    fireEvent.click(
      within(row).getByRole("button", { name: "Scan of 127.0.0.1:8011" }),
    );

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "Scan of 127.0.0.1:8011",
      }),
    ).toBeInTheDocument();
    expect(window.location.hash).toBe("#/scans/past-scan-123");
  });

  test("renames a scan in this browser", async () => {
    const scan = {
      scan_id: "named-scan",
      state: "completed",
      target_url: "http://127.0.0.1:3000/#/login",
      event_count: 1,
      evidence_count: 1,
      result_count: 0,
      results: [],
    };
    setupMockFetch([{ url: "/api/scans/named-scan", response: scan }]);

    renderAt("#/scans/named-scan");
    fireEvent.click(await screen.findByRole("button", { name: "Rename scan" }));
    fireEvent.change(screen.getByLabelText("Scan name"), {
      target: { value: "Juice Shop - login and session checks" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save name" }));

    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "Juice Shop - login and session checks",
      }),
    ).toBeInTheDocument();
    expect(
      JSON.parse(
        window.localStorage.getItem("authflowguard.scanNotes") ?? "{}",
      ),
    ).toEqual({
      "named-scan": { name: "Juice Shop - login and session checks" },
    });
  });

  test("explains when a scan ID does not exist", async () => {
    setupMockFetch([
      { url: "/api/scans/missing", status: 404, response: { detail: "x" } },
    ]);

    renderAt("#/scans/missing");

    expect(
      await screen.findByRole("heading", { name: "Scan not found" }),
    ).toBeInTheDocument();
  });
});

describe("check reference", () => {
  test("the sidebar opens the six checks and their shared method", async () => {
    setupMockFetch([{ url: "/api/scans", response: [] }]);
    render(<App />);

    const nav = screen.getByRole("navigation", { name: "Main" });
    fireEvent.click(within(nav).getByRole("button", { name: "Checks" }));

    expect(
      screen.getByRole("heading", { level: 1, name: "Checks" }),
    ).toBeInTheDocument();
    expect(window.location.hash).toBe("#/checks");
    expect(within(nav).getByRole("button", { name: "Checks" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByText(methodology[0])).toBeInTheDocument();
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(6);
    expect(within(rows[5]).getByText("CHK-006")).toBeInTheDocument();
    expect(within(rows[5]).getByText("Critical")).toBeInTheDocument();

    fireEvent.click(
      within(rows[5]).getByRole("link", { name: "Logout invalidation" }),
    );
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "CHK-006 Logout invalidation",
      }),
    ).toBeInTheDocument();
    expect(window.location.hash).toBe("#/checks/logout_invalidation");
  });

  test("a check's page explains its procedure and verdict rules", () => {
    setupMockFetch();
    renderAt("#/checks/logout_invalidation");
    const detail = checkDetail("logout_invalidation")!;

    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "CHK-006 Logout invalidation",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /OWASP WSTG-SESS-06/ }),
    ).toHaveAttribute("href", detail.owaspUrl);

    const procedure = screen.getByRole("region", { name: "How it checks" });
    const steps = within(procedure).getAllByRole("listitem");
    expect(steps.map((step) => step.textContent)).toEqual(detail.procedure);

    const verdicts = screen.getByRole("region", {
      name: "How the verdict is decided",
    });
    const terms = within(verdicts).getAllByRole("term");
    expect(terms.map((term) => term.textContent)).toEqual([
      "FindingCritical",
      "No issuePassed",
      "Inconclusive",
    ]);
    expect(
      within(verdicts)
        .getAllByRole("definition")
        .map((rule) => rule.textContent),
    ).toEqual([
      detail.verdicts.finding,
      detail.verdicts.noIssue,
      detail.verdicts.inconclusive,
    ]);
    expect(screen.getByText(detail.sourceFiles[0])).toBeInTheDocument();

    // The last check links back to the one before it only.
    const pager = screen.getByRole("navigation", { name: "Other checks" });
    expect(within(pager).getAllByRole("link")).toHaveLength(1);
    expect(within(pager).getByRole("link")).toHaveAttribute(
      "href",
      "#/checks/session_fixation",
    );
  });

  test("a finding links to how its check works", async () => {
    const scan = {
      scan_id: "scan-link",
      state: "completed",
      target_url: "https://app.example/login",
      event_count: 1,
      evidence_count: 1,
      result_count: 1,
      results: [
        {
          check_id: "login_enumeration",
          outcome: "finding_confirmed",
          owasp_reference: "WSTG-IDNT-04",
          explanation: "Repeatable account differences were observed.",
        },
      ],
    };
    setupMockFetch([{ url: "/api/scans/scan-link", response: scan }]);
    renderAt("#/scans/scan-link");

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Details for CHK-001 Login account enumeration",
      }),
    );
    const link = screen.getByRole("link", { name: "How this check works" });
    expect(link).toHaveAttribute("href", "#/checks/login_enumeration");

    fireEvent.click(link);
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "CHK-001 Login account enumeration",
      }),
    ).toBeInTheDocument();
  });

  test("the New scan checks open their explanation in a new tab", () => {
    setupMockFetch();
    renderAt("#/new");

    const link = screen.getByRole("link", {
      name: "How Logout invalidation works",
    });
    expect(link).toHaveAttribute("href", "#/checks/logout_invalidation");
    expect(link).toHaveAttribute("target", "_blank");
    // The link sits outside the checkbox's label, so it does not toggle it.
    expect(link.closest("label")).toBeNull();
  });
});
