import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import App from "./App";

function mockHealthResponse(ok: boolean, status: string) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok,
      json: async () => ({ status }),
    }),
  );
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
    expect(fetch).toHaveBeenCalledOnce();
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

    const checkboxes = screen.getAllByRole("checkbox");
    expect(checkboxes).toHaveLength(6);
    expect(screen.getByText("6 selected")).toBeInTheDocument();

    for (const checkbox of checkboxes) {
      fireEvent.click(checkbox);
    }

    expect(screen.getByText("0 selected")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /start local scan/i }),
    ).toBeDisabled();
  });

  test("submits setup and starts a local scan", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ status: "ok" }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ scan_id: "scan-123", state: "created" }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ scan_id: "scan-123", state: "running" }),
        })
        .mockResolvedValue({
          ok: true,
          json: async () => ({
            scan_id: "scan-123",
            state: "running",
            event_count: 0,
            evidence_count: 0,
            result_count: 0,
            results: [],
          }),
        }),
    );
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
    expect(fetch).toHaveBeenCalledWith(
      "/api/scans",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetch).toHaveBeenCalledWith(
      "/api/scans/scan-123/start",
      expect.objectContaining({ method: "POST" }),
    );
  });

  test("opens Discovery for a paused scan and submits guided actions", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ status: "ok" }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ scan_id: "guided-scan", state: "created" }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            scan_id: "guided-scan",
            state: "running",
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            scan_id: "guided-scan",
            state: "awaiting_guidance",
            target_url: "https://staging.example.test/login",
            error: "Expected one submit control, found 2",
            event_count: 0,
            evidence_count: 0,
            result_count: 0,
            results: [],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            scan_id: "guided-scan",
            state: "awaiting_guidance",
            target_url: "https://staging.example.test/login",
            error: "Expected one submit control, found 2",
            event_count: 0,
            evidence_count: 0,
            result_count: 0,
            results: [],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            url: "https://staging.example.test/login",
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
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            scan_id: "guided-scan",
            state: "running",
          }),
        }),
    );
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
    fireEvent.click(screen.getByRole("button", { name: "Open Discovery" }));
    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: "Help us log in" }),
      ).toBeInTheDocument();
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
      expect(fetch).toHaveBeenCalledWith(
        "/api/scans/guided-scan/guidance",
        expect.objectContaining({ method: "POST" }),
      );
    });
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

  test("loads scan results and exposes offline report links", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ status: "ok" }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => [],
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            scan_id: "scan-123",
            state: "completed",
            event_count: 78,
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
          }),
        }),
    );

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
    expect(fetch).toHaveBeenLastCalledWith("/api/scans/scan-123");
  });

  test("shows saved runs and loads one without manual ID entry", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ status: "ok" }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => [
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
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            scan_id: "past-scan-123",
            state: "completed",
            event_count: 78,
            evidence_count: 1,
            result_count: 1,
            results: [],
          }),
        }),
    );

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
