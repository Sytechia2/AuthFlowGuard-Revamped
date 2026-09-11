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

    expect(screen.getByRole("status")).toHaveTextContent("Checking backend");
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Backend connected");
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
        expect(screen.getByRole("status")).toHaveTextContent("Backend offline");
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
      expect(screen.getByRole("status")).toHaveTextContent("Backend offline");
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
      screen.getByRole("button", { name: /continue to discovery/i }),
    ).toBeDisabled();
  });

  test("submits valid setup fields and opens discovery", async () => {
    mockHealthResponse(true, "ok");
    render(<App />);

    fireEvent.change(screen.getByLabelText("Target URL"), {
      target: { value: "https://staging.example.test/login" },
    });
    fireEvent.change(screen.getByLabelText("Permitted origins"), {
      target: { value: "https://staging.example.test" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: /continue to discovery/i }),
    );

    expect(
      screen.getByRole("heading", { name: "No discovery session yet" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("02 / Authentication assessment"),
    ).toBeInTheDocument();
  });

  test("navigation switches between testing and results views", () => {
    mockHealthResponse(true, "ok");
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: /testing/i }));
    expect(
      screen.getByRole("heading", { name: "Check status" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Not started")).toHaveLength(6);

    fireEvent.click(screen.getByRole("button", { name: /results/i }));
    expect(
      screen.getByRole("heading", { name: "Evidence will appear here" }),
    ).toBeInTheDocument();
  });
});
