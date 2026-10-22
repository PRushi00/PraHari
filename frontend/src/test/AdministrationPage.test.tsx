import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { AdministrationPage } from "../pages/AdministrationPage";
import { api } from "../services/api";

/**
 * Administration view (blueprint §11).
 *
 * The behaviours worth guarding are the ones that would quietly mislead
 * an operator: a control that reports success the backend never gave, a
 * consequential action taken without confirmation, and an unmeasured
 * value rendered as a number.
 */

const health = {
  evaluated_at: "2026-10-16T12:00:00.000Z",
  counts_by_state: { reporting: 1, disabled: 1 },
  fresh_threshold_seconds: 300,
  stale_threshold_seconds: 3600,
  notes: [],
  sources: [
    {
      source_id: "sensor-a",
      name: "Sensor A",
      source_type: "json_stream",
      state: "reporting",
      enabled: true,
      event_count: 120,
      seconds_since_last_event: 42,
      receipt_evidence_available: true,
      clock_dependent: false,
      freshness_basis: "max(received_at)",
      fresh_threshold_seconds: 300,
      stale_threshold_seconds: 3600,
      evaluated_at: "2026-10-16T12:00:00.000Z",
      reasons: [],
      limitations: [],
    },
    {
      source_id: "sensor-b",
      name: "Sensor B",
      source_type: "json_stream",
      state: "never_seen",
      enabled: false,
      event_count: 0,
      seconds_since_last_event: null,
      receipt_evidence_available: false,
      clock_dependent: true,
      freshness_basis: "max(observed_at)",
      fresh_threshold_seconds: 300,
      stale_threshold_seconds: 3600,
      evaluated_at: "2026-10-16T12:00:00.000Z",
      reasons: [],
      limitations: [],
    },
  ],
};

const policy = {
  retention_days: 365,
  origin: "configured_default",
  configured_default: 365,
  enforcement: "manual",
  automatic_pruning: false,
  confirmation_required: true,
  notes: ["Retention is NOT enforced automatically."],
};

describe("Administration view", () => {
  beforeEach(() => {
    vi.spyOn(api, "getSourceHealth").mockResolvedValue(health as any);
    vi.spyOn(api, "getRetentionPolicy").mockResolvedValue(policy as any);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  const confirmWith = (answer: boolean) =>
    vi.stubGlobal("confirm", vi.fn(() => answer));

  it("lists sources from the backend", async () => {
    render(<AdministrationPage />);

    await waitFor(() => {
      expect(screen.getByText("Sensor A")).toBeInTheDocument();
    });
    expect(screen.getByText("Sensor B")).toBeInTheDocument();
  });

  it("renders an unmeasured freshness as 'not measured', not as zero", async () => {
    render(<AdministrationPage />);

    await waitFor(() => {
      expect(screen.getByText("not measured")).toBeInTheDocument();
    });
  });

  it("asks for confirmation before disabling a source", async () => {
    const confirmSpy = vi.fn(() => false);
    vi.stubGlobal("confirm", confirmSpy);
    const setEnabled = vi.spyOn(api, "setSourceEnabled");

    render(<AdministrationPage />);
    await waitFor(() => screen.getByLabelText("Disable source sensor-a"));
    fireEvent.click(screen.getByLabelText("Disable source sensor-a"));

    expect(confirmSpy).toHaveBeenCalled();
    expect(setEnabled).not.toHaveBeenCalled();
  });

  it("disables a source through the real endpoint and re-reads the server", async () => {
    confirmWith(true);
    const setEnabled = vi
      .spyOn(api, "setSourceEnabled")
      .mockResolvedValue({ source_id: "sensor-a", enabled: false } as any);

    render(<AdministrationPage />);
    await waitFor(() => screen.getByLabelText("Disable source sensor-a"));
    fireEvent.click(screen.getByLabelText("Disable source sensor-a"));

    await waitFor(() => {
      expect(setEnabled).toHaveBeenCalledWith("sensor-a", false);
    });
    // Re-read rather than patched optimistically.
    await waitFor(() => {
      expect(api.getSourceHealth).toHaveBeenCalledTimes(2);
    });
  });

  it("does not claim success when the backend rejects the change", async () => {
    confirmWith(true);
    vi.spyOn(api, "setSourceEnabled").mockRejectedValue(
      new Error("403 insufficient_privilege")
    );

    render(<AdministrationPage />);
    await waitFor(() => screen.getByLabelText("Disable source sensor-a"));
    fireEvent.click(screen.getByLabelText("Disable source sensor-a"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        /insufficient_privilege/i
      );
    });
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows the retention policy in force and the configured default", async () => {
    render(<AdministrationPage />);

    await waitFor(() => {
      expect(screen.getByText("In force")).toBeInTheDocument();
    });
    // The origin is a label, not an identifier, so it reads as one
    // (ADR-114). The underlying value is still `configured_default`.
    // Twice: the metric label, and the origin of the policy in force.
    expect(screen.getAllByText("Configured default")).toHaveLength(2);
  });

  it("warns that a policy change deletes nothing", async () => {
    render(<AdministrationPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/No records are deleted by this action/i)
      ).toBeInTheDocument();
    });
  });

  it("rejects an invalid retention value before calling the backend", async () => {
    const update = vi.spyOn(api, "updateRetentionPolicy");
    render(<AdministrationPage />);
    await waitFor(() => screen.getByLabelText("Retention (days)"));

    fireEvent.change(screen.getByLabelText("Retention (days)"), {
      target: { value: "0" },
    });
    fireEvent.click(screen.getByText("Set policy"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/at least 1/i);
    });
    expect(update).not.toHaveBeenCalled();
  });

  it("confirms before changing retention", async () => {
    const confirmSpy = vi.fn(() => false);
    vi.stubGlobal("confirm", confirmSpy);
    const update = vi.spyOn(api, "updateRetentionPolicy");

    render(<AdministrationPage />);
    await waitFor(() => screen.getByLabelText("Retention (days)"));
    fireEvent.change(screen.getByLabelText("Retention (days)"), {
      target: { value: "30" },
    });
    fireEvent.click(screen.getByText("Set policy"));

    expect(confirmSpy).toHaveBeenCalled();
    expect(update).not.toHaveBeenCalled();
  });

  it("reports the persisted value the backend returned, not the typed one", async () => {
    confirmWith(true);
    vi.spyOn(api, "updateRetentionPolicy").mockResolvedValue({
      ...policy,
      retention_days: 30,
      origin: "operator_override",
    } as any);

    render(<AdministrationPage />);
    await waitFor(() => screen.getByLabelText("Retention (days)"));
    fireEvent.change(screen.getByLabelText("Retention (days)"), {
      target: { value: "30" },
    });
    fireEvent.click(screen.getByText("Set policy"));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent(/30 days/i);
    });
    expect(screen.getByRole("status")).toHaveTextContent(/operator_override/i);
    expect(screen.getByRole("status")).toHaveTextContent(/No records were deleted/i);
  });

  it("never renders credential material", async () => {
    render(<AdministrationPage />);
    await waitFor(() => screen.getByText("Sensor A"));

    const text = document.body.textContent?.toLowerCase() ?? "";
    for (const leak of ["bearer", "token_hash", "salt", "password"]) {
      expect(text).not.toContain(leak);
    }
  });

  it("shows an empty state rather than an invented row", async () => {
    vi.spyOn(api, "getSourceHealth").mockResolvedValue({
      ...health,
      sources: [],
      counts_by_state: {},
    } as any);

    render(<AdministrationPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/No telemetry source is registered/i)
      ).toBeInTheDocument();
    });
  });

  it("surfaces a failed load instead of showing stale data", async () => {
    vi.spyOn(api, "getSourceHealth").mockRejectedValue(new Error("backend down"));

    render(<AdministrationPage />);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/backend down/i);
    });
    expect(screen.queryByText("Sensor A")).not.toBeInTheDocument();
  });
});
