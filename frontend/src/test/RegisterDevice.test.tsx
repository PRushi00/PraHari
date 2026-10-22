import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RegisterDevice } from "../components/RegisterDevice";
import { api } from "../services/api";

/**
 * Register a device (ADR-118).
 *
 * The failure mode here is a confirmation that overstates what
 * happened. "Device added" reads as "we are now watching it", and the
 * device will sit at `never seen` with no telemetry for as long as
 * nobody installs anything. So these pin:
 *
 *   * the form says, before submission, that it installs nothing,
 *     scans nothing and collects nothing;
 *   * the confirmation says collection has NOT started and names what
 *     has to happen first;
 *   * `source_type` is derived from the chosen method, not typed, so a
 *     device cannot be described into being monitored;
 *   * inventory-only is a distinct outcome that never collects.
 */

afterEach(() => vi.restoreAllMocks());

function fill(name: string, id: string) {
  fireEvent.click(screen.getByRole("button", { name: /Register a device/i }));
  fireEvent.change(screen.getByLabelText(/Device name/i), {
    target: { value: name },
  });
  fireEvent.change(screen.getByLabelText(/Source id/i), {
    target: { value: id },
  });
}

describe("register a device", () => {
  it("states up front that it installs, scans and collects nothing", () => {
    render(<RegisterDevice onRegistered={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /Register a device/i }));

    expect(
      screen.getByText(
        /does not install anything, scan your network, open a port, or begin collecting/i,
      ),
    ).toBeInTheDocument();
  });

  it("derives source_type from the monitoring method", async () => {
    const create = vi
      .spyOn(api, "createSource")
      .mockResolvedValue({ name: "Lab box", source_id: "lab-1" } as never);

    render(<RegisterDevice onRegistered={vi.fn()} />);
    fill("Lab box", "lab-1");
    fireEvent.change(screen.getByLabelText(/How it will be monitored/i), {
      target: { value: "network-sensor" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^Register device$/i }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0][0]).toMatchObject({
      source_id: "lab-1",
      source_type: "json_stream",
    });
  });

  it("confirms registration without implying collection started", async () => {
    vi.spyOn(api, "createSource").mockResolvedValue({
      name: "Lab box",
      source_id: "lab-1",
    } as never);

    render(<RegisterDevice onRegistered={vi.fn()} />);
    fill("Lab box", "lab-1");
    fireEvent.click(screen.getByRole("button", { name: /^Register device$/i }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent(
        /Nothing is collecting yet/i,
      );
    });
    expect(screen.getByRole("status")).toHaveTextContent(/never seen/i);
    expect(screen.getByRole("status")).toHaveTextContent(/authorized agent/i);
  });

  it("says an inventory-only record never collects", async () => {
    vi.spyOn(api, "createSource").mockResolvedValue({
      name: "Printer",
      source_id: "printer-1",
    } as never);

    render(<RegisterDevice onRegistered={vi.fn()} />);
    fill("Printer", "printer-1");
    fireEvent.change(screen.getByLabelText(/How it will be monitored/i), {
      target: { value: "inventory-only" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^Register device$/i }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent(
        /inventory-only records never collect/i,
      );
    });
  });

  it("surfaces a refusal from the backend rather than claiming success", async () => {
    vi.spyOn(api, "createSource").mockRejectedValue(
      new Error("Telemetry source with ID 'lab-1' already exists"),
    );

    render(<RegisterDevice onRegistered={vi.fn()} />);
    fill("Lab box", "lab-1");
    fireEvent.click(screen.getByRole("button", { name: /^Register device$/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/already exists/i);
    });
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("offers no address field, because PraHari does nothing with one", () => {
    // A field whose value changes nothing invites the reader to believe
    // it does — that entering an address starts monitoring.
    render(<RegisterDevice onRegistered={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /Register a device/i }));

    expect(screen.queryByLabelText(/IP address/i)).not.toBeInTheDocument();
  });
});
