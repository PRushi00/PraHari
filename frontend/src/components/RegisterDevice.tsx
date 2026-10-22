// Register a device (ADR-118).
//
// What this does and does not do, stated here because the distinction is
// the whole point:
//
//   * It creates a REGISTRY ROW. It does not install anything, scan the
//     network, open a port, or begin collecting.
//   * Registering a device does not make it monitored. Until an agent on
//     that machine, or a sensor that can see its traffic, actually
//     reports, the device shows `never seen` and has no telemetry — and
//     the interface says so rather than leaving a hopeful blank.
//   * `source_type` is chosen from the monitoring METHOD, not typed in,
//     because the adapter registry derives capability from it. A device
//     cannot be made to look monitored by describing it as monitored.
//
// The proposal this implements asked for an IP address field. There is
// none, deliberately: PraHari does nothing with an address it was told
// about, and a field whose value changes nothing invites the reader to
// believe it does.

import React, { useState } from "react";
import { AlertTriangle, CheckCircle, Plus } from "lucide-react";
import { api } from "../services/api";

/** The three ways a device can come to be in the registry. */
const METHODS = [
  {
    id: "host-agent",
    label: "Agent on the machine",
    sourceType: "windows_connection_table",
    detail:
      "A collector runs on that device and reports its own connections. You install and authorize it there; this only reserves the name it will report under.",
  },
  {
    id: "network-sensor",
    label: "Network sensor",
    sourceType: "json_stream",
    detail:
      "Zeek or Suricata, at an observation point that can actually see the traffic, sends JSON records here.",
  },
  {
    id: "inventory-only",
    label: "Inventory only — no collection",
    sourceType: "unknown",
    detail:
      "Record that the device exists. Nothing collects from it, and PraHari will never show traffic for it.",
  },
] as const;

type MethodId = (typeof METHODS)[number]["id"];

interface Props {
  onRegistered: () => void;
}

export const RegisterDevice: React.FC<Props> = ({ onRegistered }) => {
  const [open, setOpen] = useState(false);
  const [sourceId, setSourceId] = useState("");
  const [name, setName] = useState("");
  const [method, setMethod] = useState<MethodId>("host-agent");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const chosen = METHODS.find((m) => m.id === method)!;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const created = await api.createSource({
        source_id: sourceId.trim(),
        name: name.trim(),
        source_type: chosen.sourceType,
        description: `Registered as: ${chosen.label}`,
      });
      // Say what was actually created, and what has NOT started. A
      // "device added" confirmation would imply collection began.
      setNotice(
        `Registered "${created.name}". Nothing is collecting yet — this device ` +
          `will show as never seen until ${
            method === "inventory-only"
              ? "you change its monitoring method; inventory-only records never collect"
              : "an authorized " +
                (method === "host-agent" ? "agent" : "sensor") +
                " reports under this id"
          }.`,
      );
      setSourceId("");
      setName("");
      onRegistered();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button className="btn btn-secondary" onClick={() => setOpen(true)}>
        <Plus size={15} /> Register a device
      </button>
    );
  }

  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-header">
        <h3>Register a device</h3>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => setOpen(false)}
        >
          Cancel
        </button>
      </div>

      <p className="panel-note">
        This creates a record and reserves a source id. It does not install
        anything, scan your network, open a port, or begin collecting.
      </p>

      <div className="form-row">
        <label>
          Device name
          <input
            className="form-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Lab workstation"
            required
          />
        </label>
        <label>
          Source id
          <input
            className="form-input"
            value={sourceId}
            onChange={(e) => setSourceId(e.target.value)}
            placeholder="lab-workstation-1"
            required
          />
        </label>
      </div>

      <label>
        How it will be monitored
        <select
          className="form-select"
          value={method}
          onChange={(e) => setMethod(e.target.value as MethodId)}
        >
          {METHODS.map((m) => (
            <option key={m.id} value={m.id}>
              {m.label}
            </option>
          ))}
        </select>
      </label>
      <p className="panel-note">{chosen.detail}</p>

      {error && (
        <div className="status-banner status-error" role="alert">
          <AlertTriangle size={16} /> {error}
        </div>
      )}
      {notice && (
        <div className="status-banner status-ok" role="status">
          <CheckCircle size={16} /> {notice}
        </div>
      )}

      <div className="form-row" style={{ marginTop: "1rem" }}>
        <button className="btn btn-primary" type="submit" disabled={busy}>
          {busy ? "Registering…" : "Register device"}
        </button>
      </div>
    </form>
  );
};
