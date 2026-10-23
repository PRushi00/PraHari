// "This host" — what the machine is, and what is watching it (ADR-125).
//
// The reference design puts hostname, address, OS, collector state and
// uptime in one card. Four of those are now readable; the fifth is the
// trap this component exists to avoid.
//
// There are TWO uptimes. The machine's, and this API process's. They
// differ by hours on a running system, and a card that shows the
// process's under a label reading "Uptime", beside a hostname and an IP
// address, is read as the machine's. So the machine's is labelled
// "Host uptime", the process's "PraHari uptime", and when the
// machine's cannot be read the row says why rather than borrowing the
// number next to it.

import React from "react";
import { Monitor } from "lucide-react";
import { CollectorStatus, HostIdentity } from "../types";
import { fmtDuration, fmtTime } from "../utils/format";

interface Props {
  host: HostIdentity | null;
  collector: CollectorStatus | null;
  loading: boolean;
}

/** One label/value row; an absent value states why it is absent. */
const Row: React.FC<{
  label: string;
  value: React.ReactNode;
  reason?: string | null;
  title?: string;
}> = ({ label, value, reason, title }) => (
  <div className="host-row">
    <dt>{label}</dt>
    <dd title={title}>
      {value ?? (
        <span className="metric-unavailable" title={reason ?? undefined}>
          {reason ? "not available" : "not measured"}
        </span>
      )}
    </dd>
  </div>
);

export const HostCard: React.FC<Props> = ({ host, collector, loading }) => {
  const collectorState = collector?.state ?? null;
  const running = collectorState === "running";

  return (
    <section className="panel host-card">
      <div className="panel-header tight">
        <h3>
          <Monitor size={16} /> This host
        </h3>
        {collector && (
          <span className={`pill ${running ? "pill-ok" : "pill-idle"}`}>
            <span
              className="status-dot"
              style={{ backgroundColor: running ? "#10b981" : "#64748b" }}
            />
            {running ? "Collector running" : "Collector not running"}
          </span>
        )}
      </div>

      {loading && !host ? (
        <p className="panel-state">Reading host details…</p>
      ) : (
        <dl className="host-rows">
          <Row
            label="Hostname"
            value={host?.hostname}
            reason={host?.hostname_reason}
          />
          <Row
            label="Local IP address"
            value={host?.local_ip ? <code>{host.local_ip}</code> : null}
            reason={host?.local_ip_reason}
            title={
              host?.local_ip
                ? "The address the kernel would source from for an outbound route. Not evidence of what this interface can observe."
                : undefined
            }
          />
          <Row label="Operating system" value={host?.operating_system} />
          <Row
            label="Collector"
            value={
              collector
                ? collector.platform_supported
                  ? collectorState
                  : `unsupported on ${collector.platform_name}`
                : null
            }
            reason={collector ? null : "the collector did not answer"}
          />
          <Row
            // Named for the machine, because it is the machine's.
            label="Host uptime"
            value={
              host?.host_uptime_seconds != null
                ? fmtDuration(host.host_uptime_seconds)
                : null
            }
            reason={host?.host_uptime_reason}
            title={
              host?.host_uptime_source
                ? `Read from ${host.host_uptime_source}`
                : undefined
            }
          />
          <Row
            // And this one is named for the process, so the two can
            // never be mistaken for each other.
            label="PraHari uptime"
            value={
              host ? fmtDuration(host.process_uptime_seconds) : null
            }
            title="How long this backend process has been running — not the machine's uptime."
          />
        </dl>
      )}

      {host && (
        <p className="panel-note">
          Measured {fmtTime(host.measured_at)}. {host.limitations[0]}
        </p>
      )}
    </section>
  );
};
