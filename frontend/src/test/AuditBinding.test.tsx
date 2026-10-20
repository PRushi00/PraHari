// The Network Isolation card printed "LOOPBACK ENFORCED" unconditionally and
// fell back to "127.0.0.1:8000" when the report was missing (ADR-078). Its
// claim must now follow the backend report.
import { describe, expect, it } from "vitest";

import { describeBinding } from "../pages/AuditPage";
import { SecurityConfig } from "../types";

const base: SecurityConfig = {
  app_name: "PraHari", app_version: "0.1.0", schema_version: "1.0.0",
  deployment_mode: "local", host_binding: "127.0.0.1", port: 8000,
  loopback_enforced: true, authentication_required: false,
  max_request_size_mb: 50, database_url: "sqlite", retention_days: 365,
  serving_host: "127.0.0.1", serving_port: 8000,
  listener_matches_configuration: true, binding_evidence: "CONFIGURED",
  security_boundaries: {},
};

describe("describeBinding", () => {
  it("never claims loopback without a report", () => {
    expect(describeBinding(null).label).toBe("BINDING UNKNOWN");
  });

  it("reports exposure when the backend says loopback is not enforced", () => {
    const r = describeBinding({ ...base, loopback_enforced: false });
    expect(r.label).toBe("EXPOSED BEYOND LOOPBACK");
    expect(r.label).not.toContain("ENFORCED");
  });

  it("flags a server whose configuration does not describe it", () => {
    const r = describeBinding({ ...base, serving_port: 18765, listener_matches_configuration: false });
    expect(r.label).toBe("BINDING UNVERIFIED");
  });

  it("says configured, not enforced, when everything agrees", () => {
    const r = describeBinding(base);
    expect(r.label).toBe("LOOPBACK CONFIGURED");
  });

  it("treats an older backend without the measured fields as unverified", () => {
    const { serving_host, serving_port, listener_matches_configuration, binding_evidence, ...older } = base;
    void serving_host; void serving_port; void listener_matches_configuration; void binding_evidence;
    expect(describeBinding(older as SecurityConfig).label).toBe("BINDING UNVERIFIED");
  });

  it("never shows green when the backend cannot verify the listener (null)", () => {
    const r = describeBinding({ ...base, loopback_enforced: null, listener_matches_configuration: null });
    expect(r.label).toBe("BINDING UNVERIFIED");
    expect(r.color).not.toBe("#10b981");
  });
});
