import { describe, expect, it } from "vitest";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";
import { capabilitySurfaceState, isCapabilityView, resolveCapabilityAction, summarizeCapabilities } from "@/lib/capabilities";
import { featureIdsForPath } from "@/lib/navigation";

function item(overrides: Partial<CapabilityViewItem> = {}): CapabilityViewItem {
  return {
    capability_id: "F1",
    name: "Certificate inventory",
    purpose: "Know which certificates exist and what needs attention.",
    tool: "certificates",
    classification: "primary",
    console_route: "/certificates",
    maturity: "complete_vertical_slice",
    release_blocking: false,
    edition: "core",
    runtime_state: "available",
    authorization_state: "full",
    dependency_state: "none",
    dependencies: [],
    stages: [{ name: "observe", completion: "complete" }],
    actions: { allowed: ["listCertificates"], scoped: [], denied: [], unavailable: [] },
    ...overrides,
  };
}

function view(items: CapabilityViewItem[]): CapabilityView {
  return {
    schema_version: 1,
    contract_schema_version: 3,
    enforcement_note: "The server checks again when an operation executes.",
    license: { tier: "community", state: "community" },
    items,
  };
}

describe("runtime capability truth", () => {
  it("keeps attachment, permission, and dependency limits distinct", () => {
    expect(capabilitySurfaceState(item())).toBe("ready");
    expect(capabilitySurfaceState(item({ runtime_state: "catalog_only", authorization_state: "catalog_only" }))).toBe("unavailable");
    expect(capabilitySurfaceState(item({ authorization_state: "none" }))).toBe("permission_blocked");
    expect(capabilitySurfaceState(item({ runtime_state: "partially_available", authorization_state: "partial" }))).toBe("limited");
  });

  it("never turns an absent manifest row into a ready route", () => {
    const summary = summarizeCapabilities(view([item()]), ["F1", "F2"]);
    expect(summary.state).toBe("limited");
    expect(summary.counts).toMatchObject({ ready: 1, unknown: 1 });
    expect(summary.missingIds).toEqual(["F2"]);
  });

  it("rejects a malformed or stale projection instead of crashing or guessing", () => {
    const malformed = { schema_version: 1, contract_schema_version: 3, items: undefined } as unknown as CapabilityView;
    const stale = { ...view([item()]), contract_schema_version: 2 };
    expect(isCapabilityView(malformed)).toBe(false);
    expect(isCapabilityView(stale)).toBe(false);
    expect(summarizeCapabilities(malformed, ["F1"])).toMatchObject({ state: "unknown", counts: { unknown: 1 } });
    expect(resolveCapabilityAction(malformed, "F1", "listCertificates").state).toBe("unknown");
  });

  it("resolves every server action bucket and fails an unknown operation closed", () => {
    const capability = item({
      actions: {
        allowed: ["listCertificates"],
        scoped: ["requestCertificate"],
        denied: ["revokeCertificate"],
        unavailable: [{ operation_id: "deployCertificate", code: "dependency_not_configured", detail: "No deployment connector is configured." }],
      },
    });
    const runtime = view([capability]);
    expect(resolveCapabilityAction(runtime, "F1", "listCertificates").state).toBe("allowed");
    expect(resolveCapabilityAction(runtime, "F1", "requestCertificate").state).toBe("scoped");
    expect(resolveCapabilityAction(runtime, "F1", "revokeCertificate").state).toBe("denied");
    expect(resolveCapabilityAction(runtime, "F1", "deployCertificate")).toMatchObject({
      state: "unavailable",
      unavailable: { detail: "No deployment connector is configured." },
    });
    expect(resolveCapabilityAction(runtime, "F1", "inventedBrowserAction").state).toBe("unknown");
  });

  it("derives route capability IDs from the one navigation registry", () => {
    expect(featureIdsForPath("/discovery")).toEqual(["F2", "F17", "F35", "F36", "F42", "F49"]);
    expect(featureIdsForPath("/incidents")).toEqual(["F31", "F32", "F34"]);
    expect(featureIdsForPath("/not-a-route")).toEqual([]);
  });
});
