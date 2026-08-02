import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DriftPanel } from "@/components/discovery";
import type { DiscoveryFinding, DiscoverySource } from "@/lib/api";

// C5: this asserted a single "CT-log & drift findings" tile, which is what kept
// certificate transparency filed as a footnote on the Discovery page — one
// number shared with an unrelated capability. CT monitoring now has its own
// headline surface (CTMonitoringPanel), so this panel counts drift alone and
// the test asserts that neither number is diluted by the other.

const sources = [
  { id: "s1", name: "ct", kind: "ct_log" },
  { id: "s2", name: "drift", kind: "drift" },
  { id: "s3", name: "scan", kind: "secret_store" },
] as unknown as DiscoverySource[];

const finding = (id: string, sourceID: string, ref: string): DiscoveryFinding =>
  ({
    id,
    kind: "certificate",
    ref,
    source_id: sourceID,
    provenance: sourceID,
    discovered_at: "",
    fingerprint: id,
    metadata: {},
    run_id: "r1",
  }) as unknown as DiscoveryFinding;

const findings = [finding("f1", "s1", "ct.example.com"), finding("f2", "s2", "/etc/nginx/tls.crt"), finding("f3", "s3", "scan/hit")];

describe("U4-3 drift monitoring", () => {
  it("counts only drift findings, not certificate-transparency ones", () => {
    render(<DriftPanel findings={findings} sources={sources} />);
    expect(screen.getByText("Configuration drift")).toBeInTheDocument();
    expect(screen.getByText("Drift findings")).toBeInTheDocument();
    // One drift finding, not two: the CT finding belongs to its own surface.
    expect(screen.getByText("1")).toBeInTheDocument();
  });

  it("no longer bundles certificate transparency into the drift tile", () => {
    render(<DriftPanel findings={findings} sources={sources} />);
    expect(screen.queryByText(/CT-log/i)).not.toBeInTheDocument();
  });
});
