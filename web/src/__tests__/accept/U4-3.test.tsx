import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { CTDriftPanel } from "@/components/discovery";
import type { DiscoveryFinding, DiscoverySource } from "@/lib/api";

const sources = [
  { id: "s1", name: "ct", kind: "ct_log" },
  { id: "s2", name: "scan", kind: "secret_store" },
] as unknown as DiscoverySource[];
const findings = [
  {
    id: "f1",
    kind: "certificate",
    ref: "ct.example.com",
    source_id: "s1",
    provenance: "ct_log",
    discovered_at: "",
    fingerprint: "fp1",
    metadata: {},
    run_id: "r1",
  },
  { id: "f2", kind: "secret", ref: "scan/hit", source_id: "s2", provenance: "scan", discovered_at: "", fingerprint: "fp2", metadata: {}, run_id: "r1" },
] as unknown as DiscoveryFinding[];

describe("U4-3 CT-log & drift monitoring", () => {
  it("counts only findings from CT-log and drift sources", () => {
    render(<CTDriftPanel findings={findings} sources={sources} />);
    expect(screen.getByText("CT-log & drift monitoring")).toBeInTheDocument();
    expect(screen.getByText("CT-log & drift findings")).toBeInTheDocument();
  });
});
