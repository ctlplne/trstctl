import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DiscoveryHero } from "@/components/discovery";
import type { DiscoveryFinding } from "@/lib/api";

const findings = [
  {
    id: "f1",
    kind: "certificate",
    ref: "shadow.example.com",
    source_id: "s1",
    risk_score: 80,
    discovered_at: "",
    fingerprint: "fp1",
    provenance: "ct_log",
    metadata: {},
    run_id: "r1",
  },
  {
    id: "f2",
    kind: "secret",
    ref: "leaked/token",
    source_id: "s2",
    risk_score: 10,
    discovered_at: "",
    fingerprint: "fp2",
    provenance: "scan",
    metadata: {},
    run_id: "r1",
  },
] as unknown as DiscoveryFinding[];

describe("U4-1 discovery hero", () => {
  it("summarizes shadow findings by count, risk, and type", () => {
    render(<DiscoveryHero findings={findings} />);
    expect(screen.getByText("What needs attention")).toBeInTheDocument();
    expect(screen.getByText("Unmanaged")).toBeInTheDocument();
    expect(screen.getByText("Credential types")).toBeInTheDocument();
  });
});
