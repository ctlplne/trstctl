import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { PQCReadinessSummary } from "@/components/pqc";
import type { CBOMMigrationProgress } from "@/lib/api";

const progress = {
  total_assets: 8,
  out_of_policy_assets: 2,
  quantum_vulnerable_assets: 3,
  post_quantum_ready_assets: 5,
  percent_migrated: 62,
} as unknown as CBOMMigrationProgress;

describe("U5-1 PQC readiness dashboard", () => {
  it("renders the readiness percentage and the quantum-vulnerable / PQC-ready counts", () => {
    render(<PQCReadinessSummary progress={progress} />);
    expect(screen.getByText("62%")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "PQC migration readiness" })).toBeInTheDocument();
    expect(screen.getByText("Quantum-vulnerable assets")).toBeInTheDocument();
    expect(screen.getByText("PQC-ready assets")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });
});
