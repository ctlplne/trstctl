import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PQCMigrationProgressDetails } from "@/components/PQCMigrationProgressDetails";
import type { CBOMAsset, PQCMigrationFindingProgress, PQCMigrationProgress } from "@/lib/api";

const fingerprint = "50a7049d59fa593255f39591b0fa094a83bb0117d000958b58eb998d3bdedecb";
const asset = { id: "certificate-asset", location: "api.example.test:443" } as CBOMAsset;
const finding: PQCMigrationFindingProgress = {
  run_id: "run-1",
  asset_id: asset.id,
  finding_kind: "certificate-key",
  target_id: "",
  target_revision: "",
  connector: "",
  status: "issued",
  updated_at: "2026-09-22T08:00:00Z",
  certificate_fingerprint: fingerprint,
  target_algorithm: "ML-DSA-65",
  effective_algorithm: "Hybrid-MLDSA44-ECDSAP256",
};
const progress: PQCMigrationProgress = {
  run_id: "run-1",
  total: 1,
  queued: 0,
  issued: 1,
  applied: 0,
  failed: 0,
  rolled_back: 0,
  rollback_unverified: 0,
  findings: [finding],
};

describe("PQC certificate progress", () => {
  it("shows issuance without presenting an unchanged endpoint as migrated", () => {
    render(<PQCMigrationProgressDetails progress={progress} assets={[asset]} />);
    expect(screen.getByText("Findings in this run: 1")).toBeInTheDocument();
    expect(screen.getByText("1 issued; endpoint verification pending.")).toBeInTheDocument();
    expect(screen.getByText("Issued; deployment not verified")).toBeInTheDocument();
    expect(screen.getByText(asset.location)).toBeInTheDocument();
    expect(screen.getByText("No bound target reported")).toBeInTheDocument();
    expect(screen.getByTitle(fingerprint)).toBeInTheDocument();
    expect(screen.getByText("Requested: ML-DSA-65")).toBeInTheDocument();
    expect(screen.getByText("Issued: Hybrid-MLDSA44-ECDSAP256")).toBeInTheDocument();
    expect(screen.queryByText("Verified on target")).not.toBeInTheDocument();
  });

  it("distinguishes inventory restoration from verified recovery", () => {
    render(
      <PQCMigrationProgressDetails
        assets={[asset]}
        progress={{
          ...progress,
          issued: 0,
          rollback_unverified: 1,
          findings: [{ ...finding, status: "rollback_unverified" }],
        }}
      />,
    );
    expect(screen.getByText("Inventory restored; endpoint recovery unverified")).toBeInTheDocument();
    expect(screen.getByText("Inventory-only rollbacks: 1. Endpoint recovery is unverified.")).toBeInTheDocument();
    expect(screen.queryByText("Rollback verified on target")).not.toBeInTheDocument();
  });

  it("does not invent zero unfinished work when an older response lacks the counters", () => {
    render(<PQCMigrationProgressDetails assets={[asset]} progress={{ ...progress, issued: undefined, rollback_unverified: undefined }} />);
    expect(screen.getByText(/Certificate issuance and recovery counts were not reported/)).toBeInTheDocument();
    expect(screen.getByText("Issued; deployment not verified")).toBeInTheDocument();
  });

  it("retains a new server outcome without classifying it as successful", () => {
    render(<PQCMigrationProgressDetails assets={[asset]} progress={{ ...progress, findings: [{ ...finding, status: "awaiting_operator" }] }} />);
    expect(screen.getByText("Unrecognized outcome: awaiting_operator")).toBeInTheDocument();
    expect(screen.queryByText("Verified on target")).not.toBeInTheDocument();
  });

  it("shows the affected asset and redacted failure reason", () => {
    render(
      <PQCMigrationProgressDetails
        assets={[asset]}
        progress={{
          ...progress,
          issued: 0,
          failed: 1,
          findings: [{ ...finding, status: "failed", failure: "Certificate issuance attempts exhausted" }],
        }}
      />,
    );
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByText("Certificate issuance attempts exhausted")).toBeInTheDocument();
    expect(screen.getByText(asset.location)).toBeInTheDocument();
  });
});
