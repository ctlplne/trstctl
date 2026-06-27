import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Workloads } from "@/pages/Workloads";

function renderWorkloads() {
  return render(
    <MemoryRouter>
      <Workloads />
    </MemoryRouter>,
  );
}

describe("workload identity disclosure surface", () => {
  it("renders dynamic lease controls with expiry visualization and no fixture lease rows", () => {
    renderWorkloads();

    expect(screen.getByRole("heading", { name: "Workload identity" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Ephemeral credential leases" })).toBeInTheDocument();
    expect(screen.getByText("00:00 issued")).toBeInTheDocument();
    expect(screen.getByText("00:45 renew window")).toBeInTheDocument();
    expect(screen.getByText("01:00 expires")).toBeInTheDocument();
    expect(screen.getByLabelText("Provider")).toHaveValue("postgresql");
    expect(screen.getByLabelText("Role")).toHaveValue("readonly-reporting");
    expect(screen.getByLabelText("TTL seconds")).toHaveValue(1200);
    expect(screen.getByRole("button", { name: "Issue lease" })).toBeInTheDocument();
    expect(screen.getByText("No lease has been issued in this browser session.")).toBeInTheDocument();
    expect(screen.getByText("Lease history isn't in the console yet")).toBeInTheDocument();
    expect(screen.getByText("Ephemeral JIT issuance uses external approval flows")).toBeInTheDocument();
    expect(screen.getByText(/does not collect live proof payloads or approval actions/i)).toBeInTheDocument();
    expect(screen.queryByText("15 minute default TTL, 5 minute renew window")).not.toBeInTheDocument();
    expect(screen.queryByText("JWT-SVID")).not.toBeInTheDocument();
    expect(screen.queryByText("PKI secret bundle")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /revoke now|renew now/i })).not.toBeInTheDocument();
  });

  it("renders attested SVID controls without token leakage or fixture rows", () => {
    renderWorkloads();

    expect(screen.getByText("Workload attestation chain")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Issue attested SVID" })).toBeInTheDocument();
    expect(screen.getByLabelText("Attestation method")).toHaveValue("k8s_sat");
    expect(screen.getByLabelText("Attestation proof payload (base64)")).toBeInTheDocument();
    expect(screen.getByLabelText("Workload public key")).toBeInTheDocument();
    expect(screen.getByText("No attested SVID has been issued in this browser session.")).toBeInTheDocument();
    expect(screen.getByText("Raw attestation evidence stays out of the browser")).toBeInTheDocument();
    expect(screen.getByText(/Returned certificate PEM and claim maps are discarded/i)).toBeInTheDocument();
    expect(screen.queryByText("Workload attestation fixtures")).not.toBeInTheDocument();
    expect(screen.queryByText("accepted")).not.toBeInTheDocument();
    expect(screen.queryByText("wrong-tenant")).not.toBeInTheDocument();
    expect(screen.queryByText(/eyJ[a-z0-9_-]+/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("renders scoped AI-agent broker controls as metadata-only", () => {
    renderWorkloads();

    expect(screen.getByText("AI-agent / NHI broker")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Issue broker identity" })).toBeInTheDocument();
    expect(screen.getByLabelText("Agent ID")).toHaveValue("agent-build-1");
    expect(screen.getByLabelText("Broker method")).toHaveValue("github_oidc");
    expect(screen.getByLabelText("Broker scopes")).toHaveValue("mcp:read-only, secrets:read:ci");
    expect(screen.getByLabelText("Broker proof payload (base64)")).toBeInTheDocument();
    expect(screen.getByLabelText("Broker public key")).toBeInTheDocument();
    expect(screen.getByText("No broker identity has been issued in this browser session.")).toBeInTheDocument();
    expect(screen.getByText("Broker history isn't in the console yet")).toBeInTheDocument();
    expect(screen.queryByText("AI agent broker lifecycle fixture")).not.toBeInTheDocument();
    expect(screen.queryByText("credential lease audit event")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /approve agent|mint token/i })).not.toBeInTheDocument();
  });
});
