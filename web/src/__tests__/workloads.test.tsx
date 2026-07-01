import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Workloads } from "@/pages/Workloads";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    kubernetesCSRSupport: vi.fn(),
    kubernetesTrustBundles: vi.fn(),
    workloadAttesterTrustSources: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderWorkloads() {
  return render(
    <MemoryRouter>
      <Workloads />
    </MemoryRouter>,
  );
}

describe("workload identity disclosure surface", () => {
  beforeEach(() => {
    apiMock.kubernetesCSRSupport.mockReset().mockResolvedValue(kubernetesCSRSupportFixture());
    apiMock.kubernetesTrustBundles.mockReset().mockResolvedValue(kubernetesTrustBundleFixture());
    apiMock.workloadAttesterTrustSources.mockReset().mockResolvedValue({ items: [] });
  });

  it("renders dynamic lease controls with expiry visualization and no fixture lease rows", async () => {
    renderWorkloads();

    expect(screen.getByRole("heading", { name: "Workload identity" })).toBeInTheDocument();
    expect(await screen.findByText("CAP-K8S-04")).toBeInTheDocument();
    expect(await screen.findByText("CAP-K8S-07")).toBeInTheDocument();
    expect(screen.getByText("trustbundles/status: update, patch")).toBeInTheDocument();
    expect(screen.getByText("ConfigMap ca-bundle.pem in each target namespace")).toBeInTheDocument();
    expect(screen.getByText("trstctl.com/trstctl")).toBeInTheDocument();
    expect(screen.getByText("certificatesigningrequests/status: update, patch")).toBeInTheDocument();
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
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /revoke now|renew now/i })).not.toBeInTheDocument();
  });

  it("renders attested SVID controls without token leakage or fixture rows", async () => {
    renderWorkloads();

    expect(await screen.findByText("CAP-K8S-04")).toBeInTheDocument();
    expect(screen.getByText("Workload attestation chain")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create trust source" })).toBeInTheDocument();
    expect(screen.getByText("No attester trust source has been configured.")).toBeInTheDocument();
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

  it("renders scoped AI-agent broker controls as metadata-only", async () => {
    renderWorkloads();

    expect(await screen.findByText("CAP-K8S-04")).toBeInTheDocument();
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

function kubernetesCSRSupportFixture() {
  return {
    capability: "CAP-K8S-04",
    served: true,
    generated_at: "2026-06-28T12:00:00Z",
    api_group: "certificates.k8s.io",
    api_version: "certificates.k8s.io/v1",
    resource: "certificatesigningrequests",
    signer_names: ["trstctl.com/trstctl"],
    controller_flow: ["controller lists native Kubernetes CSRs"],
    rbac_rules: [
      { api_group: "certificates.k8s.io", resource: "certificatesigningrequests", verbs: ["get", "list", "watch"] },
      { api_group: "certificates.k8s.io", resource: "certificatesigningrequests/status", verbs: ["update", "patch"] },
    ],
    status_fields: ["status.certificate"],
    architecture_controls: ["only approved CertificateSigningRequests are signed"],
    evidence_refs: ["internal/agent/k8s/certificate_signing_request.go"],
    residuals: ["poll-based controller"],
    recommended_next_actions: ["move reconciliation to informer-backed queues"],
  };
}

function kubernetesTrustBundleFixture() {
  return {
    capability: "CAP-K8S-07",
    served: true,
    generated_at: "2026-06-30T12:00:00Z",
    api_group: "trstctl.com",
    api_version: "trstctl.com/v1alpha1",
    resource: "trustbundles",
    distribution_targets: ["ConfigMap ca-bundle.pem in each target namespace"],
    controller_flow: ["controller lists TrustBundle resources"],
    rbac_rules: [
      { api_group: "trstctl.com", resource: "trustbundles", verbs: ["get", "list", "watch"] },
      { api_group: "trstctl.com", resource: "trustbundles/status", verbs: ["update", "patch"] },
      { api_group: "", resource: "configmaps", verbs: ["get", "list", "watch", "create", "update", "patch"] },
    ],
    status_fields: ["status.targets", "status.bundleSHA256"],
    architecture_controls: ["only public PEM CERTIFICATE blocks are accepted"],
    evidence_refs: ["internal/agent/k8s/trust_bundle.go"],
    residuals: ["poll-based controller"],
    recommended_next_actions: ["add fleet-level receipts"],
  };
}
