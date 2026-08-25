import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Workloads } from "@/pages/Workloads";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    agents: vi.fn(),
    connectorDeliveries: vi.fn(),
    contextualRiskPriorities: vi.fn(),
    identities: vi.fn(),
    kubernetesCSRSupport: vi.fn(),
    kubernetesTrustBundles: vi.fn(),
    rotationRuns: vi.fn(),
    sshFleet: vi.fn(),
    sshStatus: vi.fn(),
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
    apiMock.agents.mockReset().mockResolvedValue([
      {
        id: "agent-1",
        name: "build-host-7",
        status: "offline",
        last_seen_at: new Date(Date.now() - 3_600_000).toISOString(),
        workload_api: { state: "not_serving", svids_issued: 0, detail: "The host socket is off." },
      },
    ]);
    apiMock.identities.mockReset().mockResolvedValue([
      {
        id: "workload-1",
        kind: "workload_identity",
        name: "spiffe://prod/payments-api",
        status: "issued",
        owner_id: "",
        not_after: new Date(Date.now() + 5 * 86_400_000).toISOString(),
      },
      { id: "ssh-1", kind: "ssh_key", name: "legacy-build-key", status: "active", owner_id: "team-1" },
    ]);
    apiMock.contextualRiskPriorities.mockReset().mockResolvedValue({
      generated_at: new Date().toISOString(),
      capability: "contextual-risk",
      coverage: ["workload_identity", "ssh_key"],
      summary: {},
      urgent_summary: { status: "complete", urgent: 1 },
      priorities: [
        {
          credential_id: "workload-1",
          subject: "spiffe://prod/payments-api",
          kind: "workload_identity",
          severity: "critical",
          contextual_score: 96,
          expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString(),
          owner_active: false,
          priority_reasons: ["near_expiry", "orphaned_owner"],
          recommended_action: "Assign the Payments team, then renew the SVID.",
        },
      ],
    });
    apiMock.sshStatus.mockReset().mockResolvedValue({ tenant_id: "tenant-1", served: true, krl_version: 3, revoked_count: 1, attestors: [] });
    apiMock.sshFleet.mockReset().mockResolvedValue({
      host_count: 8,
      hosts: [],
      hosts_not_under_ca: 3,
      key_count: 12,
      orphaned_key_count: 2,
      standing_key_count: 4,
    });
    apiMock.connectorDeliveries.mockReset().mockResolvedValue({
      items: [
        {
          id: "delivery-1",
          tenant_id: "tenant-1",
          identity_id: "workload-1",
          connector: "kubernetes",
          target: "prod-cluster",
          destination: "Deployment/payments-api",
          status: "failed",
          attempts: 3,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ],
    });
    apiMock.rotationRuns.mockReset().mockResolvedValue({ items: [] });
  });

  it("opens as a served Machine and Workload cockpit and keeps unopened Kubernetes diagnostics quiet", async () => {
    const user = userEvent.setup();
    renderWorkloads();

    expect(await screen.findByRole("heading", { level: 1, name: "Workloads & Machines" })).toBeInTheDocument();
    const attention = await screen.findByRole("list", { name: "Machine and workload attention" });
    expect(within(attention).getByText("spiffe://prod/payments-api")).toBeInTheDocument();
    expect(within(attention).getByText(/expires in 5 days/i)).toBeInTheDocument();
    expect(within(attention).getByText(/no accountable owner/i)).toBeInTheDocument();
    expect(within(attention).getByRole("link", { name: "Review workload identity" })).toHaveAttribute("href", "/identities");

    const health = screen.getByRole("list", { name: "Machine and workload health" });
    expect(within(health).getByRole("link", { name: /1 agent needs attention/i })).toHaveAttribute("href", "/agents");
    expect(within(health).getByRole("link", { name: /3 hosts outside the ssh ca/i })).toHaveAttribute("href", "/ssh");
    expect(within(health).getByRole("link", { name: /1 failed workload delivery/i })).toHaveAttribute("href", "/connectors");

    expect(apiMock.kubernetesCSRSupport).not.toHaveBeenCalled();
    expect(apiMock.kubernetesTrustBundles).not.toHaveBeenCalled();
    await user.click(screen.getByText("Kubernetes controller evidence"));
    expect(await screen.findByText("CAP-K8S-04")).toBeInTheDocument();
    expect(apiMock.kubernetesCSRSupport).toHaveBeenCalledTimes(1);
    expect(apiMock.kubernetesTrustBundles).toHaveBeenCalledTimes(1);
  });

  it("renders missing overview evidence as unknown instead of safe zeroes", async () => {
    apiMock.agents.mockResolvedValueOnce([]);
    apiMock.identities.mockRejectedValueOnce(new Error("identity read unavailable"));
    apiMock.contextualRiskPriorities.mockResolvedValueOnce({ priorities: [] });
    apiMock.sshStatus.mockResolvedValueOnce({ served: true });
    apiMock.sshFleet.mockResolvedValueOnce({ hosts_not_under_ca: 0, hosts: [] });
    apiMock.connectorDeliveries.mockResolvedValueOnce({ items: [] });
    apiMock.rotationRuns.mockResolvedValueOnce({ items: [] });

    renderWorkloads();

    expect(await screen.findByRole("heading", { name: "Machine and workload urgency is not fully known" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "No urgent machine or workload work" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Identity health unavailable" })).toHaveAttribute("href", "/identities");
    expect(screen.getByRole("link", { name: "0 agents need attention" })).toBeInTheDocument();
  });

  it("renders dynamic lease controls with expiry visualization and no fixture lease rows", async () => {
    const user = userEvent.setup();
    renderWorkloads();

    expect(screen.getByRole("heading", { name: "Workloads & Machines" })).toBeInTheDocument();
    expect(screen.getByText(/which machine identities may stop working.*agents are stale/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Workload identity needs a trust source" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Set up workload identity" })).toHaveAttribute("aria-expanded", "false");
    await user.click(screen.getByText("Kubernetes controller evidence"));
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

  it("reveals trust setup on request and keeps unusable proof and rotation forms out of the opening view", async () => {
    const user = userEvent.setup();
    renderWorkloads();

    expect(await screen.findByRole("heading", { level: 1, name: "Workloads & Machines" })).toBeInTheDocument();
    expect(screen.getByText("Workload attestation chain")).toBeInTheDocument();
    const setup = screen.getByRole("button", { name: "Set up workload identity" });
    expect(setup).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByLabelText("Trust source name")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Rotation JWKS JSON")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Attestation proof payload (base64)")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Issue attested SVID" })).not.toBeInTheDocument();

    await user.click(setup);

    expect(setup).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByLabelText("Trust source name")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create trust source" })).toBeInTheDocument();
    expect(screen.getByText("No attester trust source has been configured.")).toBeInTheDocument();
    const trustSources = screen.getByRole("group", { name: "Attester trust sources" });
    expect(trustSources).toHaveAttribute("tabindex", "0");
    const trustSourceTable = within(trustSources).getByRole("table", { name: "Attester trust sources" });
    expect(within(trustSourceTable).getAllByRole("columnheader")).toHaveLength(5);
    expect(within(trustSourceTable).queryByRole("columnheader", { name: "Version" })).not.toBeInTheDocument();
    expect(within(trustSourceTable).queryByRole("columnheader", { name: "Last rotated" })).not.toBeInTheDocument();
    expect(screen.getByText("Add a trusted attester before issuing a workload identity.")).toBeInTheDocument();
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

    expect(await screen.findByRole("heading", { level: 1, name: "Workloads & Machines" })).toBeInTheDocument();
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
