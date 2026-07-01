import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Workloads } from "@/pages/Workloads";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    kubernetesCSRSupport: vi.fn(),
    kubernetesTrustBundles: vi.fn(),
    workloadAttesterTrustSources: vi.fn(),
    issueBrokerAgentIdentity: vi.fn(),
    issueAttestedSVID: vi.fn(),
    issueDynamicLease: vi.fn(),
    renewDynamicLease: vi.fn(),
    revokeDynamicLease: vi.fn(),
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

describe("WIRE-02 Workloads broker and attestation wiring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.kubernetesCSRSupport.mockResolvedValue(kubernetesCSRSupportFixture());
    apiMock.kubernetesTrustBundles.mockResolvedValue(kubernetesTrustBundleFixture());
    apiMock.workloadAttesterTrustSources.mockResolvedValue({ items: [] });
    apiMock.issueBrokerAgentIdentity.mockResolvedValue({
      agent_id: "agent-build-1",
      subject: "spiffe://tenant/ai/build-agent",
      scopes: ["mcp:read-only", "secrets:read:ci"],
      not_after: "2026-06-20T10:30:00Z",
      certificate_id: "cert-broker-1",
      credential_id: "cred-broker-1",
      node_id: "node-broker-1",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nBROKER\n-----END CERTIFICATE-----",
      attestation: {
        id: "att-broker-1",
        method: "github_oidc",
        subject: "repo:example/payments",
        selectors: ["repo:example/payments", "branch:main"],
        verified_at: "2026-06-20T10:00:00Z",
        claims: { token: "RAW-BROKER-PROOF" },
      },
    });
    apiMock.issueAttestedSVID.mockResolvedValue({
      subject: "spiffe://tenant/ns/default/sa/api",
      credential_id: "cred-svid-1",
      not_after: "2026-06-20T10:15:00Z",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nSVID\n-----END CERTIFICATE-----",
      attestation: {
        id: "att-svid-1",
        method: "k8s_sat",
        subject: "system:serviceaccount:default:api",
        selectors: ["namespace:default", "serviceaccount:api"],
        verified_at: "2026-06-20T10:01:00Z",
        claims: { token: "RAW-SVID-PROOF" },
      },
    });
  });

  it("renders broker identities and attested SVID rows from the served endpoints", async () => {
    const user = userEvent.setup();
    renderWorkloads();

    await user.type(screen.getByLabelText("Broker proof payload (base64)"), "YnJva2VyLXByb29m");
    await user.type(screen.getByLabelText("Broker public key"), "-----BEGIN PUBLIC KEY-----\nBROKER\n-----END PUBLIC KEY-----");
    await user.click(screen.getByRole("button", { name: "Issue broker identity" }));

    expect(apiMock.issueBrokerAgentIdentity).toHaveBeenCalledWith({
      agent_id: "agent-build-1",
      method: "github_oidc",
      payload_base64: "YnJva2VyLXByb29m",
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nBROKER\n-----END PUBLIC KEY-----",
      scopes: ["mcp:read-only", "secrets:read:ci"],
      ttl_seconds: 900,
    });

    const brokerRow = await screen.findByRole("row", { name: /agent-build-1 spiffe:\/\/tenant\/ai\/build-agent/i });
    expect(within(brokerRow).getByText("mcp:read-only, secrets:read:ci")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Attestation proof payload (base64)"), "c3ZpZC1wcm9vZg==");
    await user.type(screen.getByLabelText("Workload public key"), "-----BEGIN PUBLIC KEY-----\nSVID\n-----END PUBLIC KEY-----");
    await user.click(screen.getByRole("button", { name: "Issue attested SVID" }));

    expect(apiMock.issueAttestedSVID).toHaveBeenCalledWith({
      method: "k8s_sat",
      payload_base64: "c3ZpZC1wcm9vZg==",
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nSVID\n-----END PUBLIC KEY-----",
      ttl_seconds: 600,
    });

    expect(await screen.findByRole("row", { name: /cred-svid-1 spiffe:\/\/tenant\/ns\/default\/sa\/api k8s_sat/i })).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN CERTIFICATE|RAW-BROKER-PROOF|RAW-SVID-PROOF/)).not.toBeInTheDocument();
  });

  it("removes the static Workloads broker and attestation fixture arrays", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Workloads.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+attestationRows/);
    expect(source).not.toMatch(/const\s+brokerRows/);
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
