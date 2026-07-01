import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Workloads } from "@/pages/Workloads";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    kubernetesCSRSupport: vi.fn(),
    kubernetesTrustBundles: vi.fn(),
    workloadAttesterTrustSources: vi.fn(),
    createWorkloadAttesterTrustSource: vi.fn(),
    rotateWorkloadAttesterTrustSource: vi.fn(),
    revokeWorkloadAttesterTrustSource: vi.fn(),
    deleteWorkloadAttesterTrustSource: vi.fn(),
    issueAttestedSVID: vi.fn(),
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

describe("JOURNEY-001 workload owner attested onboarding", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.kubernetesCSRSupport.mockResolvedValue(kubernetesCSRSupportFixture());
    apiMock.kubernetesTrustBundles.mockResolvedValue(kubernetesTrustBundleFixture());
    apiMock.workloadAttesterTrustSources.mockResolvedValue({ items: [] });
    apiMock.createWorkloadAttesterTrustSource.mockResolvedValue(trustSourceFixture({ rotation_version: 1 }));
    apiMock.rotateWorkloadAttesterTrustSource.mockResolvedValue({
      trust_source: trustSourceFixture({ rotation_version: 2, last_rotated_at: "2026-06-30T12:10:00Z" }),
    });
    apiMock.revokeWorkloadAttesterTrustSource.mockResolvedValue({
      trust_source: trustSourceFixture({ revoked_at: "2026-06-30T12:20:00Z", revoked_reason: "workload owner offboarding", rotation_version: 2 }),
    });
    apiMock.deleteWorkloadAttesterTrustSource.mockResolvedValue(undefined);
    apiMock.issueAttestedSVID
      .mockResolvedValueOnce(attestedSVIDFixture("cred-svid-1", "2026-06-30T12:05:00Z"))
      .mockResolvedValueOnce(attestedSVIDFixture("cred-svid-2", "2026-06-30T12:15:00Z"));
  });

  it("self-serves trust-source lifecycle before issuing and renewing an attested SVID", async () => {
    const user = userEvent.setup();
    renderWorkloads();

    expect(await screen.findByText("No attester trust source has been configured.")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Trust source name"), "prod-k8s");
    await user.type(screen.getByLabelText("Issuer"), "https://kubernetes.default.svc");
    await user.type(screen.getByLabelText("Audience"), "trstctl");
    fireEvent.change(screen.getByLabelText("Trust source JWKS JSON"), { target: { value: '{"keys":[{"kid":"journey-k1"}]}' } });
    await user.click(screen.getByRole("button", { name: "Create trust source" }));

    expect(apiMock.createWorkloadAttesterTrustSource).toHaveBeenCalledWith({
      name: "prod-k8s",
      method: "k8s_sat",
      issuer: "https://kubernetes.default.svc",
      audience: "trstctl",
      jwks: { keys: [{ kid: "journey-k1" }] },
      enabled: true,
    });
    const trustSourceRow = (await screen.findAllByText("prod-k8s")).find((node) => node.closest("tr"))?.closest("tr");
    expect(trustSourceRow).not.toBeNull();
    expect(within(trustSourceRow!).getByText("trust-source-1")).toBeInTheDocument();
    expect(within(trustSourceRow!).getByText("k8s_sat")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Attestation proof payload (base64)"), { target: { value: "c2F0LWpvdXJuZXktMQ==" } });
    await user.type(screen.getByLabelText("Workload public key"), "-----BEGIN PUBLIC KEY-----\nSVID\n-----END PUBLIC KEY-----");
    await user.click(screen.getByRole("button", { name: "Issue attested SVID" }));

    expect(apiMock.issueAttestedSVID).toHaveBeenCalledWith({
      method: "k8s_sat",
      payload_base64: "c2F0LWpvdXJuZXktMQ==",
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nSVID\n-----END PUBLIC KEY-----",
      ttl_seconds: 600,
    });
    expect(await screen.findByRole("row", { name: /cred-svid-1.*spiffe:\/\/tenant\/ns\/default\/sa\/api/i })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Rotation JWKS JSON"), { target: { value: '{"keys":[{"kid":"journey-k2"}]}' } });
    await user.type(screen.getByLabelText("Rotation reason"), "jwks rollover");
    await user.click(screen.getByRole("button", { name: "Rotate trust source" }));

    expect(apiMock.rotateWorkloadAttesterTrustSource).toHaveBeenCalledWith("trust-source-1", {
      jwks: { keys: [{ kid: "journey-k2" }] },
      reason: "jwks rollover",
    });
    await waitFor(() => expect(within(trustSourceRow!).getByText("2")).toBeInTheDocument());

    fireEvent.change(screen.getByLabelText("Attestation proof payload (base64)"), { target: { value: "c2F0LWpvdXJuZXktMg==" } });
    fireEvent.change(screen.getByLabelText("Workload public key"), { target: { value: "-----BEGIN PUBLIC KEY-----\nSVID-ROTATED\n-----END PUBLIC KEY-----" } });
    await user.click(screen.getByRole("button", { name: "Issue attested SVID" }));

    expect(apiMock.issueAttestedSVID).toHaveBeenLastCalledWith({
      method: "k8s_sat",
      payload_base64: "c2F0LWpvdXJuZXktMg==",
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nSVID-ROTATED\n-----END PUBLIC KEY-----",
      ttl_seconds: 600,
    });
    expect(await screen.findByRole("row", { name: /cred-svid-2.*spiffe:\/\/tenant\/ns\/default\/sa\/api/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Revoke" }));
    expect(apiMock.revokeWorkloadAttesterTrustSource).toHaveBeenCalledWith("trust-source-1", { reason: "workload owner offboarding" });
    expect(await screen.findByText("Revoked")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Offboard" }));
    expect(apiMock.deleteWorkloadAttesterTrustSource).toHaveBeenCalledWith("trust-source-1");
    expect(await screen.findByText("No attester trust source has been configured.")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN CERTIFICATE|RAW-SVID-PROOF|PRIVATE KEY/)).not.toBeInTheDocument();
  });
});

function trustSourceFixture(overrides: Record<string, unknown> = {}) {
  return { ...trustSourceFixtureBase(), ...overrides };
}

function trustSourceFixtureBase() {
  return {
    id: "trust-source-1",
    tenant_id: "tenant-1",
    name: "prod-k8s",
    method: "k8s_sat",
    issuer: "https://kubernetes.default.svc",
    audience: "trstctl",
    jwks: { keys: [{ kid: "journey-k1" }] },
    root_certs_pem: [],
    enabled: true,
    rotation_version: 1,
    created_at: "2026-06-30T12:00:00Z",
    updated_at: "2026-06-30T12:00:00Z",
  } as const;
}

function attestedSVIDFixture(credentialID: string, verifiedAt: string) {
  return {
    subject: "spiffe://tenant/ns/default/sa/api",
    credential_id: credentialID,
    not_after: "2026-06-30T13:00:00Z",
    certificate_pem: "-----BEGIN CERTIFICATE-----\nSVID\n-----END CERTIFICATE-----",
    attestation: {
      id: `${credentialID}-att`,
      method: "k8s_sat",
      subject: "system:serviceaccount:default:api",
      selectors: ["namespace:default", "serviceaccount:api"],
      verified_at: verifiedAt,
      claims: { token: "RAW-SVID-PROOF" },
    },
  };
}

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
    rbac_rules: [{ api_group: "certificates.k8s.io", resource: "certificatesigningrequests/status", verbs: ["update", "patch"] }],
    status_fields: ["status.certificate"],
    architecture_controls: ["only approved CertificateSigningRequests are signed"],
    evidence_refs: ["internal/agent/k8s/certificate_signing_request.go"],
    residuals: [],
    recommended_next_actions: [],
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
    rbac_rules: [{ api_group: "trstctl.com", resource: "trustbundles/status", verbs: ["update", "patch"] }],
    status_fields: ["status.targets", "status.bundleSHA256"],
    architecture_controls: ["only public PEM CERTIFICATE blocks are accepted"],
    evidence_refs: ["internal/agent/k8s/trust_bundle.go"],
    residuals: [],
    recommended_next_actions: [],
  };
}
