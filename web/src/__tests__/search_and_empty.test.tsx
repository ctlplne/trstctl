import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Certificates } from "@/pages/Certificates";
import { ApiError, UnauthorizedError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    certificatePage: vi.fn(),
    certificateHealth: vi.fn(),
    getCertificate: vi.fn(),
    ingestCertificate: vi.fn(),
    rogueCertificates: vi.fn(),
    revocationHealth: vi.fn(),
    submitCertificateTransparency: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderCerts() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <Certificates />
      </ToastProvider>
    </MemoryRouter>,
  );
}

function primitive(container: HTMLElement, name: string) {
  return container.querySelector(`[data-state-primitive="${name}"]`);
}

describe("inventory search", () => {
  beforeEach(() => {
    apiMock.certificatePage.mockReset();
    apiMock.certificateHealth.mockReset();
    apiMock.getCertificate.mockReset();
    apiMock.ingestCertificate.mockReset();
    apiMock.rogueCertificates.mockReset();
    apiMock.revocationHealth.mockReset();
    apiMock.submitCertificateTransparency.mockReset();
  });

  it("filters the certificate inventory as you type", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [
        { id: "c1", subject: "CN=payments.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp1" },
        { id: "c2", subject: "CN=web.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp2" },
      ],
    });
    const user = userEvent.setup();
    renderCerts();

    expect(await screen.findByText("CN=payments.example.com")).toBeInTheDocument();
    expect(screen.getByText("CN=web.example.com")).toBeInTheDocument();

    await user.type(screen.getByRole("searchbox", { name: /search/i }), "payments");

    await waitFor(() => expect(screen.queryByText("CN=web.example.com")).not.toBeInTheDocument());
    expect(screen.getByText("CN=payments.example.com")).toBeInTheDocument();
  });

  it("reports when a search matches nothing", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", subject: "CN=payments.example.com", status: "active", fingerprint: "fp1" }],
    });
    const user = userEvent.setup();
    renderCerts();

    await screen.findByText("CN=payments.example.com");
    await user.type(screen.getByRole("searchbox", { name: /search/i }), "nomatch");
    expect(await screen.findByText(/no (certificates )?match/i)).toBeInTheDocument();
  });

  it("renders estate-wide expiry health including external certificate sources", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [
        { id: "c1", subject: "CN=imported.example.com", issuer: "CN=External CA", status: "active", fingerprint: "fp1", source: "import" },
        { id: "c2", subject: "CN=issued.example.com", issuer: "CN=trstctl CA", status: "active", fingerprint: "fp2", source: "issued" },
      ],
    });
    apiMock.certificateHealth.mockResolvedValue({
      generated_at: "2026-06-28T00:00:00Z",
      inventory_path: "/api/v1/certificates",
      expiring_path: "/api/v1/certificates?expiring_before=2026-07-28T00:00:00Z",
      summary: {
        total: 3,
        active: 3,
        revoked: 0,
        superseded: 0,
        expired: 0,
        expiring_7d: 1,
        expiring_30d: 2,
        expiring_90d: 2,
        external_source_count: 2,
        imported_count: 1,
        discovered_count: 1,
        unknown_expiry_count: 0,
        health: "warning",
      },
      expiry_buckets: [],
      source_breakdown: [
        { source: "import", count: 1, external: true, expired: 0, expiring_30d: 1 },
        { source: "discovery:network", count: 1, external: true, expired: 0, expiring_30d: 0 },
        { source: "issued", count: 1, external: false, expired: 0, expiring_30d: 1 },
      ],
      expiring: [
        {
          id: "c1",
          subject: "CN=imported.example.com",
          fingerprint: "fp1",
          deployment_location: "f5:/Common/imported",
          source: "import",
          status: "active",
          not_after: "2026-06-30T00:00:00Z",
          days_remaining: 2,
          externally_issued: true,
        },
      ],
    });
    const user = userEvent.setup();
    renderCerts();

    // Estate health lives behind the certificates workspace tab.
    await user.click(await screen.findByRole("tab", { name: "Estate health" }));
    expect(await screen.findByRole("heading", { name: /estate certificate health/i })).toBeInTheDocument();
    expect(screen.getByText("warning")).toBeInTheDocument();
    expect(screen.getByText("External sources")).toBeInTheDocument();
    expect(screen.getByText("discovery:network")).toBeInTheDocument();
    expect(screen.getByText("f5:/Common/imported")).toBeInTheDocument();
  });

  it("renders rogue and non-compliant certificate posture from the served route", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "c1",
          subject: "CN=legacy.external.example.com",
          issuer: "CN=External CA",
          status: "active",
          fingerprint: "fp1",
          key_algorithm: "RSA-1024",
        },
      ],
    });
    apiMock.rogueCertificates.mockResolvedValue({
      capability: "CAP-REV-05",
      generated_at: "2026-06-30T00:00:00Z",
      coverage: ["certificate_inventory", "ct_unexpected_issuance", "weak_key_algorithm"],
      summary: {
        total_analyzed: 2,
        findings: 2,
        rogue: 1,
        non_compliant: 1,
        ct_unexpected: 1,
        weak_key: 1,
        lifetime_violations: 0,
        expired_active: 0,
        owner_missing: 1,
        issuer_missing: 0,
        critical: 1,
        high: 1,
        medium: 0,
        low: 0,
        recommendations: 2,
      },
      findings: [
        {
          id: "discovery:f1",
          discovery_id: "f1",
          kind: "rogue_certificate",
          policy_status: "rogue",
          subject: "CN=shadow.example.com",
          source: "ct_log",
          finding_types: ["ct_unexpected_issuance", "not_in_inventory"],
          severity: "critical",
          risk_score: 95,
          recommendation: "Investigate the unexpected CT hit.",
          evidence_refs: ["projection:discovery_findings:f1", "outbox:notification.ct"],
        },
        {
          id: "certificate:c1",
          certificate_id: "c1",
          kind: "non_compliant_certificate",
          policy_status: "non_compliant",
          subject: "CN=legacy.external.example.com",
          source: "import",
          finding_types: ["weak_key_algorithm", "owner_missing"],
          severity: "high",
          risk_score: 85,
          recommendation: "Reissue with an approved key algorithm.",
          evidence_refs: ["projection:certificates:c1"],
        },
      ],
      recommended_actions: ["Investigate unexpected CT hits."],
      evidence_refs: ["projection:certificates", "projection:discovery_findings"],
    });

    const user = userEvent.setup();
    renderCerts();

    await user.click(await screen.findByRole("tab", { name: "Estate health" }));
    const posture = await screen.findByRole("region", { name: "Rogue certificate detection" });
    expect(apiMock.rogueCertificates).toHaveBeenCalled();
    expect(within(posture).getByText("2 findings")).toBeInTheDocument();
    expect(within(posture).getByText("CN=shadow.example.com")).toBeInTheDocument();
    expect(within(posture).getByText("CN=legacy.external.example.com")).toBeInTheDocument();
    expect(within(posture).getByText("Unexpected CT issuance, Not in inventory")).toBeInTheDocument();
    expect(within(posture).getByText("Weak key, Owner missing")).toBeInTheDocument();
    expect(within(posture).getByText("Reissue with an approved key algorithm.")).toBeInTheDocument();
  });

  it("shows signed CRL and OCSP freshness evidence in the CRL and CT workspace", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", subject: "CN=service.example.com", issuer: "CN=Root CA", status: "active", fingerprint: "fp1" }],
    });
    apiMock.revocationHealth.mockResolvedValue({
      observed: true,
      summary: { endpoints: 2, fresh: 1, expiring: 0, stale: 1, unreachable: 0, unparseable: 0 },
      items: [
        {
          target_key: "crl-key", protocol: "crl", endpoint: "https://pki.example.test/root.crl",
          certificate_id: "c1", certificate_subject: "CN=service.example.com", certificate_fingerprint: "fp1", certificate_serial: "01",
          issuer_subject: "CN=Root CA", status: "stale", detail_code: "next_update_passed", latency_ms: 12,
          signature_verified: true, next_update: "2026-08-11T00:00:00Z", probe_id: "probe-1",
          observed_by_agent_id: "agent-1", observed_by_agent_name: "corp-relay", evidence_digest: "a".repeat(64), observed_at: "2026-08-12T00:00:00Z",
        },
        {
          target_key: "ocsp-key", protocol: "ocsp", endpoint: "https://ocsp.example.test",
          certificate_id: "c1", certificate_subject: "CN=service.example.com", certificate_fingerprint: "fp1", certificate_serial: "01",
          issuer_subject: "CN=Root CA", status: "fresh", detail_code: "fresh", latency_ms: 8,
          signature_verified: true, response_status: "good", next_update: "2026-08-13T00:00:00Z", probe_id: "probe-1",
          observed_by_agent_id: "agent-1", observed_by_agent_name: "corp-relay", evidence_digest: "b".repeat(64), observed_at: "2026-08-12T00:00:00Z",
        },
      ],
      guidance: "CRL and OCSP failures affect clients differently; verify fail-closed and soft-fail behavior.",
    });
    const user = userEvent.setup();
    renderCerts();

    await user.click(await screen.findByRole("tab", { name: /CRL & CT/i }));
    const panel = await screen.findByRole("region", { name: "Revocation" });
    expect(within(panel).getByText("Stale")).toBeInTheDocument();
    expect(within(panel).getByText("ok")).toBeInTheDocument();
    expect(within(panel).getByText(/root\.crl/)).toBeInTheDocument();
    expect(within(panel).getByText(/ocsp\.example/)).toBeInTheDocument();
    expect(within(panel).getByText(/fail-closed and soft-fail/)).toBeInTheDocument();
  });
});

describe("guiding empty states", () => {
  beforeEach(() => {
    apiMock.certificatePage.mockReset();
    apiMock.certificateHealth.mockReset();
    apiMock.getCertificate.mockReset();
    apiMock.ingestCertificate.mockReset();
    apiMock.rogueCertificates.mockReset();
    apiMock.revocationHealth.mockReset();
    apiMock.submitCertificateTransparency.mockReset();
  });

  it("guides a fresh install to issue a certificate or connect an issuer when the inventory is empty", async () => {
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    const { container } = renderCerts();

    const cta = await screen.findByRole("link", { name: "Issue first certificate" });
    expect(cta).toHaveAttribute("href", expect.stringContaining("/request"));
    expect(screen.getByRole("link", { name: "Connect an issuer" })).toHaveAttribute("href", expect.stringContaining("/ca-hierarchy"));
    expect(primitive(container, "empty")).toBeInTheDocument();
  });

  it("shows permission denial when the tenant session cannot read inventory", async () => {
    apiMock.certificatePage.mockRejectedValue(new UnauthorizedError());
    const { container } = renderCerts();

    expect(await screen.findByRole("alert")).toHaveTextContent(/permission denied/i);
    expect(primitive(container, "permission-denied")).toBeInTheDocument();
  });

  it("uses shared loading and error primitives on the representative certificate page", async () => {
    apiMock.certificatePage.mockReturnValueOnce(new Promise(() => undefined));
    const loading = renderCerts();
    expect(await screen.findByRole("status")).toHaveTextContent(/loading certificates/i);
    expect(primitive(loading.container, "loading")).toBeInTheDocument();
    loading.unmount();

    apiMock.certificatePage.mockRejectedValue(new ApiError(500, "database unavailable"));
    const error = renderCerts();
    expect(await screen.findByRole("alert")).toHaveTextContent(/database unavailable/i);
    expect(primitive(error.container, "error")).toBeInTheDocument();
  });
});

describe("certificate inventory gap closure", () => {
  beforeEach(() => {
    apiMock.certificatePage.mockReset();
    apiMock.certificateHealth.mockReset();
    apiMock.getCertificate.mockReset();
    apiMock.ingestCertificate.mockReset();
    apiMock.rogueCertificates.mockReset();
    apiMock.revocationHealth.mockReset();
    apiMock.submitCertificateTransparency.mockReset();
  });

  it("loads server-side pages, applies expiring_before, and reaches the no-more-pages state", async () => {
    apiMock.certificatePage
      .mockResolvedValueOnce({
        items: [{ id: "c1", subject: "CN=page-one", issuer: "CN=CA", status: "active", fingerprint: "fp1" }],
        next_cursor: "cursor-two",
      })
      .mockResolvedValueOnce({
        items: [{ id: "c2", subject: "CN=page-two", issuer: "CN=CA", status: "active", fingerprint: "fp2" }],
      })
      .mockResolvedValueOnce({ items: [] });
    const user = userEvent.setup();
    renderCerts();

    expect(await screen.findByText("CN=page-one")).toBeInTheDocument();
    expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 20, expiringBefore: undefined });

    await user.click(screen.getByRole("button", { name: /load next page/i }));
    await waitFor(() =>
      expect(apiMock.certificatePage).toHaveBeenCalledWith({
        limit: 20,
        cursor: "cursor-two",
        expiringBefore: undefined,
      }),
    );
    expect(await screen.findByText("CN=page-two")).toBeInTheDocument();
    expect(screen.getByText(/no more certificate pages/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "<7d" }));
    await waitFor(() =>
      expect(apiMock.certificatePage).toHaveBeenLastCalledWith({
        limit: 20,
        expiringBefore: expect.any(String),
      }),
    );
  });

  it("renders expiry bands and revoked metadata from served certificate fields", async () => {
    const user = userEvent.setup();
    const soon = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
    const revokedAt = "2026-06-19T12:00:00Z";
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "c1",
          subject: "CN=revoked.example.com",
          issuer: "CN=CA",
          not_after: soon,
          status: "revoked",
          revoked_at: revokedAt,
          revocation_reason: "keyCompromise",
          fingerprint: "fp1",
        },
      ],
    });
    apiMock.getCertificate.mockResolvedValue({
      id: "c1",
      subject: "CN=revoked.example.com",
      issuer: "CN=CA",
      not_after: soon,
      status: "revoked",
      revoked_at: revokedAt,
      revocation_reason: "keyCompromise",
      fingerprint: "fp1",
    });

    renderCerts();

    expect(await screen.findByText("<7d critical")).toBeInTheDocument();
    expect(screen.getByText("revoked")).toBeInTheDocument();
    expect(screen.getByText("keyCompromise")).toBeInTheDocument();
    expect(screen.queryByText(/^active$/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /view details/i }));

    const dialog = await screen.findByRole("dialog", { name: /certificate details/i });
    expect(within(dialog).getByText("Revoked at")).toBeInTheDocument();
    expect(within(dialog).getByText("Revocation reason")).toBeInTheDocument();
    expect(within(dialog).getByText("keyCompromise")).toBeInTheDocument();
    // Dates render through the central Intl policy (medium, UTC) — not ad-hoc toLocale*.
    expect(within(dialog).getByText("Jun 19, 2026")).toBeInTheDocument();
  });

  it("opens a served detail panel with SANs, fingerprint, issuer, and owner link", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", subject: "CN=api.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp-list" }],
    });
    apiMock.getCertificate.mockResolvedValue({
      id: "c1",
      tenant_id: "tenant-1",
      subject: "CN=api.example.com",
      sans: ["api.example.com", "10.0.0.10"],
      issuer: "CN=Issuing CA",
      key_algorithm: "ECDSA-P256",
      serial: "01",
      fingerprint: "sha256:detail",
      not_before: "2026-06-01T00:00:00Z",
      not_after: "2026-09-01T00:00:00Z",
      source: "agent",
      deployment_location: "cluster-a/api",
      owner_id: "owner-1",
      status: "active",
    });
    const user = userEvent.setup();
    renderCerts();

    await user.click(await screen.findByRole("button", { name: /view details/i }));

    expect(apiMock.getCertificate).toHaveBeenCalledWith("c1");
    const dialog = await screen.findByRole("dialog", { name: /certificate details/i });
    expect(dialog).toHaveTextContent("api.example.com");
    expect(dialog).toHaveTextContent("sha256:detail");
    expect(dialog).toHaveTextContent("CN=Issuing CA");
    expect(screen.getByRole("link", { name: "owner-1" })).toHaveAttribute("href", "/owners?owner=owner-1");
    // U1 replaced the "certificate chain coming soon" placeholder with a real renewal-history section.
    expect(dialog).toHaveTextContent("Renewal history");
    expect(dialog).toHaveTextContent("Credential activity timeline");
    expect(dialog).toHaveTextContent(/projected connector and rotation evidence/i);
    expect(dialog).toHaveTextContent("Connector delivery");
    expect(dialog).toHaveTextContent("no connector delivery receipt yet");
    expect(dialog).toHaveTextContent("Rotation run");
    expect(dialog).toHaveTextContent("no lifecycle rotation run yet");
  });

  it("ingests a PEM through the served mutation and prepends the returned row", async () => {
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.ingestCertificate.mockResolvedValue({
      id: "c-new",
      tenant_id: "tenant-1",
      subject: "CN=new.example.com",
      issuer: "CN=CA",
      fingerprint: "fp-new",
      status: "active",
    });
    const user = userEvent.setup();
    renderCerts();

    await user.click(screen.getByRole("button", { name: /add certificate/i }));
    // The ingest flow is a wizard: paste → assign ownership → review & ingest.
    await user.type(screen.getByLabelText(/certificate pem/i), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
    await user.click(screen.getByRole("button", { name: /next: assign ownership/i }));
    await user.type(screen.getByLabelText(/owner id/i), "owner-1");
    await user.type(screen.getByLabelText(/deployment location/i), "cluster-a/api");
    await user.click(screen.getByRole("button", { name: /next: review/i }));
    await user.click(screen.getByRole("button", { name: /ingest certificate/i }));

    await waitFor(() =>
      expect(apiMock.ingestCertificate).toHaveBeenCalledWith({
        pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        owner_id: "owner-1",
        source: "manual-ui",
        deployment_location: "cluster-a/api",
      }),
    );
    expect(await screen.findByText("CN=new.example.com")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/ingested CN=new.example.com/i);
  });

  it("queues Certificate Transparency precert and certificate submission from the served console", async () => {
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", subject: "CN=ct-submit.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp1" }],
    });
    apiMock.submitCertificateTransparency.mockResolvedValue({
      capability: "CAP-REV-06",
      queued: 2,
      logs: [
        {
          log_url: "https://ct.example.com",
          precertificate_queued: true,
          certificate_queued: true,
          precertificate_submission_id: "11111111-1111-1111-1111-111111111111",
          certificate_submission_id: "22222222-2222-2222-2222-222222222222",
        },
      ],
    });
    const user = userEvent.setup();
    const certPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
    const precertPEM = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";
    renderCerts();

    // CT submission opens as a dialog from the CRL & CT workspace tab.
    await user.click(await screen.findByRole("tab", { name: "CRL & CT" }));
    await user.click(screen.getByRole("button", { name: "Submit to CT" }));
    expect(await screen.findByRole("heading", { name: "Certificate Transparency" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Certificate PEM"), certPEM);
    await user.type(screen.getByLabelText("Precertificate PEM"), precertPEM);
    await user.type(screen.getByLabelText("CT logs"), "https://ct.example.com");
    await user.click(screen.getByRole("button", { name: /queue ct submission/i }));

    await waitFor(() =>
      expect(apiMock.submitCertificateTransparency).toHaveBeenCalledWith({
        certificate_pem: certPEM,
        precertificate_pem: precertPEM,
        chain_pem: [],
        logs: ["https://ct.example.com"],
        allow_private_endpoint: undefined,
      }),
    );
    expect(await screen.findByText("CAP-REV-06 queued 2")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("1 log target accepted.");
  });

  it("surfaces problem+json detail when ingest rejects invalid PEM", async () => {
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.ingestCertificate.mockRejectedValue(new ApiError(422, JSON.stringify({ detail: "could not parse certificate: bad PEM" })));
    const user = userEvent.setup();
    renderCerts();

    await user.click(screen.getByRole("button", { name: /add certificate/i }));
    await user.type(screen.getByLabelText(/certificate pem/i), "not a certificate");
    await user.click(screen.getByRole("button", { name: /next: assign ownership/i }));
    await user.click(screen.getByRole("button", { name: /next: review/i }));
    await user.click(screen.getByRole("button", { name: /ingest certificate/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not parse certificate/i);
  });
});
