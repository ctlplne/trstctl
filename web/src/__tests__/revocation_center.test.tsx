import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { RevocationCenter } from "@/pages/certificates/RevocationCenter";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    bulkRevokeCertificates: vi.fn(),
    getCertificate: vi.fn(),
    graphBlastRadius: vi.fn(),
    previewIdentityTransition: vi.fn(),
    transitionIdentity: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

const identities = [
  {
    id: "identity-payments",
    kind: "x509_certificate" as const,
    name: "payments.example.test",
    owner_id: "owner-payments",
    status: "deployed",
    attributes: { certificate_id: "certificate-payments" },
  },
];

const plan = {
  capability: "nhi_lifecycle_transition",
  ready: true,
  identity_id: "identity-payments",
  identity_name: "payments.example.test",
  identity_kind: "x509_certificate" as const,
  owner_id: "owner-payments",
  owner_name: "Payments platform",
  from: "deployed",
  to: "revoked",
  expected_version: 7,
  event_type: "identity.revoked",
  side_effect: true,
  side_effect_destination: "revocation.publish",
  request_fingerprint: "sha256:reviewed-revocation",
  required_permission: "identities:write",
  prerequisites: ["The identity is still deployed at lifecycle version 7."],
  preview_writes: [],
  preview_external_effects: [],
  execution_writes: ["Append one tenant-scoped identity.revoked event."],
  execution_external_effects: ["Publish updated CRL and OCSP status asynchronously."],
  verification_steps: ["Confirm the immutable identity.revoked audit event."],
  warnings: [],
  guidance: "This preview performed no write and contacted no external system.",
};

const brokerCertificate = {
  id: "11111111-1111-1111-1111-111111111111",
  tenant_id: "tenant-a",
  subject: "spiffe://example.test/agent/build-1",
  fingerprint: "b".repeat(64),
  serial: "0a",
  issuer: "trstctl-qa-intermediate",
  status: "active" as const,
  not_before: "2026-08-31T12:00:00Z",
  not_after: "2026-08-31T12:10:00Z",
  owner_id: "owner-build",
  source: "agent-broker",
};

function renderCenter() {
  return render(
    <MemoryRouter>
      <RevocationCenter
        identities={identities}
        health={{
          observed: true,
          summary: { endpoints: 2, fresh: 2, expiring: 0, stale: 0, unreachable: 0, unparseable: 0 },
          guidance: "Signed relay observations are current.",
          items: [],
        }}
        distributions={[
          {
            ca_id: "ca-primary",
            tenant_id: "tenant-a",
            full_number: 12,
            full_url: "/crl/tenant-a.crl",
            next_update: "2026-08-29T00:00:00Z",
            revoked_count: 4,
            shard_count: 4,
            shards: [],
            this_update: "2026-08-28T00:00:00Z",
          },
        ]}
      />
    </MemoryRouter>,
  );
}

describe("RevocationCenter", () => {
  it("requires an effect-free, version-bound review before one exact revoke", async () => {
    apiMock.previewIdentityTransition.mockReset().mockResolvedValue(plan);
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({
      node: { id: "cert:certificate-payments", kind: "certificate", name: "payments.example.test" },
      affected: [
        { id: "svc:checkout", kind: "service", name: "Checkout" },
        { id: "target:edge", kind: "deployment_target", name: "Edge load balancer" },
      ],
      by_kind: { service: 1, deployment_target: 1 },
      paths: [],
    });
    apiMock.transitionIdentity.mockReset().mockResolvedValue({ ...identities[0], status: "revoked" });
    const user = userEvent.setup();
    renderCenter();

    expect(screen.getByRole("heading", { name: "Choose credential and reason" })).toBeInTheDocument();
    expect(screen.getByText("2 signed endpoints are fresh.")).toBeInTheDocument();
    expect(screen.getByText("1 CA has a published CRL.")).toBeInTheDocument();
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();

    await user.selectOptions(screen.getByLabelText("Managed certificate"), "identity-payments");
    await user.selectOptions(screen.getByLabelText("RFC 5280 reason"), "keyCompromise");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    await waitFor(() => expect(apiMock.previewIdentityTransition).toHaveBeenCalledWith("identity-payments", "revoked", "keyCompromise"));
    expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:certificate-payments");
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(await screen.findByText("No changes were made")).toBeInTheDocument();
    expect(screen.getByText("2 downstream systems are linked to this credential.")).toBeInTheDocument();
    expect(screen.getByText("sha256:reviewed-revocation")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Continue to confirmation" }));
    const confirmation = screen.getByRole("region", { name: "Confirm irreversible revocation" });
    await user.type(within(confirmation).getByLabelText("Type the exact credential label"), "payments.example.test");
    await user.click(within(confirmation).getByRole("button", { name: "Revoke reviewed credential" }));

    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("identity-payments", "revoked", "keyCompromise", undefined, undefined, 7));
    expect(await screen.findByRole("status")).toHaveTextContent("Revocation accepted and the identity now reads revoked.");
    expect(screen.getByRole("link", { name: "Open immutable audit evidence" })).toHaveAttribute("href", "/audit?type=identity.revoked&q=identity-payments");
  });

  it("keeps execution locked when preview fails and reports unknown propagation honestly", async () => {
    apiMock.previewIdentityTransition.mockReset().mockRejectedValue(new Error("preview service unavailable"));
    apiMock.graphBlastRadius.mockReset();
    apiMock.transitionIdentity.mockReset();
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <RevocationCenter identities={identities} health={null} distributions={[]} />
      </MemoryRouter>,
    );

    expect(screen.getByText("Propagation health is unknown because no signed observation was loaded.")).toBeInTheDocument();
    expect(screen.getByText("No published CRL was loaded. Publication is not proven.")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Managed certificate"), "identity-payments");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("preview service unavailable");
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Choose credential and reason" })).toBeInTheDocument();
  });

  it("recovers an exact broker certificate from a durable deep link without inventing a lifecycle identity", async () => {
    const revoked = {
      ...brokerCertificate,
      status: "revoked" as const,
      revoked_at: "2026-09-01T13:50:00Z",
      revocation_reason: "cessationOfOperation",
    };
    apiMock.getCertificate
      .mockReset()
      .mockResolvedValueOnce(brokerCertificate)
      .mockResolvedValueOnce(brokerCertificate)
      .mockResolvedValueOnce(brokerCertificate)
      .mockResolvedValueOnce(revoked);
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({
      node: { id: `cert:${brokerCertificate.id}`, kind: "certificate", name: brokerCertificate.subject },
      affected: [],
      by_kind: {},
      paths: [],
    });
    apiMock.bulkRevokeCertificates.mockReset().mockResolvedValue({
      items: [{ id: brokerCertificate.id, status: "revoked" }],
      total_matched: 1,
      total_revoked: 1,
      total_skipped: 0,
      total_failed: 0,
    });
    apiMock.previewIdentityTransition.mockReset();
    apiMock.transitionIdentity.mockReset();
    const onCertificateRevoked = vi.fn();
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <RevocationCenter
          certificates={[]}
          targetCertificateID={brokerCertificate.id}
          identities={[]}
          health={null}
          distributions={[]}
          onCertificateRevoked={onCertificateRevoked}
        />
      </MemoryRouter>,
    );

    await screen.findByRole("option", { name: `${brokerCertificate.subject} · active · exact certificate record` });
    expect(screen.getByLabelText("Managed certificate")).toHaveValue(`certificate:${brokerCertificate.id}`);
    expect(screen.queryByText("No managed X.509 identity is currently in a revocable lifecycle state.")).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("RFC 5280 reason"), "cessationOfOperation");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    await waitFor(() => expect(apiMock.getCertificate).toHaveBeenCalledTimes(2));
    expect(apiMock.graphBlastRadius).toHaveBeenCalledWith(`cert:${brokerCertificate.id}`);
    expect(apiMock.bulkRevokeCertificates).not.toHaveBeenCalled();
    expect(apiMock.previewIdentityTransition).not.toHaveBeenCalled();
    expect(await screen.findByText("Exact certificate record")).toBeInTheDocument();
    expect(screen.getByText(brokerCertificate.id)).toBeInTheDocument();
    expect(screen.getByText(brokerCertificate.fingerprint)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Continue to confirmation" }));
    const confirmation = screen.getByRole("region", { name: "Confirm irreversible revocation" });
    await user.type(within(confirmation).getByLabelText("Type the exact credential label"), brokerCertificate.subject);
    await user.click(within(confirmation).getByRole("button", { name: "Revoke reviewed credential" }));

    await waitFor(() =>
      expect(apiMock.bulkRevokeCertificates).toHaveBeenCalledWith({ certificate_ids: [brokerCertificate.id], reason: "cessationOfOperation" }),
    );
    expect(apiMock.getCertificate).toHaveBeenCalledTimes(4);
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(onCertificateRevoked).toHaveBeenCalledWith(revoked);
    expect(await screen.findByRole("status")).toHaveTextContent("Revocation accepted and the exact certificate now reads revoked.");
    expect(screen.getByRole("link", { name: "Open immutable audit evidence" })).toHaveAttribute(
      "href",
      `/audit?type=certificate.revocation.batch.applied&q=${brokerCertificate.id}`,
    );
  });

  it("uses the exact certificate ID when a broker record has no subject and never accepts an empty destructive confirmation", async () => {
    const subjectless = { ...brokerCertificate, id: "22222222-2222-4222-8222-222222222222", subject: "" };
    const revoked = {
      ...subjectless,
      status: "revoked" as const,
      revoked_at: "2026-09-01T13:55:00Z",
      revocation_reason: "cessationOfOperation",
    };
    apiMock.getCertificate
      .mockReset()
      .mockResolvedValueOnce(subjectless)
      .mockResolvedValueOnce(subjectless)
      .mockResolvedValueOnce(subjectless)
      .mockResolvedValueOnce(revoked);
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({ node: null, affected: [], by_kind: {}, paths: [] });
    apiMock.bulkRevokeCertificates.mockReset().mockResolvedValue({
      items: [{ id: subjectless.id, status: "revoked" }],
      total_matched: 1,
      total_revoked: 1,
      total_skipped: 0,
      total_failed: 0,
    });
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <RevocationCenter certificates={[]} targetCertificateID={subjectless.id} identities={[]} health={null} distributions={[]} />
      </MemoryRouter>,
    );

    await screen.findByRole("option", { name: `${subjectless.id} · active · exact certificate record` });
    await user.selectOptions(screen.getByLabelText("RFC 5280 reason"), "cessationOfOperation");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Continue to confirmation" }));

    const confirmation = screen.getByRole("region", { name: "Confirm irreversible revocation" });
    expect(confirmation).toHaveTextContent(`Revoking “${subjectless.id}”`);
    const input = within(confirmation).getByLabelText("Type the exact credential label");
    expect(input).toHaveAttribute("placeholder", subjectless.id);
    const execute = within(confirmation).getByRole("button", { name: "Revoke reviewed credential" });
    expect(execute).toBeDisabled();
    await user.click(execute);
    expect(apiMock.bulkRevokeCertificates).not.toHaveBeenCalled();

    await user.type(input, subjectless.id);
    expect(execute).toBeEnabled();
    await user.click(execute);

    await waitFor(() =>
      expect(apiMock.bulkRevokeCertificates).toHaveBeenCalledWith({
        certificate_ids: [subjectless.id],
        reason: "cessationOfOperation",
      }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent("Revocation accepted and the exact certificate now reads revoked.");
  });

  it("fails closed when a linked certificate is already revoked", async () => {
    apiMock.getCertificate.mockReset().mockResolvedValue({ ...brokerCertificate, status: "revoked" });
    apiMock.bulkRevokeCertificates.mockReset();
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <RevocationCenter certificates={[]} targetCertificateID={brokerCertificate.id} identities={[]} health={null} distributions={[]} />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText("This exact certificate already reads revoked. Open its audit evidence instead of submitting it again."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review exact plan" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(apiMock.bulkRevokeCertificates).not.toHaveBeenCalled();
  });

  it("fails closed when the linked certificate is missing or outside the caller tenant", async () => {
    apiMock.getCertificate.mockReset().mockRejectedValue(new Error("certificate not found"));
    apiMock.bulkRevokeCertificates.mockReset();

    render(
      <MemoryRouter>
        <RevocationCenter certificates={[]} targetCertificateID={brokerCertificate.id} identities={[]} health={null} distributions={[]} />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("certificate not found");
    expect(screen.getByRole("button", { name: "Review exact plan" })).toBeDisabled();
    expect(apiMock.bulkRevokeCertificates).not.toHaveBeenCalled();
  });

  it("requires a new review when the exact certificate changes before execution", async () => {
    apiMock.getCertificate
      .mockReset()
      .mockResolvedValueOnce(brokerCertificate)
      .mockResolvedValueOnce(brokerCertificate)
      .mockResolvedValueOnce({ ...brokerCertificate, fingerprint: "c".repeat(64) });
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({ node: null, affected: [], by_kind: {}, paths: [] });
    apiMock.bulkRevokeCertificates.mockReset();
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <RevocationCenter certificates={[]} targetCertificateID={brokerCertificate.id} identities={[]} health={null} distributions={[]} />
      </MemoryRouter>,
    );

    await screen.findByRole("option", { name: `${brokerCertificate.subject} · active · exact certificate record` });
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Continue to confirmation" }));
    const confirmation = screen.getByRole("region", { name: "Confirm irreversible revocation" });
    await user.type(within(confirmation).getByLabelText("Type the exact credential label"), brokerCertificate.subject);
    await user.click(within(confirmation).getByRole("button", { name: "Revoke reviewed credential" }));

    expect(await within(confirmation).findByRole("alert")).toHaveTextContent("The certificate changed after review");
    expect(apiMock.bulkRevokeCertificates).not.toHaveBeenCalled();
  });
});
