import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { RevocationCenter } from "@/pages/certificates/RevocationCenter";
import { AppQueryProvider } from "@/lib/query";
import { ApiError } from "@/lib/api";

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
        { id: "id:payments", kind: "credential", name: "Payments lifecycle identity" },
        { id: "res:checkout", kind: "resource", name: "Checkout" },
        { id: "res:edge", kind: "resource", name: "Edge load balancer" },
      ],
      by_kind: {
        credential: [{ id: "id:payments", kind: "credential", name: "Payments lifecycle identity" }],
        resource: [
          { id: "res:checkout", kind: "resource", name: "Checkout" },
          { id: "res:edge", kind: "resource", name: "Edge load balancer" },
        ],
      },
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
    expect(screen.getByText("Payments lifecycle identity")).toBeInTheDocument();
    expect(screen.getByText("Checkout")).toBeInTheDocument();
    expect(screen.getByText("Edge load balancer")).toBeInTheDocument();
    expect(screen.queryByText(/\[object Object\]/)).not.toBeInTheDocument();
    expect(screen.getByText("sha256:reviewed-revocation")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Continue to confirmation" }));
    const confirmation = screen.getByRole("region", { name: "Confirm irreversible revocation" });
    await user.type(within(confirmation).getByLabelText("Type the exact credential label"), "payments.example.test");
    await user.click(within(confirmation).getByRole("button", { name: "Revoke reviewed credential" }));

    await waitFor(() =>
      expect(apiMock.transitionIdentity).toHaveBeenCalledWith("identity-payments", "revoked", "keyCompromise", undefined, expect.any(String), 7),
    );
    expect(await screen.findByRole("status")).toHaveTextContent("Revocation accepted and the identity now reads revoked.");
    expect(screen.getByRole("link", { name: "Open immutable audit evidence" })).toHaveAttribute("href", "/audit?type=identity.revoked&q=identity-payments");
  });

  it("recovers the same reviewed identity revocation after approval and remount", async () => {
    apiMock.previewIdentityTransition.mockReset().mockResolvedValue(plan);
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({ node: { id: "cert:certificate-payments", kind: "credential", name: "payments" }, affected: [] });
    apiMock.transitionIdentity
      .mockReset()
      .mockRejectedValueOnce(
        new ApiError(
          403,
          JSON.stringify({
            code: "identity_approval_required",
            approval_request_id: "1ca14715-666f-5ed8-bd88-7b262fe543f5",
            approval_status: "pending",
            detail: "awaits independent approval",
          }),
        ),
      )
      .mockResolvedValue({ ...identities[0], status: "revoked" });
    const user = userEvent.setup();
    async function reviewAndConfirm() {
      await user.selectOptions(screen.getByLabelText("Managed certificate"), "identity-payments");
      await user.selectOptions(screen.getByLabelText("RFC 5280 reason"), "keyCompromise");
      await user.click(screen.getByRole("button", { name: "Review exact plan" }));
      await user.click(await screen.findByRole("button", { name: "Continue to confirmation" }));
      const confirmation = screen.getByRole("region", { name: "Confirm irreversible revocation" });
      await user.type(within(confirmation).getByLabelText("Type the exact credential label"), "payments.example.test");
      await user.click(within(confirmation).getByRole("button", { name: "Revoke reviewed credential" }));
    }
    const first = renderCenter();
    await reviewAndConfirm();
    expect(await screen.findByRole("alert")).toHaveTextContent("awaits independent approval");
    expect(screen.getByRole("link", { name: "Open approval requests" })).toHaveAttribute("href", "/approvals");
    expect(apiMock.transitionIdentity.mock.calls[0]?.[4]).toEqual(expect.any(String));
    first.unmount();
    renderCenter();
    await reviewAndConfirm();
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(2));
    expect(apiMock.transitionIdentity.mock.calls[1]).toEqual(apiMock.transitionIdentity.mock.calls[0]);
    expect(await screen.findByRole("status")).toHaveTextContent("Revocation accepted");
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
  it("keeps an external command pending through a failed read and confirms only the selected leaf without resubmitting", async () => {
    apiMock.getCertificate.mockReset().mockResolvedValue(brokerCertificate);
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({ node: null, affected: [], by_kind: {}, paths: [] });
    apiMock.bulkRevokeCertificates.mockReset().mockResolvedValue({
      items: [{ id: brokerCertificate.id, status: "queued" }],
      total_matched: 1,
      total_queued: 1,
      total_revoked: 0,
      total_skipped: 0,
      total_failed: 0,
    });
    const onCertificateRevoked = vi.fn();
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <AppQueryProvider>
          <RevocationCenter
            certificates={[brokerCertificate]}
            targetCertificateID={brokerCertificate.id}
            identities={[]}
            health={null}
            distributions={[]}
            onCertificateRevoked={onCertificateRevoked}
          />
        </AppQueryProvider>
      </MemoryRouter>,
    );
    await screen.findByRole("option", { name: `${brokerCertificate.subject} · active · exact certificate record` });
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Continue to confirmation" }));
    await user.type(screen.getByLabelText("Type the exact credential label"), brokerCertificate.subject);
    await user.click(screen.getByRole("button", { name: "Revoke reviewed credential" }));
    expect(await screen.findByRole("status")).toHaveTextContent("the issuing CA has not yet confirmed it");
    expect(onCertificateRevoked).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Revoke reviewed credential" })).not.toBeInTheDocument();

    apiMock.getCertificate.mockRejectedValue(new Error("unavailable"));
    await user.click(screen.getByRole("button", { name: "Refresh revocation result" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Revocation remains unconfirmed");
    expect(onCertificateRevoked).not.toHaveBeenCalled();

    apiMock.getCertificate.mockResolvedValue({ ...brokerCertificate, status: "revoked", fingerprint: "c".repeat(64) });
    await user.click(screen.getByRole("button", { name: "Refresh revocation result" }));
    await waitFor(() => expect(apiMock.getCertificate).toHaveBeenCalled());
    expect(onCertificateRevoked).not.toHaveBeenCalled();
    expect(screen.getByRole("status")).toHaveTextContent("the issuing CA has not yet confirmed it");

    const revoked = { ...brokerCertificate, status: "revoked", revocation_reason: "keyCompromise" };
    apiMock.getCertificate.mockResolvedValue(revoked);
    // The visibility-aware live query detects the issuer result without another mutation.
    expect(await screen.findByText("Revocation accepted and the exact certificate now reads revoked.", {}, { timeout: 4000 })).toBeInTheDocument();
    expect(onCertificateRevoked).toHaveBeenCalledExactlyOnceWith(revoked);
    expect(apiMock.bulkRevokeCertificates).toHaveBeenCalledTimes(1);
  });
});
