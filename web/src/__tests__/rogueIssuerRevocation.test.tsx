import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { RogueCertificatePanel } from "@/pages/certificates/RogueCertificatePanel";
import type { RogueCertificateFinding, RogueCertificatePosture } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { externalCAs: vi.fn(), revokeRogueCertificateAtIssuer: vi.fn(), bulkRevokeCertificates: vi.fn(), takedownRogueCertificate: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const discoveryID = "0f9e8d7c-6b5a-4c3d-9e2f-1a0b9c8d7e6f";
const certificateID = "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d";

function finding(overrides: Partial<RogueCertificateFinding>): RogueCertificateFinding {
  return {
    id: overrides.id ?? "f",
    kind: "rogue_certificate",
    policy_status: "rogue",
    subject: "shadow.corp.example",
    source: "ct_log",
    finding_types: ["ct_unexpected_issuance"],
    severity: "high",
    risk_score: 90,
    recommendation: "Investigate this Certificate Transparency hit.",
    evidence_refs: [],
    ...overrides,
  };
}

const posture: RogueCertificatePosture = {
  capability: "CAP-REV-05",
  generated_at: "2026-10-31T20:00:00Z",
  coverage: [],
  summary: {
    total_analyzed: 3,
    findings: 3,
    rogue: 3,
    non_compliant: 0,
    ct_unexpected: 2,
    weak_key: 0,
    distrusted_issuer: 0,
    lifetime_violations: 0,
    expired_active: 0,
    owner_missing: 0,
    issuer_missing: 0,
    critical: 0,
    high: 3,
    medium: 0,
    low: 0,
    recommendations: 3,
    policy_violations: 0,
  },
  findings: [
    finding({ id: "discovery:" + discoveryID, discovery_id: discoveryID, subject: "shadow.corp.example" }),
    finding({ id: "certificate:" + certificateID, certificate_id: certificateID, subject: "kept.corp.example", source: "inventory" }),
    finding({
      id: "discovery:revoked",
      discovery_id: "1e2d3c4b-5a69-4788-9a0b-c1d2e3f4a5b6",
      subject: "gone.corp.example",
      issuer_revocation: {
        discovery_id: "1e2d3c4b-5a69-4788-9a0b-c1d2e3f4a5b6",
        authority_id: "corp-digicert",
        serial: "1a2b",
        reason: "keyCompromise",
        status: "revoked",
        attempts: 1,
      },
    }),
  ],
  recommended_actions: [],
  evidence_refs: [],
  policy_evaluated: 0,
  policy_evaluation_errors: 0,
};

function rowOf(subject: string): HTMLElement {
  const row = screen.getByText(subject).closest("tr");
  expect(row).not.toBeNull();
  return row as HTMLElement;
}

describe("A163 revoke a rogue certificate at its issuer", () => {
  beforeEach(() => {
    // A163-L3: the server says how each authority revokes a found certificate.
    apiMock.externalCAs.mockReset().mockResolvedValue([
      { id: "corp-digicert", type: "digicert", name: "Corp DigiCert", status: "available", revokes_by_serial: true, revokes_by_certificate: false },
      { id: "corp-venafi", type: "venafi", name: "Corp Venafi", status: "available", revokes_by_serial: false, revokes_by_certificate: false },
      { id: "corp-acme", type: "letsencrypt", name: "Corp ACME", status: "available", revokes_by_serial: false, revokes_by_certificate: true },
      { id: "corp-next", type: "nextca", name: "Corp NextCA", status: "available", revokes_by_serial: true, revokes_by_certificate: false },
      {
        id: "corp-digicert-down",
        type: "digicert",
        name: "Corp DigiCert (down)",
        status: "unavailable",
        revokes_by_serial: false,
        revokes_by_certificate: false,
      },
    ]);
    apiMock.revokeRogueCertificateAtIssuer.mockReset();
    apiMock.bulkRevokeCertificates.mockReset();
  });

  it("revokes a CT finding by serial at a CA that can, and shows a confirmed one", async () => {
    apiMock.revokeRogueCertificateAtIssuer.mockResolvedValue({
      discovery_id: discoveryID,
      authority_id: "corp-digicert",
      serial: "1a2b",
      reason: "keyCompromise",
      status: "queued",
      attempts: 0,
    });
    render(<RogueCertificatePanel posture={posture} />);
    expect(within(rowOf("gone.corp.example")).getByText("Revoked at corp-digicert")).toBeInTheDocument();
    const shadow = rowOf("shadow.corp.example");
    await within(shadow).findByRole("option", { name: "Corp DigiCert" });
    expect(within(shadow).queryByRole("option", { name: "Corp Venafi" })).not.toBeInTheDocument();
    // N10: an ACME CA revokes a found certificate from its bytes.
    expect(within(shadow).getByRole("option", { name: "Corp ACME" })).toBeInTheDocument();
    // A163-L3: the served property decides, not a list of kinds in the console.
    expect(within(shadow).getByRole("option", { name: "Corp NextCA" })).toBeInTheDocument();
    expect(within(shadow).queryByRole("option", { name: "Corp DigiCert (down)" })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Revocation reason"), { target: { value: "keyCompromise" } });
    fireEvent.change(within(shadow).getByLabelText("Issuing CA"), { target: { value: "corp-digicert" } });
    fireEvent.click(within(shadow).getByRole("button", { name: "Revoke at issuer" }));
    await waitFor(() =>
      expect(apiMock.revokeRogueCertificateAtIssuer).toHaveBeenCalledWith(
        { discovery_id: discoveryID, authority_id: "corp-digicert", reason: "keyCompromise" },
        expect.any(String),
      ),
    );
    expect(await screen.findByText("Revocation queued at corp-digicert.")).toBeInTheDocument();
  });

  it("revokes an inventory finding through the exact revocation", async () => {
    apiMock.bulkRevokeCertificates.mockResolvedValue({ total_matched: 1, total_queued: 1, total_revoked: 0, total_skipped: 0, total_failed: 0, items: [] });
    render(<RogueCertificatePanel posture={posture} />);
    const kept = rowOf("kept.corp.example");
    expect(within(kept).getByRole("button", { name: "Revoke at issuer" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Revocation reason"), { target: { value: "superseded" } });
    fireEvent.click(within(kept).getByRole("button", { name: "Revoke at issuer" }));
    await waitFor(() => expect(apiMock.bulkRevokeCertificates).toHaveBeenCalledWith({ certificate_ids: [certificateID], reason: "superseded" }));
    expect(await screen.findByText("Revocation: 1 queued, 0 revoked, 0 failed.")).toBeInTheDocument();
  });
});

// A184-L1: a posture that read a full page says the estate is not fully rated.
describe("rogue certificate posture read limit", () => {
  it("says a full page was rated, and only then", () => {
    const { unmount } = render(<RogueCertificatePanel posture={{ ...posture, read_limited: true }} />);
    expect(screen.getByRole("status")).toHaveTextContent(
      "This posture rated the first 500 certificates and the first 500 discovery findings. A larger inventory is not fully rated here",
    );
    unmount();
    render(<RogueCertificatePanel posture={posture} />);
    expect(screen.queryByText(/is not fully rated here/)).not.toBeInTheDocument();
  });
});
