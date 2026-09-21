import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { PQCCampaigns } from "@/pages/posture/PQCCampaigns";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    pqcCampaigns: vi.fn(),
    pqcCampaign: vi.fn(),
    createPQCCampaign: vi.fn(),
    createCryptoReadinessAction: vi.fn(),
    setPQCCampaignReadiness: vi.fn(),
    dispositionPQCCampaignFinding: vi.fn(),
    closePQCCampaign: vi.fn(),
    pqcCampaignEvidence: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const asset = {
  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  kind: "certificate-key",
  location: "payments.internal:443",
  algorithm: "RSA",
  key_bits: 2048,
  strength: "legacy",
  out_of_policy: true,
  quantum_vulnerable: true,
  migration_generation: "generation-1",
  migration_standard: "FIPS 204",
  migration_target: "ML-DSA-65",
  reasons: ["RSA is quantum-vulnerable"],
};

const finding = {
  finding_id: asset.id,
  finding_digest: `sha256:${"a".repeat(64)}`,
  kind: asset.kind,
  location: asset.location,
  algorithm: asset.algorithm,
  key_bits: asset.key_bits,
  disposition: "pending" as const,
  evidence_refs: [],
  evidence_digests: [],
};

const campaign = {
  id: "77777777-7777-4777-8777-777777777777",
  tenant_id: "11111111-1111-1111-1111-111111111111",
  name: "Payments PQC migration",
  owner: "team:payments",
  deadline: "2026-12-01T00:00:00Z",
  wave: "wave-1",
  readiness_criteria: ["owner approved"],
  readiness_status: "pending" as const,
  readiness_evidence_refs: [],
  status: "open" as const,
  finding_count: 1,
  pending_count: 1,
  remediated_count: 0,
  excepted_count: 0,
  automated_execution_available: false,
  automated_execution_note: "Campaign tracking works without a license.",
  created_at: "2026-07-28T00:00:00Z",
  updated_at: "2026-07-28T00:00:00Z",
  findings: [finding],
};

function renderCampaigns() {
  return render(
    <AppQueryProvider>
      <PQCCampaigns assets={[asset]} />
    </AppQueryProvider>,
  );
}

describe("core PQC migration campaigns", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.pqcCampaigns.mockResolvedValue({ items: [campaign], next_cursor: "" });
    apiMock.pqcCampaign.mockResolvedValue(campaign);
    apiMock.createPQCCampaign.mockResolvedValue(campaign);
    apiMock.createCryptoReadinessAction.mockResolvedValue(campaign);
    apiMock.setPQCCampaignReadiness.mockResolvedValue({ ...campaign, readiness_status: "passed" });
    apiMock.dispositionPQCCampaignFinding.mockResolvedValue({
      ...campaign,
      pending_count: 0,
      remediated_count: 1,
      findings: [{ ...finding, disposition: "remediated" }],
    });
    apiMock.closePQCCampaign.mockResolvedValue({ ...campaign, status: "closed" });
    apiMock.pqcCampaignEvidence.mockResolvedValue({
      format: "trstctl.pqc-migration-campaign-closure.v1",
      signed_closure: "header.payload.signature",
      public_jwks: { keys: [] },
    });
  });

  it("renders an accessible standalone Community list and creation workflow", async () => {
    const { container } = renderCampaigns();
    expect(await screen.findByText("Payments PQC migration")).toBeInTheDocument();
    expect(screen.getByText("Tracking works in Community")).toBeInTheDocument();
    expect(screen.getByRole("checkbox")).toHaveAccessibleName("payments.internal:443 RSA");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("treats a JSON null campaign list as an honest empty state", async () => {
    apiMock.pqcCampaigns.mockResolvedValue({ items: null, next_cursor: "" });
    renderCampaigns();
    expect(await screen.findByText("No PQC campaigns yet")).toBeInTheDocument();
    expect(screen.queryByText("This page stopped unexpectedly")).not.toBeInTheDocument();
  });

  it("creates a campaign from CBOM findings", async () => {
    const user = userEvent.setup();
    renderCampaigns();
    await screen.findByText("Payments PQC migration");
    await user.type(screen.getByLabelText("Campaign name"), "Gateway migration");
    await user.type(screen.getByLabelText("Owner"), "team:edge");
    await user.type(screen.getByLabelText("Deadline"), "2026-12-01T10:00");
    await user.clear(screen.getByLabelText("Wave"));
    await user.type(screen.getByLabelText("Wave"), "wave-2");
    await user.type(screen.getByLabelText("Readiness criteria"), "owner approved\nrollback documented");
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Create campaign" }));
    await waitFor(() =>
      expect(apiMock.createCryptoReadinessAction).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Gateway migration",
          owner: "team:edge",
          wave: "wave-2",
          finding_ids: [asset.id],
          readiness_criteria: ["owner approved", "rollback documented"],
        }),
      ),
    );
  });

  it("wires readiness and finding evidence mutations", async () => {
    const user = userEvent.setup();
    renderCampaigns();
    await user.click(await screen.findByRole("button", { name: /Payments PQC migration/ }));
    const detail = await screen.findByRole("heading", { name: "Payments PQC migration", level: 4 });

    const region = detail.closest("section");
    if (!region) throw new Error("campaign detail region missing");
    await user.type(within(region).getAllByLabelText("Evidence references")[0]!, "change:CAB-2048");
    await user.click(within(region).getByRole("button", { name: "Record readiness" }));
    await waitFor(() =>
      expect(apiMock.setPQCCampaignReadiness).toHaveBeenCalledWith(campaign.id, {
        status: "passed",
        evidence_refs: ["change:CAB-2048"],
      }),
    );

    await user.type(within(region).getByLabelText("Reason"), "operator replaced the certificate");
    await user.type(within(region).getAllByLabelText("Evidence references")[1]!, "audit:certificate.issued");
    await user.type(within(region).getByLabelText("Evidence SHA-256 digests"), `sha256:${"b".repeat(64)}`);
    await user.click(within(region).getByRole("button", { name: "Record disposition" }));
    await waitFor(() => expect(apiMock.dispositionPQCCampaignFinding).toHaveBeenCalled());
  });

  it("closes a ready campaign and exports signed closure evidence", async () => {
    const user = userEvent.setup();
    const ready = {
      ...campaign,
      readiness_status: "passed" as const,
      readiness_evidence_refs: ["change:CAB-2048"],
      pending_count: 0,
      remediated_count: 1,
      findings: [{ ...finding, disposition: "remediated" as const }],
    };
    apiMock.pqcCampaign.mockResolvedValue(ready);
    apiMock.closePQCCampaign.mockResolvedValue({ ...ready, status: "closed" });
    const first = renderCampaigns();
    await user.click(await screen.findByRole("button", { name: /Payments PQC migration/ }));
    await user.click(await screen.findByRole("button", { name: "Close and sign campaign" }));
    await waitFor(() => expect(apiMock.closePQCCampaign).toHaveBeenCalledWith(campaign.id));
    first.unmount();

    const closed = { ...ready, status: "closed" as const };
    apiMock.pqcCampaigns.mockResolvedValue({ items: [closed], next_cursor: "" });
    apiMock.pqcCampaign.mockResolvedValue(closed);
    renderCampaigns();
    await user.click(await screen.findByRole("button", { name: /Payments PQC migration/ }));
    await user.click(await screen.findByRole("button", { name: "Load signed closure evidence" }));
    expect(((await screen.findByLabelText("Signed PQC campaign closure evidence")) as HTMLTextAreaElement).value).toContain("header.payload.signature");
  });

  it("surfaces list failures honestly", async () => {
    apiMock.pqcCampaigns.mockRejectedValue(new Error("campaign store unavailable"));
    renderCampaigns();
    expect(await screen.findByRole("alert", undefined, { timeout: 3_000 })).toHaveTextContent("campaign store unavailable");
  });
});
