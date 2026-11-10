import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AccessReviewGenerate, AccessReviewOutcome, AccessReviewSignedResult } from "@/pages/policy/AccessReviewActs";
import type { NHIReviewItem } from "@/lib/api";

const { apiMock, can } = vi.hoisted(() => ({
  apiMock: { generateNHIReviewCampaign: vi.fn(), nhiReviewResult: vi.fn(), retryNHIReviewRevocation: vi.fn() },
  can: { value: true },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => can.value }));

const item = (patch: Partial<NHIReviewItem>): NHIReviewItem => ({
  item_id: "i1",
  nhi_id: "pam:p1",
  nhi_kind: "pam_session",
  display_name: "readonly@pg-main",
  resource: "res:pam:postgres:pg-main",
  entitlement: "readonly",
  risk: "high",
  evidence_refs: [],
  status: "revoked",
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
  ...patch,
});

describe("Q1 access reviews that act", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    can.value = true;
  });

  it("generates a review from who can reach a resource, retrying with the same key", async () => {
    apiMock.generateNHIReviewCampaign.mockRejectedValueOnce(new Error("network"));
    apiMock.generateNHIReviewCampaign.mockResolvedValueOnce({
      campaign: { id: "c1", item_count: 2 },
      coverage: { sources: [], not_covered: [], note: "An empty answer is not proof." },
    });
    const onGenerated = vi.fn();
    const user = userEvent.setup();
    render(<AccessReviewGenerate onGenerated={onGenerated} />);
    await user.type(screen.getByRole("textbox", { name: "Campaign name" }), "pg-main access");
    await user.type(screen.getByRole("textbox", { name: /Graph node/ }), "res:pam:postgres:pg-main");
    await user.type(screen.getByRole("textbox", { name: "Assigned reviewer" }), "bob");
    await user.click(screen.getByRole("button", { name: "Generate review" }));
    await user.click(screen.getByRole("button", { name: "Generate review" }));
    const [first, second] = apiMock.generateNHIReviewCampaign.mock.calls;
    expect(first[0]).toEqual({ name: "pg-main access", source: "graph_reachers", target: "res:pam:postgres:pg-main", reviewer_subject: "bob" });
    expect(second[1]).toBe(first[1]);
    expect(onGenerated).toHaveBeenCalledWith("c1");
    expect(await screen.findByText("Coverage: An empty answer is not proof.")).toBeInTheDocument();
  });

  it("builds a stale-owner review with a window", async () => {
    apiMock.generateNHIReviewCampaign.mockResolvedValueOnce({ campaign: { id: "c2", item_count: 1 } });
    const user = userEvent.setup();
    render(<AccessReviewGenerate onGenerated={() => {}} />);
    await user.type(screen.getByRole("textbox", { name: "Campaign name" }), "stale owners");
    await user.selectOptions(screen.getByRole("combobox", { name: "Build from" }), "stale_owner_attestation");
    await user.type(screen.getByRole("spinbutton"), "45");
    await user.click(screen.getByRole("button", { name: "Generate review" }));
    expect(apiMock.generateNHIReviewCampaign.mock.calls[0][0]).toEqual({ name: "stale owners", source: "stale_owner_attestation", older_than_days: 45 });
  });

  it("is hidden without access:write", () => {
    can.value = false;
    const { container } = render(<AccessReviewGenerate onGenerated={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("retries a failed revocation with a reason, reusing the key on a network retry (Q1-L2)", async () => {
    const campaign = { id: "c1", items: [] };
    apiMock.retryNHIReviewRevocation.mockRejectedValueOnce(new Error("network"));
    apiMock.retryNHIReviewRevocation.mockResolvedValueOnce(campaign);
    const onRetried = vi.fn();
    const user = userEvent.setup();
    render(
      <AccessReviewOutcome
        item={item({ revocation_status: "failed", revocation_detail: "the PAM session's revocation failed" })}
        campaignId="c1"
        onRetried={onRetried}
      />,
    );
    expect(screen.getByText(/retries a failed revocation on its own/)).toBeInTheDocument();
    const retry = screen.getByRole("button", { name: "Retry revocation" });
    expect(retry).toBeDisabled();
    await user.type(screen.getByRole("textbox", { name: "Why retry now" }), "provider repaired");
    await user.click(retry);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    await user.click(retry);
    const [first, second] = apiMock.retryNHIReviewRevocation.mock.calls;
    expect(first.slice(0, 3)).toEqual(["c1", "i1", { reason: "provider repaired" }]);
    expect(second[3]).toBe(first[3]);
    expect(onRetried).toHaveBeenCalledWith(campaign);
  });

  it("offers no retry without access:write, and none for a revocation that did not fail", () => {
    can.value = false;
    const { rerender } = render(
      <AccessReviewOutcome item={item({ revocation_status: "failed", revocation_detail: "refused" })} campaignId="c1" onRetried={() => {}} />,
    );
    expect(screen.getByText(/retries a failed revocation on its own/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry revocation" })).not.toBeInTheDocument();
    can.value = true;
    rerender(<AccessReviewOutcome item={item({ revocation_status: "requested", revocation_detail: "requested" })} campaignId="c1" onRetried={() => {}} />);
    expect(screen.queryByRole("button", { name: "Retry revocation" })).not.toBeInTheDocument();
  });

  it("says what a decision did", () => {
    const { rerender } = render(<AccessReviewOutcome item={item({ revocation_status: "requested", revocation_detail: "PAM session revocation requested" })} />);
    expect(screen.getByText("Revocation requested")).toBeInTheDocument();
    rerender(<AccessReviewOutcome item={item({ revocation_status: "closed", closing_evidence: "PAM session revoked at 2026-11-01T00:01:00Z" })} />);
    expect(screen.getByText("PAM session revoked at 2026-11-01T00:01:00Z")).toBeInTheDocument();
    rerender(<AccessReviewOutcome item={item({ revocation_status: "failed", revocation_detail: "refused" })} />);
    expect(screen.getByText("Revocation failed")).toBeInTheDocument();
    rerender(<AccessReviewOutcome item={item({ status: "certified", next_review_at: "2027-01-30T00:00:00Z" })} />);
    expect(screen.getByText(/no upstream right changed/)).toBeInTheDocument();
  });

  it("says an item closed because trstctl no longer holds the credential (Q1-L3)", () => {
    render(
      <AccessReviewOutcome item={item({ revocation_status: "closed", closed_as: "gone", closing_evidence: "gone: trstctl no longer holds the API token" })} />,
    );
    expect(screen.getByText("Closed: trstctl no longer holds this credential")).toBeInTheDocument();
    expect(screen.getByText("gone: trstctl no longer holds the API token")).toBeInTheDocument();
    expect(screen.queryByText("Closed: the credential reads revoked")).not.toBeInTheDocument();
  });

  it("generates a privileged account certification with no target (A276)", async () => {
    apiMock.generateNHIReviewCampaign.mockResolvedValueOnce({ campaign: { id: "c2", item_count: 4 } });
    const onGenerated = vi.fn();
    const user = userEvent.setup();
    render(<AccessReviewGenerate onGenerated={onGenerated} />);
    await user.type(screen.getByRole("textbox", { name: "Campaign name" }), "Q4 privileged accounts");
    await user.selectOptions(screen.getByRole("combobox", { name: "Build from" }), "pam_accounts");
    expect(screen.getByText(/every template's approvers and quorum/)).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /Graph node/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Generate review" }));
    expect(apiMock.generateNHIReviewCampaign).toHaveBeenCalledWith({ name: "Q4 privileged accounts", source: "pam_accounts" }, expect.any(String));
    expect(onGenerated).toHaveBeenCalledWith("c2");
  });

  it("downloads a completed campaign's signed result, and offers none before it completes (A276)", async () => {
    apiMock.nhiReviewResult.mockResolvedValueOnce({ artifact: "access-certification-result", result: { campaign_id: "c2" }, signature: "sig" });
    const create = vi.fn(() => "blob:result");
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const user = userEvent.setup();
    const { rerender } = render(<AccessReviewSignedResult campaignId="c2" completed={false} />);
    expect(screen.queryByRole("button", { name: "Download the signed result" })).not.toBeInTheDocument();
    rerender(<AccessReviewSignedResult campaignId="c2" completed />);
    await user.click(screen.getByRole("button", { name: "Download the signed result" }));
    expect(apiMock.nhiReviewResult).toHaveBeenCalledWith("c2");
    expect(click).toHaveBeenCalled();
    expect(await screen.findByRole("status")).toHaveTextContent("Verify its signature with the audit verification keys.");
    click.mockRestore();
  });
});
