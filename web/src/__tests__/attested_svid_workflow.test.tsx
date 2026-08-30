import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AttestedSVIDWorkflow } from "@/pages/workloads/AttestedSVIDWorkflow";
import { attestedPreviewFixture } from "./support/attestedSVID";

const { apiMock } = vi.hoisted(() => ({ apiMock: { previewAttestedSVID: vi.fn(), issueAttestedSVID: vi.fn() } }));
vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const issued = {
  credential_id: "cred-attested-1",
  subject: "ns/default/sa/web",
  not_after: "2026-08-30T20:10:00Z",
  certificate_pem: "-----BEGIN CERTIFICATE-----\nPUBLIC-CERTIFICATE\n-----END CERTIFICATE-----",
  attestation: { id: "att-1", method: "k8s_sat", subject: "ns/default/sa/web", selectors: ["ns:default"], verified_at: "2026-08-30T20:00:00Z" },
};

function renderWorkflow() {
  return render(
    <MemoryRouter>
      <AttestedSVIDWorkflow onIssued={vi.fn()} onFailure={vi.fn()} />
    </MemoryRouter>,
  );
}

async function enterRequest() {
  fireEvent.change(screen.getByLabelText("Attestation proof payload (base64)"), { target: { value: "c2VjcmV0LXByb29m" } });
  fireEvent.change(screen.getByLabelText("Workload public key"), { target: { value: "-----BEGIN PUBLIC KEY-----\nPUBLIC-KEY\n-----END PUBLIC KEY-----" } });
  await userEvent.click(screen.getByRole("button", { name: "Preview request" }));
}

describe("attested SVID workflow", () => {
  beforeEach(() => {
    apiMock.previewAttestedSVID.mockReset().mockResolvedValue(attestedPreviewFixture);
    apiMock.issueAttestedSVID.mockReset().mockResolvedValue(issued);
  });

  it("reviews the exact server plan and retries an unchanged failed issuance with one idempotency key", async () => {
    apiMock.issueAttestedSVID.mockRejectedValueOnce(new Error("Signer temporarily unavailable")).mockResolvedValueOnce(issued);
    renderWorkflow();
    await enterRequest();
    expect(await screen.findByRole("heading", { name: "Ready to verify and issue" })).toBeInTheDocument();
    expect(screen.getByText("workloads.example.test")).toBeInTheDocument();
    expect(screen.queryByDisplayValue("c2VjcmV0LXByb29m")).not.toBeInTheDocument();
    expect(screen.queryByText(/PUBLIC-KEY|PUBLIC-CERTIFICATE/)).not.toBeInTheDocument();
    expect(apiMock.issueAttestedSVID).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Verify proof and issue" }));
    expect(await screen.findByText("Signer temporarily unavailable")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry exact issuance" }));
    expect(await screen.findByRole("heading", { name: "Workload certificate issued" })).toBeInTheDocument();
    expect(apiMock.issueAttestedSVID.mock.calls[0][0]).toEqual(apiMock.previewAttestedSVID.mock.calls[0][0]);
    expect(apiMock.issueAttestedSVID.mock.calls[1]).toEqual(apiMock.issueAttestedSVID.mock.calls[0]);
    expect(apiMock.issueAttestedSVID.mock.calls[0][1]).toEqual(expect.any(String));
  });

  it.each([
    { ready: false, effect_free: true, blockers: ["Trust source is not configured."] },
    { ready: true, effect_free: false, blockers: [] },
  ])("never executes an unready or effectful plan: %j", async (overrides) => {
    apiMock.previewAttestedSVID.mockResolvedValue({ ...attestedPreviewFixture, ...overrides });
    renderWorkflow();
    await enterRequest();
    expect(await screen.findByRole("heading", { name: "Fix these items before submitting" })).toBeInTheDocument();
    if (overrides.blockers.length) expect(screen.getByText("Trust source is not configured.")).toBeInTheDocument();
    if (!overrides.effect_free) expect(screen.queryByText("This preview made no database writes, external calls, or signer calls.")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify proof and issue" })).toBeDisabled();
    expect(apiMock.issueAttestedSVID).not.toHaveBeenCalled();
  });

  it("invalidates a reviewed plan after any edit and requires another server preview", async () => {
    renderWorkflow();
    await enterRequest();
    await screen.findByRole("heading", { name: "Ready to verify and issue" });
    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    fireEvent.change(screen.getByLabelText("SVID TTL seconds"), { target: { value: "300" } });
    expect(screen.queryByRole("button", { name: "Verify proof and issue" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Preview request" }));
    await screen.findByRole("heading", { name: "Ready to verify and issue" });
    expect(apiMock.previewAttestedSVID).toHaveBeenLastCalledWith(expect.objectContaining({ ttl_seconds: 300 }));
    expect(apiMock.issueAttestedSVID).not.toHaveBeenCalled();
  });
});
