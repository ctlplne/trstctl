import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AttestedSVIDWorkflow } from "@/pages/workloads/AttestedSVIDWorkflow";
import { attestedPreviewFixture } from "./support/attestedSVID";
import { ApiError } from "@/lib/api";
import { IntlProvider } from "@/i18n/I18nProvider";

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

function renderWorkflow(timeZone = "UTC") {
  return render(
    <MemoryRouter>
      <IntlProvider initialLocale="en-US" initialTimeZone={timeZone}>
        <AttestedSVIDWorkflow onIssued={vi.fn()} onFailure={vi.fn()} />
      </IntlProvider>
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

  it.each([
    ["2026-08-31T00:24:48Z", "Aug 30, 2026, 8:24 PM"],
    ["2026-03-08T06:59:00Z", "Mar 8, 2026, 1:59 AM"],
    ["2026-03-08T07:00:00Z", "Mar 8, 2026, 3:00 AM"],
  ])("uses the selected time zone across midnight and DST without changing validity: %s", async (notAfter, visibleTime) => {
    apiMock.issueAttestedSVID.mockResolvedValue({ ...issued, not_after: notAfter });
    renderWorkflow("America/New_York");
    await enterRequest();
    await screen.findByRole("heading", { name: "Ready to verify and issue" });
    await userEvent.click(screen.getByRole("button", { name: "Verify proof and issue" }));
    expect(await screen.findByText(visibleTime)).toBeInTheDocument();
    expect(apiMock.issueAttestedSVID).toHaveBeenCalledTimes(1);
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
    expect(screen.queryByDisplayValue("c2VjcmV0LXByb29m")).not.toBeInTheDocument();
    expect(screen.queryByText(/PUBLIC-KEY|PUBLIC-CERTIFICATE/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Start another request" }));
    expect(screen.getByLabelText("Attestation proof payload (base64)")).toHaveValue("");
    expect(screen.getByLabelText("Workload public key")).toHaveValue("");
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

  it("does not present a server outage as rejected proof or expose internal server detail", async () => {
    apiMock.issueAttestedSVID.mockRejectedValueOnce(new ApiError(500, JSON.stringify({ detail: "private-internal-dependency-detail" })));
    renderWorkflow();
    await enterRequest();
    await screen.findByRole("heading", { name: "Ready to verify and issue" });
    await userEvent.click(screen.getByRole("button", { name: "Verify proof and issue" }));
    expect(await screen.findByText(/does not mean the workload proof was rejected/)).toBeInTheDocument();
    expect(screen.queryByText(/private-internal-dependency-detail/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry exact issuance" })).toBeEnabled();
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
