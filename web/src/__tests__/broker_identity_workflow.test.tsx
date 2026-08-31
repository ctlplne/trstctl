import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { BrokerIdentityWorkflow } from "@/pages/workloads/BrokerIdentityWorkflow";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { ApiError } from "@/lib/api";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { brokerHistoryFixture, brokerHistoryPage, brokerPreviewFixture } from "./support/brokerIdentity";

const { apiMock, session } = vi.hoisted(() => ({
  apiMock: { previewBrokerAgentIdentity: vi.fn(), issueBrokerAgentIdentity: vi.fn(), brokerAgentIdentities: vi.fn(), brokerAgentIdentity: vi.fn() },
  session: { tenant: "tenant-a" },
}));
vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/auth/AuthProvider", () => ({ useAuth: () => ({ user: { tenant_id: session.tenant, subject: "operator" } }) }));

const issued = {
  certificate_id: brokerHistoryFixture.certificate_id,
  subject: brokerHistoryFixture.certificate_subject,
  not_after: brokerHistoryFixture.not_after!,
  certificate_pem: "PUBLIC-CERTIFICATE-NOT-FOR-DOM",
  attestation: { claims: { proof: "RAW-PROOF-NOT-FOR-DOM" } },
};
function Harness({ entry = "/workloads", denied = false }: { entry?: string; denied?: boolean }) {
  const body = <BrokerIdentityWorkflow />;
  return (
    <MemoryRouter initialEntries={[entry]}>
      <IntlProvider initialLocale="en-US">
        <AppQueryProvider>{denied ? <CapabilityFixtureProvider view={null}>{body}</CapabilityFixtureProvider> : body}</AppQueryProvider>
      </IntlProvider>
    </MemoryRouter>
  );
}
async function enterRequest() {
  await userEvent.click(screen.getByRole("button", { name: "Request agent identity" }));
  fireEvent.change(screen.getByLabelText("Agent ID"), { target: { value: "agent-build-1" } });
  fireEvent.change(screen.getByLabelText("Broker scopes"), { target: { value: "tool:inventory.read" } });
  fireEvent.change(screen.getByLabelText("Broker proof payload (base64)"), { target: { value: "cHJvb2Y=" } });
  fireEvent.change(screen.getByLabelText("Broker public key"), { target: { value: "-----BEGIN PUBLIC KEY-----\nUFVCTElD\n-----END PUBLIC KEY-----" } });
  await userEvent.click(screen.getByRole("button", { name: "Preview request" }));
  await screen.findByRole("heading", { name: "Ready to verify and issue" });
}

describe("durable broker operator workflow", () => {
  beforeEach(() => {
    session.tenant = "tenant-a";
    apiMock.brokerAgentIdentities.mockReset().mockResolvedValue(brokerHistoryPage());
    apiMock.brokerAgentIdentity.mockReset().mockResolvedValue(brokerHistoryFixture);
    apiMock.previewBrokerAgentIdentity.mockReset().mockResolvedValue(brokerPreviewFixture);
    apiMock.issueBrokerAgentIdentity.mockReset().mockResolvedValue(issued);
  });

  it("reads durable history before opening the form and reads server detail on a deep link", async () => {
    render(<Harness entry={`/workloads?broker_id=${brokerHistoryFixture.certificate_id}`} />);
    const drawer = screen.getByRole("dialog", { name: "Agent certificate record" });
    expect(await within(drawer).findByText("Facts recorded at issuance")).toBeInTheDocument();
    expect(within(drawer).getByText("tool:inventory.read")).toBeInTheDocument();
    expect(apiMock.brokerAgentIdentity).toHaveBeenCalledWith(brokerHistoryFixture.certificate_id, expect.any(AbortSignal));
    expect(apiMock.issueBrokerAgentIdentity).not.toHaveBeenCalled();
    expect(screen.queryByLabelText("Broker proof payload (base64)")).not.toBeInTheDocument();
    await userEvent.click(within(drawer).getByRole("button", { name: "Close" }));
    expect(await screen.findByRole("row", { name: /agent-build-1.*Within validity window/ })).toBeInTheDocument();
  });

  it("previews before signing and locks uncertain requests to the exact body and same retry key", async () => {
    apiMock.issueBrokerAgentIdentity
      .mockRejectedValueOnce(new ApiError(500, JSON.stringify({ detail: "private-server-detail" })))
      .mockResolvedValueOnce(issued);
    render(<Harness />);
    await enterRequest();
    expect(screen.queryByDisplayValue("cHJvb2Y=")).not.toBeInTheDocument();
    expect(apiMock.issueBrokerAgentIdentity).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Verify proof and issue" }));
    expect(await screen.findByText(/The response did not confirm the outcome/)).toBeInTheDocument();
    expect(screen.queryByText("private-server-detail")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Retry exact issuance" }));
    expect(await screen.findByRole("heading", { name: "Certificate issuance recorded" })).toBeInTheDocument();
    expect(apiMock.issueBrokerAgentIdentity.mock.calls[0][0]).toEqual(apiMock.previewBrokerAgentIdentity.mock.calls[0][0]);
    expect(apiMock.issueBrokerAgentIdentity.mock.calls[1]).toEqual(apiMock.issueBrokerAgentIdentity.mock.calls[0]);
    expect(apiMock.issueBrokerAgentIdentity.mock.calls[0][1]).toEqual(expect.any(String));
    expect(screen.queryByText(/PUBLIC-CERTIFICATE-NOT-FOR-DOM|RAW-PROOF-NOT-FOR-DOM/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Start another request" }));
    expect(screen.getByLabelText("Broker proof payload (base64)")).toHaveValue("");
    expect(screen.getByLabelText("Task envelope (base64, optional)")).toHaveValue("");
  });

  it("requires an explicit warning acknowledgment before discarding an uncertain retry", async () => {
    apiMock.issueBrokerAgentIdentity.mockRejectedValue(new Error("network lost"));
    render(<Harness />);
    await enterRequest();
    await userEvent.click(screen.getByRole("button", { name: "Verify proof and issue" }));
    await userEvent.click(await screen.findByRole("button", { name: "Start a different request" }));
    const dialog = screen.getByRole("dialog", { name: "Start a different request" });
    const reset = within(dialog).getByRole("button", { name: "Clear inputs and start again" });
    expect(reset).toBeDisabled();
    expect(within(dialog).getByText(/does not cancel or revoke anything/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("checkbox"));
    await userEvent.click(reset);
    expect(screen.getByLabelText("Broker proof payload (base64)")).toHaveValue("");
    expect(apiMock.issueBrokerAgentIdentity).toHaveBeenCalledTimes(1);
  });

  it.each([
    { effect_free: false },
    { blockers: ["Trust source unavailable."] },
    { preview_writes: ["unexpected write"] },
    { task_envelope_verification: "unavailable" },
    { policy_evaluation: "unknown-future-behavior" },
  ])("does not issue an unsafe or unsupported preview %j", async (overrides) => {
    render(<Harness />);
    // Supply valid inputs first; the server may return a non-ready result.
    await enterRequest();
    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    apiMock.previewBrokerAgentIdentity.mockResolvedValue({ ...brokerPreviewFixture, ...overrides });
    await userEvent.click(screen.getByRole("button", { name: "Preview request" }));
    await waitFor(() => expect(apiMock.previewBrokerAgentIdentity).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("button", { name: "Verify proof and issue" })).toBeDisabled();
    expect(apiMock.issueBrokerAgentIdentity).not.toHaveBeenCalled();
  });

  it("does not invent missing original facts or turn unavailable reads into an empty inventory", async () => {
    apiMock.brokerAgentIdentity.mockResolvedValue({
      ...brokerHistoryFixture,
      metadata_state: "unavailable",
      issuance: undefined,
      projection_state: "catching_up",
    });
    render(<Harness entry={`/workloads?broker_id=${brokerHistoryFixture.certificate_id}`} />);
    expect(await screen.findByText(/Original issuance facts are unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/Projection is catching up/)).toBeInTheDocument();
    expect(screen.queryByText("Owner at issuance")).not.toBeInTheDocument();
  });

  it("keeps query context across server-side filtering and fails closed on unknown filter states", async () => {
    render(<Harness entry="/workloads?broker_state=not-a-state&broker_q=agent" />);
    expect(screen.getAllByText("Choose a supported certificate state.").length).toBeGreaterThan(0);
    expect(apiMock.brokerAgentIdentities).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Certificate state"), { target: { value: "expired" } });
    await waitFor(() =>
      expect(apiMock.brokerAgentIdentities).toHaveBeenCalledWith(expect.objectContaining({ state: "expired", q: "agent" }), expect.any(AbortSignal)),
    );
  });

  it("blocks reads and signing while capability authority is unknown", () => {
    render(<Harness denied />);
    expect(screen.getByRole("button", { name: "Request agent identity" })).toBeDisabled();
    expect(apiMock.brokerAgentIdentities).not.toHaveBeenCalled();
    expect(apiMock.previewBrokerAgentIdentity).not.toHaveBeenCalled();
    expect(apiMock.issueBrokerAgentIdentity).not.toHaveBeenCalled();
  });

  it("drops a late issuance result after the tenant changes", async () => {
    let finish!: (value: typeof issued) => void;
    apiMock.issueBrokerAgentIdentity.mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const view = render(<Harness />);
    await enterRequest();
    await userEvent.click(screen.getByRole("button", { name: "Verify proof and issue" }));
    session.tenant = "tenant-b";
    view.rerender(<Harness />);
    await act(async () => finish(issued));
    expect(screen.queryByText("Certificate issuance recorded")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Request agent identity" })).toBeInTheDocument();
  });
});
