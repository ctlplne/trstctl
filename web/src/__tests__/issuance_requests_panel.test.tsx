import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { IssuanceRequestsPanel } from "@/components/IssuanceRequestsPanel";
import { AppQueryProvider, useApiQuery } from "@/lib/query";
import { approvalRequestsQueryKey } from "@/lib/approvalQueue";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuanceRequests: vi.fn(),
    approveIssuanceRequest: vi.fn(),
    denyIssuanceRequest: vi.fn(),
    cancelIssuanceRequest: vi.fn(),
    prepareIssuanceRequest: vi.fn(),
    transitionIdentity: vi.fn(),
    completeIssuanceRequest: vi.fn(),
    ticketIntakeSchedule: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("ticket-intake relay visibility", () => {
  beforeEach(() => {
    apiMock.issuanceRequests.mockReset().mockResolvedValue({ items: [], open: 0, guidance: "" });
    apiMock.approveIssuanceRequest.mockReset();
    apiMock.denyIssuanceRequest.mockReset();
    apiMock.cancelIssuanceRequest.mockReset();
    apiMock.prepareIssuanceRequest.mockReset();
    apiMock.transitionIdentity.mockReset();
    apiMock.completeIssuanceRequest.mockReset();
    apiMock.ticketIntakeSchedule.mockReset().mockImplementation(async (system: "servicenow" | "jira") =>
      system === "servicenow"
        ? {
            configured: true,
            enabled: true,
            system,
            last_error: "a dispatched ticket.sync job is still waiting",
            guidance: "A network relay executes the durable read; the control plane never dials ServiceNow.",
          }
        : { configured: false, enabled: false, system, guidance: "" },
    );
  });

  it("shows the durable relay outcome even before a ticket opens a request", async () => {
    render(
      <AppQueryProvider>
        <IssuanceRequestsPanel />
      </AppQueryProvider>,
    );

    expect(await screen.findByRole("heading", { name: "Network relay" })).toBeInTheDocument();
    expect(apiMock.ticketIntakeSchedule).toHaveBeenCalledWith("servicenow");
    expect(apiMock.ticketIntakeSchedule).toHaveBeenCalledWith("jira");
    expect(screen.getByText((_, node) => node?.tagName === "P" && node.textContent === "servicenow · Enabled · Last run: —")).toBeInTheDocument();
    expect(screen.getByText("a dispatched ticket.sync job is still waiting")).toBeInTheDocument();
    expect(screen.getByText(/control plane never dials ServiceNow/)).toBeInTheDocument();
  });

  it("lets a distinct approver decide a real issuance request", async () => {
    const request = {
      id: "request-1",
      tenant_id: "tenant-1",
      subject: "qa-design-partner-mtls",
      owner_id: "owner-1",
      profile: "service-mtls-30d:1",
      requester: "demo-admin",
      status: "requested" as const,
      expires_at: "2026-08-21T00:00:00Z",
      created_at: "2026-08-20T00:00:00Z",
    };
    apiMock.issuanceRequests.mockResolvedValue({ items: [request], open: 1, guidance: "Independent approval required." });
    apiMock.approveIssuanceRequest.mockResolvedValue({ ...request, status: "approved", decided_by: "se-demo-operator" });
    const user = userEvent.setup();

    render(
      <AppQueryProvider>
        <IssuanceRequestsPanel currentPrincipal={{ subject: "se-demo-operator", email: "se-demo-operator@trstctl.local", permissions: ["certs:issue"] }} />
      </AppQueryProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "Approve qa-design-partner-mtls" }));

    expect(apiMock.approveIssuanceRequest).toHaveBeenCalledWith("request-1");
    expect(await screen.findByRole("status")).toHaveTextContent("Approval recorded for qa-design-partner-mtls");
    expect(screen.queryByRole("button", { name: "Approve qa-design-partner-mtls" })).not.toBeInTheDocument();
  });

  it("keeps self-approval blocked while letting a requester withdraw their own request", async () => {
    const request = {
      id: "request-2",
      tenant_id: "tenant-1",
      subject: "own-request",
      owner_id: "owner-1",
      requester: "demo-admin",
      status: "requested" as const,
      expires_at: "2026-08-21T00:00:00Z",
      created_at: "2026-08-20T00:00:00Z",
    };
    apiMock.issuanceRequests.mockResolvedValue({ items: [request], open: 1, guidance: "Independent approval required." });
    apiMock.cancelIssuanceRequest.mockResolvedValue({ ...request, status: "cancelled" });
    const user = userEvent.setup();

    render(
      <AppQueryProvider>
        <IssuanceRequestsPanel currentPrincipal={{ subject: "demo-admin", email: "demo-admin@trstctl.local", permissions: ["certs:request"] }} />
      </AppQueryProvider>,
    );

    expect(await screen.findByText("own-request")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve own-request" })).not.toBeInTheDocument();
    expect(screen.getByText(/You opened this request, so a different person must approve or deny it/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Withdraw own-request" }));
    expect(apiMock.cancelIssuanceRequest).toHaveBeenCalledWith("request-2");
    expect(await screen.findByRole("status")).toHaveTextContent("Request withdrawn for own-request");
  });

  it("turns an approved request into signer-backed issued evidence through the guarded identity path", async () => {
    const request = {
      id: "request-issued",
      tenant_id: "tenant-1",
      subject: "qa-design-partner-mtls",
      owner_id: "owner-1",
      profile: "service-mtls-30d:1",
      requester: "demo-admin",
      decided_by: "security-reviewer",
      status: "approved" as const,
      expires_at: "2026-08-21T00:00:00Z",
      created_at: "2026-08-20T00:00:00Z",
    };
    apiMock.issuanceRequests.mockResolvedValue({ items: [request], open: 0, guidance: "Approval is not issuance." });
    apiMock.prepareIssuanceRequest.mockResolvedValue({
      request: { ...request, identity_id: "identity-issued" },
      identity: {
        id: "identity-issued",
        tenant_id: "tenant-1",
        kind: "x509_certificate",
        name: request.subject,
        owner_id: request.owner_id,
        status: "requested",
        attributes: {},
      },
      csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\npublic-csr\n-----END CERTIFICATE REQUEST-----",
      issue_idempotency_key: "issuance-request-issue:request-issued",
    });
    apiMock.transitionIdentity.mockResolvedValue({ id: "identity-issued", status: "issued" });
    apiMock.completeIssuanceRequest.mockResolvedValue({
      ...request,
      identity_id: "identity-issued",
      status: "issued",
      issued_by: "se-demo-operator",
      issued_at: "2026-08-20T01:00:00Z",
    });
    const user = userEvent.setup();
    const readQueue = vi.fn().mockResolvedValueOnce(["pending-command"]).mockResolvedValue([]);
    function QueueCount() {
      const queue = useApiQuery<string[]>(approvalRequestsQueryKey, readQueue);
      return <span aria-label="Pending operation approvals">{queue.data?.length ?? "loading"}</span>;
    }

    render(
      <AppQueryProvider>
        <QueueCount />
        <IssuanceRequestsPanel currentPrincipal={{ subject: "se-demo-operator", permissions: ["certs:issue", "identities:write"] }} />
      </AppQueryProvider>,
    );

    await waitFor(() => expect(screen.getByLabelText("Pending operation approvals")).toHaveTextContent("1"));
    await user.click(await screen.findByRole("button", { name: "Issue certificate for qa-design-partner-mtls" }));

    expect(apiMock.prepareIssuanceRequest).toHaveBeenCalledWith("request-issued");
    expect(apiMock.transitionIdentity).toHaveBeenCalledWith(
      "identity-issued",
      "issued",
      "fulfill approved issuance request request-issued",
      expect.stringContaining("CERTIFICATE REQUEST"),
      "issuance-request-issue:request-issued",
    );
    expect(apiMock.completeIssuanceRequest).toHaveBeenCalledWith("request-issued");
    expect(await screen.findByRole("status")).toHaveTextContent("Certificate issued for qa-design-partner-mtls");
    expect(screen.getByText(/Issued by se-demo-operator/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText("Pending operation approvals")).toHaveTextContent("0"));
    expect(readQueue).toHaveBeenCalledTimes(2);
  });

  it("keeps a failed approved request recoverable and retries with the same issuance identity", async () => {
    const request = {
      id: "request-retry",
      tenant_id: "tenant-1",
      subject: "retry-safe-mtls",
      owner_id: "owner-1",
      profile: "service-mtls-30d:1",
      requester: "demo-admin",
      decided_by: "security-reviewer",
      status: "approved" as const,
      expires_at: "2026-08-21T00:00:00Z",
      created_at: "2026-08-20T00:00:00Z",
    };
    const preparation = {
      request: { ...request, identity_id: "identity-retry" },
      identity: {
        id: "identity-retry",
        tenant_id: "tenant-1",
        kind: "x509_certificate",
        name: request.subject,
        owner_id: request.owner_id,
        status: "requested",
        attributes: {},
      },
      csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\npublic-csr\n-----END CERTIFICATE REQUEST-----",
      issue_idempotency_key: "issuance-request-issue:request-retry",
    };
    apiMock.issuanceRequests.mockResolvedValue({ items: [request], open: 0, guidance: "Approval is not issuance." });
    apiMock.prepareIssuanceRequest.mockResolvedValue(preparation);
    apiMock.transitionIdentity
      .mockRejectedValueOnce(new Error("signer temporarily unavailable"))
      .mockResolvedValueOnce({ id: "identity-retry", status: "issued" });
    apiMock.completeIssuanceRequest.mockResolvedValue({
      ...request,
      identity_id: "identity-retry",
      status: "issued",
      issued_by: "se-demo-operator",
      issued_at: "2026-08-20T01:00:00Z",
    });
    const user = userEvent.setup();

    render(
      <AppQueryProvider>
        <IssuanceRequestsPanel currentPrincipal={{ subject: "se-demo-operator", permissions: ["certs:issue", "identities:write"] }} />
      </AppQueryProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "Issue certificate for retry-safe-mtls" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("signer temporarily unavailable");
    expect(screen.getByText(/request and approval are still saved/i)).toBeInTheDocument();
    expect(screen.getByText(/same request identity and issuance key/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry safely for retry-safe-mtls" }));

    expect(apiMock.prepareIssuanceRequest).toHaveBeenCalledTimes(2);
    expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(2);
    expect(apiMock.transitionIdentity.mock.calls[0]).toEqual(apiMock.transitionIdentity.mock.calls[1]);
    expect(apiMock.transitionIdentity.mock.calls[1]?.[4]).toBe("issuance-request-issue:request-retry");
    expect(await screen.findByRole("status")).toHaveTextContent("Certificate issued for retry-safe-mtls");
  });

  it("does not offer certificate decisions to a read-only requester role", async () => {
    apiMock.issuanceRequests.mockResolvedValue({
      open: 1,
      guidance: "Independent approval required.",
      items: [
        {
          id: "request-3",
          tenant_id: "tenant-1",
          subject: "somebody-elses-request",
          owner_id: "owner-1",
          requester: "demo-admin",
          status: "requested",
          expires_at: "2026-08-21T00:00:00Z",
          created_at: "2026-08-20T00:00:00Z",
        },
      ],
    });

    render(
      <AppQueryProvider>
        <IssuanceRequestsPanel currentPrincipal={{ subject: "payments-bot", email: "payments-bot@trstctl.local", permissions: ["certs:request"] }} />
      </AppQueryProvider>,
    );

    expect(await screen.findByText("somebody-elses-request")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Approve somebody-elses-request/i })).not.toBeInTheDocument();
    expect(screen.getByText(/this session cannot approve or deny certificates/i)).toBeInTheDocument();
  });

  it("requires and records an actionable denial reason", async () => {
    const request = {
      id: "request-4",
      tenant_id: "tenant-1",
      subject: "unsafe-name",
      owner_id: "owner-1",
      requester: "demo-admin",
      status: "requested" as const,
      expires_at: "2026-08-21T00:00:00Z",
      created_at: "2026-08-20T00:00:00Z",
    };
    apiMock.issuanceRequests.mockResolvedValue({ items: [request], open: 1, guidance: "Independent approval required." });
    apiMock.denyIssuanceRequest.mockResolvedValue({
      ...request,
      status: "denied",
      decided_by: "se-demo-operator",
      decision_reason: "Name does not match the approved service inventory.",
    });
    const user = userEvent.setup();

    render(
      <AppQueryProvider>
        <IssuanceRequestsPanel currentPrincipal={{ subject: "se-demo-operator", permissions: ["certs:issue"] }} />
      </AppQueryProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "Deny unsafe-name" }));
    const submit = screen.getByRole("button", { name: "Record denial" });
    expect(submit).toBeDisabled();
    await user.type(screen.getByLabelText("Why is this request denied?"), "Name does not match the approved service inventory.");
    await user.click(submit);

    expect(apiMock.denyIssuanceRequest).toHaveBeenCalledWith("request-4", "Name does not match the approved service inventory.");
    expect(await screen.findByRole("status")).toHaveTextContent("Request denied for unsafe-name");
  });
});
