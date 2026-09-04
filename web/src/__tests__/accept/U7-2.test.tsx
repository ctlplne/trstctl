import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BreakGlassReconcile } from "@/components/breakglass";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    previewBreakglassIssue: vi.fn(),
    startBreakglassIssueCeremony: vi.fn(),
    breakglassIssue: vi.fn(),
    caCeremony: vi.fn(),
    breakglassReconcile: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.previewBreakglassIssue.mockReset().mockResolvedValue({
    capability: "F34",
    operation: "issue_breakglass",
    ready: true,
    effect_free: true,
    request_id: "bg-online-1",
    subject: "svc.example",
    reason: "regional outage",
    requested_ttl_seconds: 900,
    effective_ttl_seconds: 900,
    csr_sha256: "sha256:csr",
    request_fingerprint: "sha256:request",
    approval_threshold: 2,
    configured_operator_count: 3,
    required_permission: "certs:issue",
    prerequisites: [
      { id: "online_signer", ready: true, detail: "Purpose-constrained signer is configured." },
      { id: "operator_roster", ready: true, detail: "3 operators can satisfy a 2-person quorum." },
    ],
    blockers: [],
    preview_writes: [],
    preview_external_effects: [],
    preview_signer_calls: [],
    execution_writes: ["Open one exact ceremony", "Append breakglass.issued"],
    execution_external_effects: [],
    execution_signer_calls: ["Sign one short-lived certificate after quorum"],
    recovery_steps: ["Do not issue if the ceremony no longer matches the incident."],
    verification_steps: ["Verify the returned bundle and audit event."],
  });
  apiMock.startBreakglassIssueCeremony.mockReset().mockResolvedValue({
    id: "ceremony-1",
    tenant_id: "tenant-1",
    purpose: "breakglass-issue:sha256:request",
    threshold: 2,
    approvals: 0,
    status: "pending",
    created_at: "2026-09-04T00:00:00Z",
  });
  apiMock.caCeremony.mockReset().mockResolvedValue({
    id: "ceremony-1",
    tenant_id: "tenant-1",
    purpose: "breakglass-issue:sha256:request",
    threshold: 2,
    approvals: 2,
    status: "approved",
    created_at: "2026-09-04T00:00:00Z",
  });
  apiMock.breakglassIssue.mockReset().mockResolvedValue({ reconciled: 1, audit_event_type: "breakglass.issued", bundle: { request_id: "bg-online-1" } });
  apiMock.breakglassReconcile.mockReset().mockResolvedValue({ reconciled: 2 });
});

const bundles = JSON.stringify([
  { request_id: "r1", subject: "CN=emergency", approvals: ["a", "b"], cert_der: "DER", signature: "SIG", issued_at: "2026-06-20T10:00:00Z", reason: "outage" },
]);

describe("U7-2 break-glass console", () => {
  it("previews, opens an exact quorum ceremony, and only issues after authenticated approvals", async () => {
    const user = userEvent.setup();
    render(<BreakGlassReconcile />);
    const body = {
      request_id: "bg-online-1",
      subject: "svc.example",
      csr_der: "Y3Ny",
      reason: "regional outage",
      ttl_seconds: 900,
    };

    fireEvent.change(screen.getByLabelText("Request ID"), { target: { value: body.request_id } });
    fireEvent.change(screen.getByLabelText("Emergency certificate subject"), { target: { value: body.subject } });
    fireEvent.change(screen.getByLabelText("CSR (DER, base64)"), { target: { value: body.csr_der } });
    fireEvent.change(screen.getByLabelText("Incident reason"), { target: { value: body.reason } });
    fireEvent.change(screen.getByLabelText("Lifetime (seconds)"), { target: { value: String(body.ttl_seconds) } });
    await user.click(screen.getByRole("button", { name: "Review emergency request" }));

    await waitFor(() => expect(apiMock.previewBreakglassIssue).toHaveBeenCalledWith(body));
    expect(await screen.findByText("No state changed during this review.")).toBeInTheDocument();
    expect(screen.getByText("2-person quorum from 3 configured operators")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open quorum ceremony" }));

    await waitFor(() => expect(apiMock.startBreakglassIssueCeremony).toHaveBeenCalledWith(body));
    expect(await screen.findByText("0 of 2 approvals recorded")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Issue emergency certificate" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Refresh approvals" }));
    expect(await screen.findByText("2 of 2 approvals recorded")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Issue emergency certificate" }));

    await waitFor(() => expect(apiMock.breakglassIssue).toHaveBeenCalledWith({ ...body, ceremony_id: "ceremony-1" }));
    expect(await screen.findByText(/Issued and audited 1 break-glass bundle/i)).toBeInTheDocument();
  });

  it("reconciles offline-issued bundles through the served endpoint and reports the count", async () => {
    const user = userEvent.setup();
    render(<BreakGlassReconcile />);
    expect(screen.getByRole("heading", { name: "Emergency certificate access" })).toBeInTheDocument();
    await user.click(screen.getByText("Recover offline-issued certificates"));

    // fireEvent.change avoids userEvent's special-character parsing of JSON braces/brackets.
    fireEvent.change(screen.getByLabelText("Offline-issued bundles (JSON)"), { target: { value: bundles } });
    await user.click(screen.getByRole("button", { name: "Reconcile break-glass bundles" }));

    await waitFor(() => expect(apiMock.breakglassReconcile).toHaveBeenCalled());
    expect(await screen.findByText(/Reconciled 2 break-glass bundles/i)).toBeInTheDocument();
  });
});
