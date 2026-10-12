import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { BreakGlassReconcile } from "@/components/breakglass";
import type { CapabilityView } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { AppQueryProvider } from "@/lib/query";

const {
  previewBreakglassIssue,
  startBreakglassIssueCeremony,
  breakglassIssue,
  breakglassReconcile,
  breakglassIssues,
  getBreakglassIssue,
  breakglassAuthorityReceipts,
  getBreakglassAuthorityReceipt,
  startBreakglassRotationCeremony,
  rotateBreakglass,
  startBreakglassCrossSignCeremony,
  crossSignBreakglass,
  caCeremony,
} = vi.hoisted(() => ({
  previewBreakglassIssue: vi.fn(),
  startBreakglassIssueCeremony: vi.fn(),
  breakglassIssue: vi.fn(),
  breakglassReconcile: vi.fn(),
  breakglassIssues: vi.fn(),
  getBreakglassIssue: vi.fn(),
  breakglassAuthorityReceipts: vi.fn(),
  getBreakglassAuthorityReceipt: vi.fn(),
  startBreakglassRotationCeremony: vi.fn(),
  rotateBreakglass: vi.fn(),
  startBreakglassCrossSignCeremony: vi.fn(),
  crossSignBreakglass: vi.fn(),
  caCeremony: vi.fn(),
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      previewBreakglassIssue,
      startBreakglassIssueCeremony,
      breakglassIssue,
      breakglassReconcile,
      breakglassIssues,
      getBreakglassIssue,
      breakglassAuthorityReceipts,
      getBreakglassAuthorityReceipt,
      startBreakglassRotationCeremony,
      rotateBreakglass,
      startBreakglassCrossSignCeremony,
      crossSignBreakglass,
      caCeremony,
    },
  };
});

const unavailableDetail = "This operation is not mounted because its runtime dependency is not configured.";
const unavailableRuntime: CapabilityView = {
  schema_version: 2,
  contract_schema_version: 3,
  enforcement_note: "The server checks every operation again when it executes.",
  license: { tier: "community", state: "community" },
  operations: [],
  items: [
    {
      capability_id: "F34",
      name: "Break-glass procedures",
      purpose: "Issue and reconcile short-lived emergency credentials.",
      tool: "operations",
      classification: "primary",
      console_route: "/incidents",
      maturity: "partial_workflow",
      release_blocking: true,
      edition: "core",
      runtime_state: "partially_available",
      authorization_state: "partial",
      dependency_state: "documented_not_runtime_verified",
      dependencies: [],
      stages: [{ name: "execute", completion: "blocked", reason: unavailableDetail }],
      actions: {
        allowed: [],
        scoped: [],
        denied: [],
        unavailable: [
          { operation_id: "previewBreakglassIssue", code: "dependency_not_configured", detail: unavailableDetail },
          { operation_id: "startBreakglassIssueCeremony", code: "dependency_not_configured", detail: unavailableDetail },
          { operation_id: "issueBreakglass", code: "dependency_not_configured", detail: unavailableDetail },
          { operation_id: "reconcileBreakglass", code: "dependency_not_configured", detail: unavailableDetail },
        ],
      },
    },
  ],
};

describe("break-glass runtime truth", () => {
  it("keeps valid-looking emergency requests disabled when the exact operations are unavailable", () => {
    breakglassIssues.mockResolvedValue({ items: [], next_cursor: "" });
    breakglassAuthorityReceipts.mockResolvedValue({ items: [], next_cursor: "" });
    render(
      <AppQueryProvider>
        <CapabilityFixtureProvider view={unavailableRuntime}>
          <BreakGlassReconcile />
        </CapabilityFixtureProvider>
      </AppQueryProvider>,
    );

    fireEvent.change(screen.getByLabelText("Request ID"), { target: { value: "bg-1" } });
    fireEvent.change(screen.getByLabelText("Emergency certificate subject"), { target: { value: "svc.example" } });
    fireEvent.change(screen.getByLabelText("CSR (DER, base64)"), { target: { value: "Y3Ny" } });
    fireEvent.change(screen.getByLabelText("Incident reason"), { target: { value: "regional outage" } });
    fireEvent.change(screen.getByLabelText("Offline-issued bundles (JSON)"), { target: { value: "[]" } });
    expect(screen.getByRole("button", { name: "Review emergency request" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reconcile break-glass bundles" })).toBeDisabled();
    expect(screen.getAllByText(unavailableDetail).length).toBeGreaterThanOrEqual(2);
    expect(previewBreakglassIssue).not.toHaveBeenCalled();
    expect(startBreakglassIssueCeremony).not.toHaveBeenCalled();
    expect(breakglassIssue).not.toHaveBeenCalled();
    expect(breakglassReconcile).not.toHaveBeenCalled();
  });

  it("recovers a prior signed issue from the durable list after a fresh component mount", async () => {
    const record = {
      tenant_id: "tenant-1",
      ceremony_id: "ceremony-1",
      request_id: "incident-1",
      subject: "recovery.test",
      request_digest: "digest-1",
      event_sequence: 42,
      issued_at: "2026-10-12T12:00:00Z",
    };
    breakglassIssues.mockResolvedValue({ items: [record], next_cursor: "" });
    breakglassAuthorityReceipts.mockResolvedValue({ items: [], next_cursor: "" });
    getBreakglassIssue.mockResolvedValue({
      ...record,
      bundle: {
        request_id: "incident-1",
        subject: "recovery.test",
        cert_der: "AQID",
        reason: "outage",
        approvals: ["a", "b"],
        issued_at: record.issued_at,
        signature: "BAUG",
      },
    });
    render(
      <AppQueryProvider>
        <CapabilityFixtureProvider view={unavailableRuntime}>
          <BreakGlassReconcile />
        </CapabilityFixtureProvider>
      </AppQueryProvider>,
    );
    expect(await screen.findByRole("button", { name: /recovery.test · incident-1/ })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Download signed bundle" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download certificate" })).toBeInTheDocument();
    expect(getBreakglassIssue).toHaveBeenCalledWith("ceremony-1");
  });

  it("recovers a prior emergency CA public result after a fresh console mount", async () => {
    breakglassIssues.mockResolvedValue({ items: [], next_cursor: "" });
    breakglassAuthorityReceipts.mockResolvedValue({
      items: [
        {
          tenant_id: "tenant-1",
          ceremony_id: "ceremony-rotation",
          kind: "rotation",
          subject: "successor-handle",
          request_digest: "sha256:exact",
          event_sequence: 93,
          completed_at: "2026-10-12T12:00:00Z",
        },
      ],
      next_cursor: "",
    });
    getBreakglassAuthorityReceipt.mockResolvedValue({
      tenant_id: "tenant-1",
      ceremony_id: "ceremony-rotation",
      kind: "rotation",
      subject: "successor-handle",
      request_digest: "sha256:exact",
      event_sequence: 93,
      completed_at: "2026-10-12T12:00:00Z",
      rotation: {
        ceremony_id: "ceremony-rotation",
        active_signer_handle: "successor-handle",
        previous_signer_handle: "predecessor-handle",
        active_certificate_pem: "-----BEGIN CERTIFICATE-----\nACTIVE\n-----END CERTIFICATE-----",
        previous_certificate_pem: "-----BEGIN CERTIFICATE-----\nPREVIOUS\n-----END CERTIFICATE-----",
        new_signed_by_previous_pem: "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----",
        previous_signed_by_new_pem: "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----",
        request_digest: "sha256:exact",
      },
    });
    render(
      <AppQueryProvider>
        <CapabilityFixtureProvider view={unavailableRuntime}>
          <BreakGlassReconcile />
        </CapabilityFixtureProvider>
      </AppQueryProvider>,
    );
    expect(await screen.findByRole("button", { name: "View signed public result" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "View signed public result" }));
    expect(await screen.findByRole("button", { name: "Download public CA result" })).toBeInTheDocument();
    expect(getBreakglassAuthorityReceipt).toHaveBeenCalledWith("ceremony-rotation");
    expect(rotateBreakglass).not.toHaveBeenCalled();
    expect(crossSignBreakglass).not.toHaveBeenCalled();
  });

  it("does not execute an approved rotation after its reviewed reason changes", async () => {
    breakglassIssues.mockResolvedValue({ items: [], next_cursor: "" });
    breakglassAuthorityReceipts.mockResolvedValue({ items: [], next_cursor: "" });
    startBreakglassRotationCeremony.mockResolvedValue({
      id: "ceremony-1",
      tenant_id: "tenant-1",
      purpose: "sha256:bound-request",
      status: "approved",
      approvals: 2,
      threshold: 2,
      created_at: "2026-10-12T12:00:00Z",
    });
    const view: CapabilityView = {
      ...unavailableRuntime,
      items: [
        {
          ...unavailableRuntime.items[0],
          actions: {
            ...unavailableRuntime.items[0].actions,
            allowed: ["startBreakglassRotationCeremony", "rotateBreakglass"],
          },
        },
      ],
    };
    render(
      <AppQueryProvider>
        <CapabilityFixtureProvider view={view}>
          <BreakGlassReconcile />
        </CapabilityFixtureProvider>
      </AppQueryProvider>,
    );
    fireEvent.click(screen.getByText("Rotate emergency CA"));
    fireEvent.change(screen.getByLabelText("CA rotation reason"), { target: { value: "incident 1" } });
    fireEvent.click(screen.getByRole("button", { name: "Open CA rotation ceremony" }));
    expect(await screen.findByText(/Approval digest: sha256:bound-request/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rotate approved CA" })).toBeEnabled();
    fireEvent.change(screen.getByLabelText("CA rotation reason"), { target: { value: "different incident" } });
    expect(screen.getByRole("button", { name: "Rotate approved CA" })).toBeDisabled();
    expect(rotateBreakglass).not.toHaveBeenCalled();
  });
});
