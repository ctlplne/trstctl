import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Identities } from "@/pages/Identities";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    getIdentity: vi.fn(),
    transitionIdentity: vi.fn(),
    graphBlastRadius: vi.fn(),
    connectorDeliveries: vi.fn(),
    rotationRuns: vi.fn(),
    lifecycleAutomationPlan: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderIdentities() {
  return render(
    <MemoryRouter>
      <Identities />
    </MemoryRouter>,
  );
}

describe("WIRE-11 identity delivery and rotation evidence", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.identities.mockResolvedValue([
      {
        id: "id-deployed-1",
        name: "payments-tls",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
      },
    ]);
    apiMock.getIdentity.mockResolvedValue({
      id: "id-deployed-1",
      name: "payments-tls",
      kind: "x509_certificate",
      owner_id: "owner-1",
      status: "deployed",
    });
    apiMock.transitionIdentity.mockResolvedValue({ id: "id-deployed-1", name: "payments-tls", status: "renewing" });
    apiMock.graphBlastRadius.mockResolvedValue({ node: { id: "cert:id-deployed-1", kind: "credential", name: "payments-tls" }, affected: [], by_kind: {} });
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "delivery-1",
          tenant_id: "tenant-1",
          identity_id: "id-deployed-1",
          destination: "connector.deploy",
          connector: "kubernetes",
          target: "prod/payments-tls",
          fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          status: "delivered",
          attempts: 1,
          reason: "outbox_delivered",
          detail: "receipt persisted by delivery worker",
          rollback_ref: "rollback:delivery-1",
          idempotency_key: "idem-delivery-1",
          created_at: "2026-06-26T13:00:00Z",
          updated_at: "2026-06-26T13:01:00Z",
        },
      ],
    });
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "rotation-1",
          tenant_id: "tenant-1",
          identity_id: "id-deployed-1",
          status: "succeeded",
          trigger: "scheduler",
          reason: "renew-before window reached",
          predecessor_fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          successor_fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          rollback_ref: "restore sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          idempotency_key: "idem-rotation-1",
          created_at: "2026-06-26T12:58:00Z",
          updated_at: "2026-06-26T13:02:00Z",
          completed_at: "2026-06-26T13:02:00Z",
        },
      ],
    });
    apiMock.lifecycleAutomationPlan.mockResolvedValue({
      capability: "lifecycle_automation",
      ready: true,
      generated_at: "2026-06-26T13:02:00Z",
      scheduler: {
        status: "running",
        renew_before: "720h0m0s",
        alert_before: "336h0m0s",
        interval: "1m0s",
        ari_first: true,
        maintenance_window_status: "open",
      },
      summary: { monitored: 1, due_now: 0, renewal_failed: 0, outbox_pending: 0, outbox_processing: 0, outbox_failed: 0 },
      items: [],
      controls: [],
      preview_writes: [],
      preview_external_effects: [],
      execution_writes: [],
      execution_external_effects: [],
      verification_steps: [],
    });
  });

  it("renders served delivery and rotation evidence while removing unserved preview panels", async () => {
    const user = userEvent.setup();
    renderIdentities();

    await waitFor(() => expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 50 }));
    expect(apiMock.rotationRuns).toHaveBeenCalledWith({ limit: 50 });
    const identitiesTable = await screen.findByRole("table", { name: /credential identities/i });
    await user.click((await screen.findAllByText("Delivery and rotation evidence"))[0]);
    expect(screen.getAllByText("kubernetes").length).toBeGreaterThan(0);
    expect(screen.getAllByText("prod/payments-tls").length).toBeGreaterThan(0);
    await user.click(screen.getByText("Show exact reason"));
    expect(screen.getByText("outbox_delivered")).toBeInTheDocument();
    expect(screen.getAllByText("succeeded").length).toBeGreaterThan(0);
    expect(screen.getAllByText("scheduler").length).toBeGreaterThan(0);
    expect(screen.getByText("restore sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")).toBeInTheDocument();

    const identityRow = within(identitiesTable).getByText("payments-tls").closest("tr")!;
    expect(identityRow).toHaveTextContent("Delivered successfully.");
    expect(identityRow).not.toHaveTextContent("outbox_delivered");

    expect(screen.getByRole("heading", { name: "Lifecycle automation" })).toBeInTheDocument();
    expect(screen.getByText("Nothing needs a manual nudge right now. trstctl will keep checking.")).toBeInTheDocument();
    expect(screen.queryByText("Automation layout preview")).not.toBeInTheDocument();
    expect(screen.queryByText("JIT approvals moved to the inbox")).not.toBeInTheDocument();
    expect(screen.queryByText("Pending JIT approval requests")).not.toBeInTheDocument();
  });

  it("deletes the automation-preview and duplicate JIT-summary components", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Identities.tsx"), "utf8");
    expect(source).not.toMatch(/function\s+LifecycleAutomationDisclosure/);
    expect(source).not.toMatch(/Automation layout preview/);
    expect(source).not.toMatch(/function\s+PendingApprovalSummary/);
    expect(source).not.toMatch(/JIT approvals moved to the inbox/);
  });
});
