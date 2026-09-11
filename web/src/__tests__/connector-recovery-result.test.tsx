import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { api, type ConnectorDelivery } from "@/lib/api";
import { AppQueryProvider } from "@/lib/query";
import { RecoveryResult } from "@/pages/connectors/RecoveryResult";

vi.mock("@/lib/api", () => ({ api: { connectorDelivery: vi.fn() } }));

const queued: ConnectorDelivery = {
  id: "restore-255",
  tenant_id: "tenant-1",
  outbox_id: 255,
  identity_id: "identity-1",
  destination: "connector.rollback",
  connector: "nginx",
  target: "edge/payments",
  status: "rollback_queued",
  attempts: 1,
  fingerprint: "successor",
  reason: "operator restore",
  detail: "Waiting for host proof",
  rollback_ref: "restore predecessor",
  idempotency_key: "command-key",
  created_at: "2026-09-11T15:12:01Z",
  updated_at: "2026-09-11T15:12:01Z",
};
const restored: ConnectorDelivery = {
  ...queued,
  status: "rolled_back",
  fingerprint: "predecessor",
  reason: "rolled_back_and_reverified",
  detail: "The host restored and verified the predecessor",
  idempotency_key: "job:rollback-result",
  updated_at: "2026-09-11T15:12:04Z",
};

function show() {
  return render(
    <AppQueryProvider>
      <RecoveryResult initial={queued} />
    </AppQueryProvider>,
  );
}

describe("exact connector restore result", () => {
  beforeEach(() => vi.mocked(api.connectorDelivery).mockReset());

  it("refreshes the same queued receipt automatically when the host finishes", async () => {
    vi.mocked(api.connectorDelivery).mockResolvedValueOnce(queued).mockResolvedValue(restored);
    show();
    await screen.findByRole("heading", { name: "Restore queued — waiting for agent proof" });
    expect(await screen.findByRole("heading", { name: "Previous version restored" }, { timeout: 4500 })).toBeInTheDocument();
    expect(vi.mocked(api.connectorDelivery).mock.calls.every(([id]) => id === queued.id)).toBe(true);
    expect(screen.queryByRole("button", { name: "Check restore result" })).not.toBeInTheDocument();
  });

  it.each([
    { id: "another-receipt" },
    { tenant_id: "another-tenant" },
    { outbox_id: 256 },
    { identity_id: "another-identity" },
    { connector: "apache" },
    { destination: "connector.deploy" },
  ])("refuses a completed result with different command identity %j", async (different) => {
    vi.mocked(api.connectorDelivery).mockResolvedValue({ ...restored, ...different });
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent("The exact restore result could not be confirmed");
    expect(screen.queryByRole("heading", { name: "Previous version restored" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check restore result" })).toBeEnabled();
  });

  it("accepts the canonical result when the display name becomes the execution route", async () => {
    vi.mocked(api.connectorDelivery).mockResolvedValue({ ...restored, target: "configured-execution-route" });
    show();
    expect(await screen.findByRole("heading", { name: "Previous version restored" })).toBeInTheDocument();
  });

  it("does not reuse prior success while reading a re-armed command on the same receipt", async () => {
    vi.mocked(api.connectorDelivery).mockResolvedValueOnce(restored);
    const view = show();
    await screen.findByRole("heading", { name: "Previous version restored" });
    let resolveRead!: (receipt: ConnectorDelivery) => void;
    vi.mocked(api.connectorDelivery).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveRead = resolve;
        }),
    );
    const next = { ...queued, idempotency_key: "second-command-key", updated_at: "2026-09-11T15:25:45Z" };
    view.rerender(
      <AppQueryProvider>
        <RecoveryResult initial={next} />
      </AppQueryProvider>,
    );
    await waitFor(() => expect(api.connectorDelivery).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("heading", { name: "Restore queued — waiting for agent proof" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Previous version restored" })).not.toBeInTheDocument();
    resolveRead({ ...restored, updated_at: "2026-09-11T15:25:46Z" });
    expect(await screen.findByRole("heading", { name: "Previous version restored" })).toBeInTheDocument();
  });

  it("keeps a failed read distinct from a failed restore and retries only the read", async () => {
    vi.mocked(api.connectorDelivery).mockRejectedValueOnce(new Error("HTTP 403")).mockResolvedValue(restored);
    const user = userEvent.setup();
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent("No new restore was submitted");
    await user.click(screen.getByRole("button", { name: "Check restore result" }));
    expect(await screen.findByRole("heading", { name: "Previous version restored" })).toBeInTheDocument();
    expect(api.connectorDelivery).toHaveBeenCalledTimes(2);
    expect(api.connectorDelivery).toHaveBeenNthCalledWith(2, queued.id);
  });

  it("reports terminal host failure without promoting it to restoration", async () => {
    vi.mocked(api.connectorDelivery).mockResolvedValue({ ...queued, status: "failed", detail: "The predecessor was absent" });
    show();
    expect(await screen.findByRole("heading", { name: "Restore not proven" })).toBeInTheDocument();
    expect(screen.getByText("The predecessor was absent")).toBeInTheDocument();
    await waitFor(() => expect(api.connectorDelivery).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole("heading", { name: "Previous version restored" })).not.toBeInTheDocument();
  });
  it.each(["rollback_queued", "rollback_failed"] as const)("can read a later retry result after %s without another restore", async (initialStatus) => {
    const failed = { ...queued, status: "rollback_failed", reason: "rollback_failed", detail: "The agent reached the target but the rollback did not succeed: connector rollback failed against the target" } satisfies ConnectorDelivery;
    vi.mocked(api.connectorDelivery).mockResolvedValueOnce(failed).mockResolvedValue(restored);
    const user = userEvent.setup();
    render(<AppQueryProvider><RecoveryResult initial={{ ...queued, status: initialStatus }} /></AppQueryProvider>);
    expect(await screen.findByText(failed.detail)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Restore not proven" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check restore result" }));
    expect(await screen.findByRole("heading", { name: "Previous version restored" })).toBeInTheDocument();
    expect(api.connectorDelivery).toHaveBeenCalledTimes(2);
    expect(api.connectorDelivery).toHaveBeenNthCalledWith(2, queued.id);
  });

});
