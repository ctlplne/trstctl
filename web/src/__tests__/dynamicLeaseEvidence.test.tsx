import { useEffect, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AppQueryProvider, useQueryClient } from "@/lib/query";
import type { DynamicLease } from "@/lib/api";
import { DynamicLeaseEvidence } from "@/pages/secrets/DynamicLeaseEvidence";
import { useDynamicLeaseMetadata } from "@/pages/secrets/useDynamicLeaseMetadata";

const { read } = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, getDynamicLease: read } };
});

function Receipt({ receipt }: { receipt: DynamicLease }) {
  const result = useDynamicLeaseMetadata(receipt);
  const client = useQueryClient();
  const [credential, setCredential] = useState({ leaseID: receipt.id, value: "REVEAL-FIXTURE" } as { leaseID: string; value: string } | null);
  useEffect(() => {
    if (!result.active) setCredential(null);
  }, [result.active]);
  return (
    <>
      <DynamicLeaseEvidence
        lease={result.lease!}
        active={result.active}
        error={result.error}
        refresh={result.refresh}
        credential={credential}
        dismiss={() => setCredential(null)}
      />
      <button disabled={!result.active}>Renew fixture</button>
      <output data-testid="headroom">{result.headroom}</output>
      <button
        onClick={() => {
          expect(JSON.stringify(client.getQueriesData({ queryKey: ["dynamic-secret-lease"] }))).not.toMatch(/FORBIDDEN|credential/);
        }}
      >
        Inspect safe cache
      </button>
    </>
  );
}

function renderReceipt(receipt: DynamicLease) {
  return render(
    <AppQueryProvider>
      <Receipt receipt={receipt} />
    </AppQueryProvider>,
  );
}

describe("dynamic lease provider evidence", () => {
  let lease: DynamicLease;
  beforeEach(() => {
    read.mockReset();
    lease = {
      id: "exact-lease",
      provider: "qa-postgres",
      role: "reader",
      state: "active",
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 60000).toISOString(),
      hard_expires_at: new Date(Date.now() + 120000).toISOString(),
      revocation_status: "none",
    };
    read.mockResolvedValue(lease);
  });
  afterEach(cleanup);

  it("refreshes provider completion on tab return and removes the reveal", async () => {
    renderReceipt(lease);
    expect(await screen.findByText("REVEAL-FIXTURE")).toBeInTheDocument();
    await waitFor(() => expect(read).toHaveBeenCalledWith(lease.id, expect.any(AbortSignal)));
    read.mockResolvedValue({
      ...lease,
      state: "revoked",
      revocation_status: "completed",
      revocation_completed_at: new Date().toISOString(),
      credential: "FORBIDDEN-METADATA-CREDENTIAL",
    });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    expect(await screen.findByText("Provider confirmed credential removal")).toBeInTheDocument();
    expect(screen.queryByText("REVEAL-FIXTURE")).not.toBeInTheDocument();
    expect(screen.queryByText("FORBIDDEN-METADATA-CREDENTIAL")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Renew fixture" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Inspect safe cache" }));
  });

  it("shows no renewal allowance after revocation is queued", async () => {
    read.mockResolvedValue({ ...lease, state: "revoked", revocation_status: "pending" });
    renderReceipt(lease);
    expect(await screen.findByText("Revocation queued; provider removal pending")).toBeInTheDocument();
    expect(screen.getByTestId("headroom")).toHaveTextContent("0");
    expect(screen.queryByText("Provider confirmed credential removal")).not.toBeInTheDocument();
    expect(screen.queryByText("REVEAL-FIXTURE")).not.toBeInTheDocument();
  });

  it("uses the persisted original renewal limit for an active lease", async () => {
    renderReceipt(lease);
    await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
    expect(screen.getByTestId("headroom")).toHaveTextContent("60");
  });

  it("clears the reveal at the deadline without waiting for the next provider read", async () => {
    lease = { ...lease, expires_at: new Date(Date.now() + 300).toISOString() };
    read.mockResolvedValue(lease);
    renderReceipt(lease);
    expect(await screen.findByText("REVEAL-FIXTURE")).toBeInTheDocument();
    expect(await screen.findByText("Lease ended; provider removal unconfirmed")).toBeInTheDocument();
    expect(screen.queryByText("REVEAL-FIXTURE")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Renew fixture" })).toBeDisabled();
    expect(read).toHaveBeenCalledTimes(1);
  });

  it.each(["different lease", "read failure"])("clears stale proof on %s", async (failure) => {
    renderReceipt(lease);
    expect(await screen.findByText("REVEAL-FIXTURE")).toBeInTheDocument();
    await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
    if (failure === "different lease") read.mockResolvedValue({ ...lease, id: "another-lease", credential: "FORBIDDEN" });
    else read.mockRejectedValue(new Error("metadata unavailable"));
    fireEvent.click(screen.getByRole("button", { name: "Refresh lease status" }));
    await waitFor(() => expect(screen.queryByText("REVEAL-FIXTURE")).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Renew fixture" })).toBeDisabled();
    expect(screen.queryByText("another-lease")).not.toBeInTheDocument();
    expect(screen.queryByText("Provider confirmed credential removal")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Inspect safe cache" }));
  });
});
