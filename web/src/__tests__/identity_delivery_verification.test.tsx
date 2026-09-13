import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppQueryProvider } from "@/lib/query";
import { IdentityActivityEvidence } from "@/pages/identities/IdentityActivityEvidence";
import type { ConnectorDelivery, Identity } from "@/lib/api";

const { deliveries } = vi.hoisted(() => ({ deliveries: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, connectorDeliveries: deliveries, rotationRuns: vi.fn().mockResolvedValue({ items: [] }) } };
});
afterEach(cleanup);
beforeEach(() => deliveries.mockReset());

const identity = { id: "jks", name: "payments", kind: "x509_certificate", status: "deployed" } as Identity;
const delivery: ConnectorDelivery = {
  id: "delivery",
  identity_id: "jks",
  tenant_id: "tenant",
  outbox_id: 1202,
  destination: "connector.deploy",
  connector: "java-keystore",
  target: "payments",
  fingerprint: "exact-leaf",
  status: "delivered",
  attempts: 5,
  idempotency_key: "renew:exact",
  created_at: "2026-09-13T13:32:32Z",
  updated_at: "2026-09-13T13:33:51.266Z",
  detail: "Recovered after reload failure",
  rollback_ref: "restore predecessor",
};
const verification: ConnectorDelivery = {
  ...delivery,
  id: "verification",
  outbox_id: undefined,
  status: "verified",
  attempts: 1,
  idempotency_key: "renew:exact:verified",
  updated_at: "2026-09-13T13:33:51.316Z",
  detail: "Listener served the exact leaf",
  rollback_ref: "",
};
function show(items: ConnectorDelivery[], next_cursor = "") {
  deliveries.mockResolvedValue({ items, next_cursor });
  render(
    <AppQueryProvider>
      <IdentityActivityEvidence identity={identity} />
    </AppQueryProvider>,
  );
}
describe("delivery retries and separate endpoint verification", () => {
  it.each(["verified", "verify_failed"] as const)("retains five delivery attempts beside a later %s observation", async (status) => {
    show([{ ...verification, status }, delivery]);
    const actual = await screen.findByText("delivered java-keystore/payments after 5 attempts");
    expect(actual.closest("li")).toHaveTextContent("1202");
    expect(screen.getByText("restore predecessor")).toBeInTheDocument();
    const observation = screen.getByText("Endpoint verification").closest("li")!;
    expect(observation).toHaveTextContent(status === "verified" ? "Verified" : "Verification failed");
    expect(observation).toHaveTextContent("Listener served the exact leaf");
    expect(observation).not.toHaveTextContent("after 1 attempt");
    expect(within(observation).queryByText("1202")).not.toBeInTheDocument();
  });
  it.each(["idempotency_key", "fingerprint", "target", "connector"] as const)("does not attach another delivery's %s observation", async (field) => {
    show([{ ...verification, [field]: "other" }, delivery]);
    await screen.findByText("delivered java-keystore/payments after 5 attempts");
    expect(screen.getByText("No matching endpoint verification is recorded for this delivery.")).toBeInTheDocument();
    expect(screen.queryByText(verification.detail!)).not.toBeInTheDocument();
  });
  it("does not turn an orphan verification into a delivery or invent its retry count", async () => {
    show([verification]);
    await screen.findByText("no connector delivery receipt yet");
    expect(screen.queryByText(/after 1 attempt/)).not.toBeInTheDocument();
  });
  it("retains a canonical verified delivery that carries an actual outbox ID", async () => {
    show([{ ...delivery, status: "verified" }]);
    await screen.findByText("verified java-keystore/payments after 5 attempts");
    expect(screen.getByText("1202")).toBeInTheDocument();
  });
  it("withholds both summaries when receipt history is incomplete", async () => {
    show([verification, delivery], "more");
    await screen.findByRole("button", { name: "Load more delivery records" });
    expect(screen.queryByText(/after 5 attempts/)).not.toBeInTheDocument();
    expect(screen.queryByText(verification.detail!)).not.toBeInTheDocument();
  });
});
