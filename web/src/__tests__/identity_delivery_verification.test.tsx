import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppQueryProvider } from "@/lib/query";
import { IdentityActivityEvidence } from "@/pages/identities/IdentityActivityEvidence";
import type { ConnectorDelivery, Identity } from "@/lib/api";
import { IntlProvider } from "@/i18n/I18nProvider";

const { deliveries, rotations } = vi.hoisted(() => ({ deliveries: vi.fn(), rotations: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, connectorDeliveries: deliveries, rotationRuns: rotations } };
});
afterEach(cleanup);
beforeEach(() => {
  deliveries.mockReset();
  rotations.mockReset().mockResolvedValue({ items: [] });
});

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
function show(items: ConnectorDelivery[], next_cursor = "", timeZone = "UTC", certificateFingerprint?: string) {
  deliveries.mockResolvedValue({ items, next_cursor });
  render(
    <IntlProvider initialLocale="en-US" initialTimeZone={timeZone}>
      <AppQueryProvider>
        <IdentityActivityEvidence identity={identity} certificateFingerprint={certificateFingerprint} />
      </AppQueryProvider>
    </IntlProvider>,
  );
}
describe("delivery retries and separate endpoint verification", () => {
  it("keeps an older selected certificate's proof instead of borrowing the newest successor", async () => {
    const newer = {
      ...delivery,
      id: "newer",
      fingerprint: "newer-leaf",
      attempts: 1,
      idempotency_key: "renew:newer",
      updated_at: "2026-09-13T13:40:00Z",
      rollback_ref: "newer-only-rollback",
    };
    const newerVerification = {
      ...verification,
      id: "newer-verification",
      fingerprint: "newer-leaf",
      idempotency_key: "renew:newer:verified",
      updated_at: "2026-09-13T13:40:01Z",
      detail: "newer-only-observation",
    };
    rotations.mockResolvedValue({
      items: [
        {
          id: "produced-selected",
          identity_id: identity.id,
          successor_fingerprint: "exact-leaf",
          predecessor_fingerprint: "earlier-leaf",
          status: "succeeded",
          trigger: "scheduler",
          created_at: "2026-09-13T13:33:00Z",
          updated_at: "2026-09-13T13:33:52Z",
          rollback_ref: "selected-only-rollback",
        },
        {
          id: "later-successor",
          identity_id: identity.id,
          successor_fingerprint: "newer-leaf",
          predecessor_fingerprint: "exact-leaf",
          status: "succeeded",
          trigger: "scheduler",
          created_at: "2026-09-13T13:40:00Z",
          updated_at: "2026-09-13T13:40:02Z",
          rollback_ref: "newer-only-rollback",
        },
      ],
    });
    show([newerVerification, newer, verification, delivery], "", "UTC", "exact-leaf");
    await screen.findByText("delivered java-keystore/payments after 5 attempts");
    expect(await screen.findByText("succeeded via scheduler; successor exact-leaf")).toBeInTheDocument();
    expect(screen.getByText("selected-only-rollback")).toBeInTheDocument();
    expect(screen.getByText("Listener served the exact leaf")).toBeInTheDocument();
    expect(screen.queryByText("newer-only-observation")).not.toBeInTheDocument();
    expect(screen.queryByText("newer-only-rollback")).not.toBeInTheDocument();
  });
  it("does not turn a rotation away from the selected certificate into its issuance proof", async () => {
    rotations.mockResolvedValue({
      items: [
        {
          id: "later-successor",
          identity_id: identity.id,
          successor_fingerprint: "newer-leaf",
          predecessor_fingerprint: "exact-leaf",
          status: "succeeded",
          trigger: "scheduler",
          updated_at: "2026-09-13T13:40:02Z",
          rollback_ref: "newer-only-rollback",
        },
      ],
    });
    show([verification, delivery], "", "UTC", "exact-leaf");
    await screen.findByText("No renewal that produced this certificate is recorded.");
    expect(screen.queryByText("succeeded via scheduler; successor newer-leaf")).not.toBeInTheDocument();
    expect(screen.getByText("restore predecessor")).toBeInTheDocument();
  });

  it("shows the exact verification observation in the operator's selected time zone", async () => {
    show([verification, delivery], "", "America/New_York");
    await screen.findByText("delivered java-keystore/payments after 5 attempts");
    const observation = screen.getByText("Endpoint verification").closest("li")!;
    expect(observation).toHaveTextContent(/Sep 13, 2026,\s9:33\sAM/);
    expect(observation).not.toHaveTextContent(/1:33\sPM/);
  });
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
