import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { CredentialActivityTimeline } from "@/components/CredentialActivityTimeline";
import type { ConnectorDelivery } from "@/lib/api";

afterEach(cleanup);

const failure = {
  id: "delivery-1",
  tenant_id: "tenant-1",
  created_at: "2026-09-13T08:00:00Z",
  updated_at: "2026-09-13T08:01:00Z",
  identity_id: "identity-1",
  outbox_id: 418,
  destination: "connector.deploy",
  connector: "java-keystore",
  target: "payments",
  status: "failed",
  attempts: 16,
  fingerprint: "",
  reason: "agent_reported_failure",
  detail: "Signing refused by the approved DNS profile. <script>untrusted</script>",
  rollback_ref: "",
} satisfies ConnectorDelivery;

describe("identity deployment attempt evidence", () => {
  it("shows the safe failure detail and exact job while escaping agent-supplied markup", () => {
    const { container } = render(<CredentialActivityTimeline credentialLabel="Payments" deliveryReceipt={failure} />);
    expect(screen.getByText(/failed java-keystore\/payments after 16 attempts/)).toBeInTheDocument();
    expect(screen.getByText(failure.detail)).toBeInTheDocument();
    expect(screen.getByText("418")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });

  it("does not show stale failure detail when the identity evidence is unavailable", () => {
    render(<CredentialActivityTimeline deliveryReceipt={failure} deliveryNotice="Evidence unavailable" />);
    expect(screen.getAllByText("Evidence unavailable")).toHaveLength(2);
    expect(screen.queryByText(failure.detail)).not.toBeInTheDocument();
    expect(screen.queryByText("418")).not.toBeInTheDocument();
  });

  it("replaces the displayed failure with the served recovery result", () => {
    const { rerender } = render(<CredentialActivityTimeline deliveryReceipt={failure} />);
    rerender(
      <CredentialActivityTimeline deliveryReceipt={{ ...failure, status: "delivered", attempts: 17, detail: "Delivered and verified on payments host" }} />,
    );
    expect(screen.getByText(/delivered java-keystore\/payments after 17 attempts/)).toBeInTheDocument();
    expect(screen.getByText("Delivered and verified on payments host")).toBeInTheDocument();
    expect(screen.queryByText(failure.detail)).not.toBeInTheDocument();
  });
});
