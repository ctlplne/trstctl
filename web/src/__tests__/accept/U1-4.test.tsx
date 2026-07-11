import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { DeploymentReceipts } from "@/components/certs";
import type { ConnectorDelivery } from "@/lib/api";

function delivery(partial: Partial<ConnectorDelivery>): ConnectorDelivery {
  return {
    id: "d",
    connector: "nginx",
    target: "edge/prod",
    destination: "edge",
    status: "delivered",
    attempts: 1,
    created_at: "",
    updated_at: "",
    tenant_id: "t",
    ...partial,
  } as unknown as ConnectorDelivery;
}

describe("U1-4 closed-loop deployment receipts", () => {
  it("renders connector delivery receipts with status and rollback ref", () => {
    const deliveries = [
      delivery({ id: "d1", connector: "nginx", target: "edge/prod", status: "delivered" }),
      delivery({ id: "d2", connector: "f5", target: "dc/lb", status: "failed", rollback_ref: "restore-123" }),
      delivery({ id: "d3", connector: "acm", target: "aws/use1", status: "queued", attempts: 0 }),
    ];
    render(<DeploymentReceipts deliveries={deliveries} />);
    const list = screen.getByRole("list", { name: "Connector delivery receipts" });
    expect(within(list).getByText("delivered")).toBeInTheDocument();
    expect(within(list).getByText("failed")).toBeInTheDocument();
    expect(within(list).getByText(/restore-123/)).toBeInTheDocument();
  });

  it("shows an empty state when there are no receipts", () => {
    render(<DeploymentReceipts deliveries={[]} />);
    expect(screen.getByText(/No deployment receipts/)).toBeInTheDocument();
  });
});
