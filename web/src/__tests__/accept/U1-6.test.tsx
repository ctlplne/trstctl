import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { IssuancePipeline, pipelineStages } from "@/components/issuance";
import type { Identity } from "@/lib/api";

function identity(status: string, id: string): Identity {
  return { id, name: id, kind: "workload_identity", status, owner_id: "o", tenant_id: "t" } as unknown as Identity;
}

describe("U1-6 issuance pipeline", () => {
  it("groups identities by lifecycle stage in pipeline order", () => {
    const stages = pipelineStages([identity("issued", "a"), identity("issued", "b"), identity("deployed", "c"), identity("revoked", "d")]);
    expect(stages.find((stage) => stage.stage === "issued")?.count).toBe(2);
    expect(stages.find((stage) => stage.stage === "deployed")?.count).toBe(1);
    const order = stages.map((stage) => stage.stage);
    expect(order.indexOf("issued")).toBeLessThan(order.indexOf("deployed"));
    expect(order.indexOf("deployed")).toBeLessThan(order.indexOf("revoked"));
  });

  it("renders a stage tile per lifecycle stage", () => {
    render(<IssuancePipeline counts={{ issued: 20, deployed: 10 }} />);
    expect(screen.getByText("Issued")).toBeInTheDocument();
    expect(screen.getByText("Deployed")).toBeInTheDocument();
    expect(screen.getByText("20")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
  });
});
