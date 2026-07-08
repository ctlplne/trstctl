import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { RenewalHistory } from "@/components/certs";
import type { RotationRun } from "@/lib/api";

function run(partial: Partial<RotationRun>): RotationRun {
  return {
    id: "r",
    identity_id: "i",
    status: "succeeded",
    trigger: "ari",
    created_at: "2026-01-01",
    updated_at: "",
    tenant_id: "t",
    ...partial,
  } as unknown as RotationRun;
}

describe("U1-5 certificate detail renewal history", () => {
  it("lists rotation runs with status, trigger, and reason", () => {
    render(
      <RenewalHistory
        runs={[run({ id: "r1", status: "succeeded", trigger: "ari", reason: "47-day cadence" }), run({ id: "r2", status: "failed", trigger: "manual" })]}
      />,
    );
    expect(screen.getByText("succeeded")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
    expect(screen.getByText(/47-day cadence/)).toBeInTheDocument();
  });

  it("shows an empty state when there is no renewal history", () => {
    render(<RenewalHistory runs={[]} />);
    expect(screen.getByText(/No renewal history/)).toBeInTheDocument();
  });
});
