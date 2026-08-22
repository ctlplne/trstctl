import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ReadinessPanel } from "@/components/certs";
import type { Certificate, RotationRun } from "@/lib/api";

const DAY = 86_400_000;
function cert(partial: Partial<Certificate>): Certificate {
  return {
    id: "x",
    subject: "x",
    status: "active",
    fingerprint: "fp",
    not_after: new Date(Date.now() + 100 * DAY).toISOString(),
    ...partial,
  } as unknown as Certificate;
}

describe("U1-2 47-day renewal readiness panel", () => {
  it("computes auto vs manual from served rotation runs and flags manual certs at risk", () => {
    const certificates = [
      cert({ id: "c1", fingerprint: "f1" }),
      cert({ id: "c2", fingerprint: "f2" }),
      cert({ id: "c3", fingerprint: "f3", not_after: new Date(Date.now() + 10 * DAY).toISOString() }),
    ];
    const rotationRuns = [{ successor_fingerprint: "f1" }, { predecessor_fingerprint: "f2" }] as unknown as RotationRun[];

    render(<ReadinessPanel certificates={certificates} rotationRuns={rotationRuns} />);

    expect(screen.getByText("67%")).toBeInTheDocument();
    expect(screen.getByText(/1 manual certs expiring within 47 days/)).toHaveClass("text-status-warning");
    expect(screen.getByRole("img", { name: "Auto-renew vs manual" })).toBeInTheDocument();
  });
});
