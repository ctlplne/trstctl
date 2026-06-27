import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { NotificationCenter, deriveAlerts } from "@/components/notifications";
import type { CredentialRisk, Certificate } from "@/lib/api";

const risks = [
  { credential_id: "c1", subject: "payments-api", kind: "certificate", score: 95, owner_active: true },
  { credential_id: "c2", subject: "worker", kind: "certificate", score: 75, owner_active: true },
] as unknown as CredentialRisk[];
const certs = [{ id: "x1", subject: "edge-tls", not_after: new Date(Date.now() + 3 * 86_400_000).toISOString() }] as unknown as Certificate[];

describe("U8-1 notification & alert center", () => {
  it("ranks alerts by severity from served risk and expiry events", () => {
    const alerts = deriveAlerts(risks, certs);
    expect(alerts[0].severity).toBe("critical"); // critical sorts first
    expect(alerts.some((a) => a.severity === "high")).toBe(true);

    render(<NotificationCenter risks={risks} certs={certs} />);
    expect(screen.getByRole("heading", { name: "Alert center" })).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "Active alerts" });
    expect(within(list).getByText("Critical risk: payments-api")).toBeInTheDocument();
    expect(within(list).getByText("Expiring now: edge-tls")).toBeInTheDocument();
    expect(within(list).getByText("High risk: worker")).toBeInTheDocument();
  });
});
