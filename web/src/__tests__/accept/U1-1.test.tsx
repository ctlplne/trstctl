import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { CertificatesDashboard } from "@/components/certs";
import type { Certificate } from "@/lib/api";
import type { RiskItem } from "@/components/risk";

const DAY = 86_400_000;
function cert(partial: Partial<Certificate>): Certificate {
  return {
    id: "x",
    subject: "x",
    status: "active",
    fingerprint: "fp",
    issuer: "CA",
    not_after: new Date(Date.now() + 200 * DAY).toISOString(),
    ...partial,
  } as unknown as Certificate;
}

describe("U1-1 certificates dashboard", () => {
  it("renders KPIs, an expiry-bucket chart, and a needs-attention list from real cert + risk shapes", () => {
    const certificates = [
      cert({ id: "c1", subject: "alpha", fingerprint: "f1", issuer: "CA1", not_after: new Date(Date.now() + 3 * DAY).toISOString() }),
      cert({ id: "c2", subject: "bravo", fingerprint: "f2", issuer: "CA1", not_after: new Date(Date.now() + 20 * DAY).toISOString() }),
      cert({ id: "c3", subject: "charlie", fingerprint: "f3", issuer: "CA2", not_after: new Date(Date.now() + 200 * DAY).toISOString() }),
      cert({ id: "c4", subject: "delta", status: "revoked", fingerprint: "f4", not_after: new Date(Date.now() - 5 * DAY).toISOString() }),
    ];
    const risks = [{ credential_id: "c1", score: 85 }] as unknown as RiskItem[];

    render(<CertificatesDashboard certificates={certificates} risks={risks} />);

    // The estate total/expiring KPIs live on the server-backed health panel;
    // this dashboard keeps the client-derived tiles that panel lacks.
    expect(screen.queryByText("Total certificates")).not.toBeInTheDocument();
    expect(screen.getByText("Revoked")).toBeInTheDocument();
    expect(screen.getByText("High risk")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Certificates by time to expiry" })).toBeInTheDocument();

    const list = screen.getByRole("list", { name: "Certificates needing attention" });
    expect(within(list).getByText("alpha")).toBeInTheDocument();
    expect(within(list).getByText("bravo")).toBeInTheDocument();
    expect(screen.queryByText("charlie")).not.toBeInTheDocument();
  });
});
