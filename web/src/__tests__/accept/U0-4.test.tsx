import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { axe } from "vitest-axe";

const sample = [
  { credential_id: "c1", subject: "svc-a", kind: "x509", score: 92, exposure: 3, privilege: 3, sensitivity: 3, owner_active: true, expires_at: null, components: {} },
];

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, risk: async () => sample as unknown as Awaited<ReturnType<typeof actual.api.risk>> } };
});

import { RiskScore, useRisk } from "@/components/risk";

function RiskList() {
  const { loading, data } = useRisk({ sort: "score" });
  return <div>{loading ? "loading" : `count:${data.length}`}</div>;
}

describe("U0-4 risk lens primitive", () => {
  it("maps a score to a risk band badge with the value", () => {
    render(<RiskScore score={92} />);
    expect(screen.getByText("92")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("renders distinct low and high scores", () => {
    render(
      <div>
        <RiskScore score={5} />
        <RiskScore score={92} />
      </div>,
    );
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("92")).toBeInTheDocument();
  });

  it("useRisk wraps the served /risk/credentials endpoint", async () => {
    render(<RiskList />);
    await waitFor(() => expect(screen.getByText("count:1")).toBeInTheDocument());
  });

  it("has no accessibility violations", async () => {
    const { container } = render(<RiskScore score={50} />);
    expect(await axe(container)).toHaveNoViolations();
  });
});
