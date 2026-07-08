import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

const risks = [
  {
    credential_id: "c1",
    subject: "orphan-svc",
    kind: "x509",
    score: 80,
    exposure: 2,
    privilege: 2,
    sensitivity: 2,
    owner_active: false,
    expires_at: null,
    components: {},
  },
  {
    credential_id: "c2",
    subject: "owned-svc",
    kind: "x509",
    score: 10,
    exposure: 1,
    privilege: 1,
    sensitivity: 1,
    owner_active: true,
    expires_at: null,
    components: {},
  },
];

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, risk: async () => risks as unknown as Awaited<ReturnType<typeof actual.api.risk>> } };
});

import { OrphanGovernance } from "@/components/nhi";

describe("U3-2 ownership & orphan governance", () => {
  it("flags credentials whose owner is gone", async () => {
    render(<OrphanGovernance />);
    expect(await screen.findByText("orphan-svc")).toBeInTheDocument();
    expect(screen.getByText("Orphaned")).toBeInTheDocument();
    expect(screen.queryByText("owned-svc")).not.toBeInTheDocument();
  });
});
