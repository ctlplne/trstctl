import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Incidents } from "@/pages/Incidents";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    incidentExecutions: vi.fn(),
    fleetReissuanceRuns: vi.fn(),
    ownerRemediationActions: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: new Proxy(
      { ...actual.api, ...apiMock },
      {
        // Any reader this page calls that the fixture does not name resolves
        // empty, so the test is about the deep link and nothing else.
        get(target, prop: string) {
          const value = (target as Record<string, unknown>)[prop];
          if (typeof value === "function") return value;
          return () => Promise.resolve({ items: [] });
        },
      },
    ),
  };
});

// S-C11: the response loop is only closed if the identity actually arrives.
// The graph and the certificate drawer link with ?identity=<id>; this pins the
// receiving half so a rename of the parameter cannot silently break the hop.
describe("incident response deep link", () => {
  it("preselects the affected identity from the identity query parameter", async () => {
    apiMock.identities.mockResolvedValue([{ id: "cred-42", name: "payments-api", kind: "x509_certificate", owner_id: "owner-1", status: "issued" }]);
    apiMock.incidentExecutions.mockResolvedValue({ items: [] });
    apiMock.fleetReissuanceRuns.mockResolvedValue({ items: [] });
    apiMock.ownerRemediationActions.mockResolvedValue({ items: [] });

    render(
      <MemoryRouter initialEntries={["/incidents?identity=cred-42"]}>
        <Incidents />
      </MemoryRouter>,
    );

    const picker = (await screen.findByLabelText(/affected identity/i)) as HTMLInputElement | HTMLSelectElement;
    expect(picker.value).toBe("cred-42");
  });
});
