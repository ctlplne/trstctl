import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Identities } from "@/pages/Identities";
import { AppQueryProvider } from "@/lib/query";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import type { CapabilityView } from "@/lib/api-types.gen";

const fixture = vi.hoisted(() => ({ permissions: ["certs:request", "identities:read"], issue: vi.fn() }));
vi.mock("@/auth/AuthProvider", () => ({
  useAuth: () => ({ user: { subject: "requester", tenant_id: "tenant-a", roles: ["requester"], permissions: fixture.permissions }, loading: false }),
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      identities: vi.fn(async () => []),
      owners: vi.fn(async () => []),
      connectorDeliveries: vi.fn(async () => ({ items: [] })),
      rotationRuns: vi.fn(async () => ({ items: [] })),
      issueCertificate: fixture.issue,
    },
  };
});
function view(direct: boolean, request: boolean, unknown = false): CapabilityView {
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "The server authorizes every execution.",
    license: { tier: "community", state: "community" },
    items: [],
    operations: unknown
      ? []
      : [
          { operation_id: "createIdentity", state: direct ? "allowed" : "denied" },
          { operation_id: "transitionIdentity", state: direct ? "allowed" : "denied" },
          { operation_id: "openIssuanceRequest", state: request ? "allowed" : "denied" },
        ],
  };
}
function page(runtime: CapabilityView) {
  return (
    <MemoryRouter>
      <AppQueryProvider>
        <CapabilityFixtureProvider view={runtime}>
          <Identities />
        </CapabilityFixtureProvider>
      </AppQueryProvider>
    </MemoryRouter>
  );
}
beforeEach(() => {
  fixture.permissions = ["certs:request", "identities:read"];
  fixture.issue.mockReset();
});
describe("machine identity issuance authority", () => {
  it("offers authorized issuance and removes an open form when authority is lost", async () => {
    const user = userEvent.setup();
    fixture.permissions = ["*"];
    const rendered = render(page(view(true, true)));
    await user.click(await screen.findByRole("button", { name: "Add identity" }));
    expect(screen.getByLabelText("Service name")).toBeInTheDocument();
    fixture.permissions = ["certs:request"];
    rendered.rerender(page(view(false, true)));
    expect(screen.queryByLabelText("Service name")).not.toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Request a certificate" }).length).toBeGreaterThan(0);
    expect(fixture.issue).not.toHaveBeenCalled();
  });
  it("offers request-only users the supported request path instead of direct issuance", async () => {
    render(page(view(false, true)));
    await screen.findByText("No identities yet", { exact: true });
    expect(screen.queryByRole("button", { name: "Add identity" })).not.toBeInTheDocument();
    const links = screen.getAllByRole("link", { name: "Request a certificate" });
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) expect(link).toHaveAttribute("href", "/request");
    expect(screen.queryByRole("link", { name: "Set up your first certificate" })).not.toBeInTheDocument();
    expect(fixture.issue).not.toHaveBeenCalled();
  });
  it("requires certificate issuance authority even when identity writes are allowed", async () => {
    fixture.permissions = ["identities:write", "certs:request"];
    render(page(view(true, true)));
    await screen.findByText("No identities yet", { exact: true });
    expect(screen.queryByRole("button", { name: "Add identity" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Request a certificate" }).length).toBeGreaterThan(0);
  });
  it("does not offer either mutation when runtime authority is unknown", async () => {
    fixture.permissions = ["*"];
    render(page(view(false, false, true)));
    await screen.findByText("No identities yet", { exact: true });
    expect(screen.queryByRole("button", { name: "Add identity" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Set up your first certificate" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Request a certificate" })).not.toBeInTheDocument();
    expect(fixture.issue).not.toHaveBeenCalled();
  });
});
