import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppRoutes } from "@/App";
import { AuthProvider } from "@/auth/AuthProvider";
import { ThemeProvider } from "@/components/ThemeProvider";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    owners: vi.fn(),
    ownershipAttribution: vi.fn(),
    unownedIdentities: vi.fn(),
    createOwner: vi.fn(),
    updateOwner: vi.fn(),
    deleteOwner: vi.fn(),
    attestOwner: vi.fn(),
    grantOwnershipException: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderOwners() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/owners"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

const owner = {
  id: "owner-payments",
  name: "Payments team",
  kind: "team" as const,
  email: "payments@example.test",
  application_id: "APP-0044",
  service: "payments-api",
  business_unit: "commerce",
  environment: "production",
  escalation_chain: ["oncall@example.test", "director@example.test"],
  ownership_complete: true,
  ownership_attested: false,
  ownership_current: false,
};

describe("AUD-44 ownership readiness console", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "operator-44", tenant_id: "t1", email: "operator@example.test" });
    apiMock.owners.mockResolvedValue([owner]);
    apiMock.ownershipAttribution.mockResolvedValue({
      generated_at: "2026-08-12T10:00:00Z",
      summary: {},
      coverage: [],
      items: [],
    });
    apiMock.unownedIdentities.mockResolvedValue({
      items: [],
      counts: {
        no_owner: 0,
        owner_missing_application_model: 0,
        ownership_never_attested: 0,
        ownership_attestation_stale: 0,
      },
      guidance: "",
    });
  });

  it("edits the full owner model and performs an explicit attestation", async () => {
    const user = userEvent.setup();
    apiMock.updateOwner.mockResolvedValue({ ...owner, service: "payments-control" });
    apiMock.attestOwner.mockResolvedValue({
      ...owner,
      ownership_attested: true,
      ownership_current: true,
      ownership_attestation_due_at: "2026-11-10T10:00:00Z",
    });
    renderOwners();

    const table = await screen.findByRole("table", { name: "Credential owners" });
    expect(screen.getByText("Current owner records").closest(".rounded-panel")).toHaveTextContent("0/1");
    expect(screen.queryByText("Ownership coverage")).not.toBeInTheDocument();
    const row = within(table).getByRole("row", { name: /Payments team/ });
    expect(row).toHaveTextContent("APP-0044");
    expect(row).toHaveTextContent("Needs attestation");

    await user.click(within(row).getByRole("button", { name: "Edit" }));
    expect(screen.getByLabelText("Application ID")).toHaveValue("APP-0044");
    expect(screen.getByLabelText("Service")).toHaveValue("payments-api");
    expect(screen.getByLabelText("Business unit")).toHaveValue("commerce");
    expect(screen.getByLabelText("Environment")).toHaveValue("production");
    expect(screen.getByLabelText("Escalation recipients (one per line)")).toHaveValue("oncall@example.test\ndirector@example.test");
    await user.clear(screen.getByLabelText("Service"));
    await user.type(screen.getByLabelText("Service"), "payments-control");
    await user.click(screen.getByRole("button", { name: "Save owner" }));
    expect(apiMock.updateOwner).toHaveBeenCalledWith(
      "owner-payments",
      expect.objectContaining({
        application_id: "APP-0044",
        service: "payments-control",
        business_unit: "commerce",
        environment: "production",
        escalation_chain: ["oncall@example.test", "director@example.test"],
      }),
    );

    const updatedRow = within(table).getByRole("row", { name: /Payments team/ });
    await user.click(within(updatedRow).getByRole("button", { name: "Attest" }));
    expect(apiMock.attestOwner).toHaveBeenCalledWith("owner-payments");
    expect(await within(updatedRow).findByText("Current until 2026-11-10")).toBeInTheDocument();
  });

  it("grants an attributed exception with an explicit bounded expiry", async () => {
    const user = userEvent.setup();
    apiMock.unownedIdentities.mockResolvedValue({
      items: [
        {
          identity_id: "identity-44",
          name: "payments-deployer",
          reason: "ownership_attestation_stale",
          detail: "Payments team must re-attest this application model.",
        },
      ],
      counts: {
        no_owner: 0,
        owner_missing_application_model: 0,
        ownership_never_attested: 0,
        ownership_attestation_stale: 1,
      },
      guidance: "Resolve the ownership record or grant a short-lived exception.",
    });
    apiMock.grantOwnershipException.mockResolvedValue({
      id: "exception-44",
      identity_id: "identity-44",
      reason: "Incident recovery",
      granted_by: "operator-44",
      granted_at: "2026-08-12T10:00:00Z",
      expires_at: "2026-08-13T10:00:00Z",
      active: true,
    });
    renderOwners();

    const exceptionButton = await screen.findByRole("button", { name: "Grant temporary exception" });
    expect(exceptionButton.closest("section")).toHaveTextContent("Stale attestations: 1.");
    await user.click(exceptionButton);
    await user.type(screen.getByLabelText("Reason"), "Incident recovery");
    await user.clear(screen.getByLabelText("Expires in hours (maximum 720)"));
    await user.type(screen.getByLabelText("Expires in hours (maximum 720)"), "12");
    await user.click(screen.getByRole("button", { name: "Grant exception" }));

    expect(apiMock.grantOwnershipException).toHaveBeenCalledWith("identity-44", {
      reason: "Incident recovery",
      expires_at: expect.any(String),
    });
  });
});
