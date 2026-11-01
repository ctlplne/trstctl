import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DecoyDatabaseWorkflow } from "@/pages/secrets/DecoyDatabaseWorkflow";

const { apiMock, can } = vi.hoisted(() => ({
  apiMock: { dynamicSecretProviders: vi.fn(), listDatabaseDecoys: vi.fn(), createDatabaseDecoy: vi.fn(), retireDatabaseDecoy: vi.fn() },
  can: { value: true },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => can.value }));

const provider = (id: string, type: string) => ({
  id,
  type,
  label: id,
  allowed_roles: ["readonly"],
  configuration_revision: "r",
  maximum_ttl_seconds: 7776000,
  ready: true,
});

describe("Q6 decoy database logins", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    can.value = true;
    apiMock.dynamicSecretProviders.mockResolvedValue({ configured_providers: [provider("warehouse-pg", "postgresql"), provider("cache", "redis")] });
    apiMock.listDatabaseDecoys.mockResolvedValue({
      items: [
        {
          id: "d1",
          kind: "database",
          name: "warehouse bait",
          placement: "ops wiki",
          db_provider_id: "warehouse-pg",
          db_lease_id: "l1",
          db_role: "trstctl_app_0123456789",
          state: "triggered",
          created_at: "2026-11-01T00:00:00Z",
          triggered_at: "2026-11-01T02:00:00Z",
        },
      ],
      next_cursor: "",
    });
  });

  it("offers PostgreSQL providers only, mints with one retry-safe key, and shows the connection string once", async () => {
    apiMock.createDatabaseDecoy.mockRejectedValueOnce(new Error("network"));
    apiMock.createDatabaseDecoy.mockResolvedValueOnce({
      id: "d2",
      kind: "database",
      name: "billing bait",
      placement: "repo",
      db_provider_id: "warehouse-pg",
      db_lease_id: "l2",
      db_role: "trstctl_app_9876543210",
      state: "active",
      created_at: "2026-11-01T03:00:00Z",
      database: "trstctl_app_9876543210_db",
      dsn: "postgres://trstctl_app_9876543210:pw@db:5432/trstctl_app_9876543210_db",
    });
    const user = userEvent.setup();
    render(<DecoyDatabaseWorkflow />);
    expect(await screen.findByText("Used at", { exact: false })).toBeInTheDocument();
    const picker = screen.getByRole("combobox", { name: "PostgreSQL provider" });
    expect(within(picker).queryByRole("option", { name: "cache" })).toBeNull();
    await user.selectOptions(picker, "warehouse-pg");
    await user.type(screen.getByRole("textbox", { name: "Label" }), "billing bait");
    await user.type(screen.getByRole("textbox", { name: "Where you plant it" }), "repo");
    await user.click(screen.getByRole("button", { name: "Mint decoy login" }));
    await user.click(screen.getByRole("button", { name: "Mint decoy login" }));
    expect(apiMock.createDatabaseDecoy).toHaveBeenCalledTimes(2);
    const [firstInput, firstKey] = apiMock.createDatabaseDecoy.mock.calls[0];
    const [, secondKey] = apiMock.createDatabaseDecoy.mock.calls[1];
    expect(firstInput).toEqual({ provider: "warehouse-pg", name: "billing bait", placement: "repo", ttl_seconds: 30 * 86400 });
    expect(secondKey).toBe(firstKey);
    expect(await screen.findByText("Decoy connection string")).toBeInTheDocument();
  });

  it("is hidden from anyone who cannot plant decoys", () => {
    can.value = false;
    const { container } = render(<DecoyDatabaseWorkflow />);
    expect(container).toBeEmptyDOMElement();
    expect(apiMock.listDatabaseDecoys).not.toHaveBeenCalled();
  });
});
