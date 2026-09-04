import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Connectors } from "@/pages/Connectors";
import { ToastProvider } from "@/components/ToastProvider";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    connectorCatalog: vi.fn(),
    connectorTargets: vi.fn(),
    identities: vi.fn(),
    connectorDeliveries: vi.fn(),
    outboxCircuits: vi.fn(),
    endpointVerifications: vi.fn(),
    endpointKeyCustody: vi.fn(),
    createConnectorTarget: vi.fn(),
    createEndpointBinding: vi.fn(),
    bindIdentityConnectorTarget: vi.fn(),
    testConnectorTarget: vi.fn(),
    deployConnectorTarget: vi.fn(),
    rollbackConnectorTarget: vi.fn(),
    updateConnectorTarget: vi.fn(),
    deleteConnectorTarget: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderConnectors() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <Connectors />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("route 031 decision-first deployment destination design", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.connectorCatalog.mockResolvedValue({
      items: [
        {
          name: "nginx",
          kind: "file/process",
          delivery_mode: "native registry, signed plugin, or receipt",
          target_vantage: "host_agent",
          rollback: "restore the previous fullchain and key, then reload nginx",
          executes_rollback: true,
          device_proven: false,
        },
        {
          name: "f5",
          kind: "appliance",
          delivery_mode: "network relay",
          target_vantage: "network_relay",
          rollback: "rebind the previous certificate object",
          executes_rollback: true,
          device_proven: true,
        },
      ],
      relay_plugins: [],
    });
    apiMock.connectorTargets.mockResolvedValue({
      items: [
        {
          id: "target-31",
          tenant_id: "tenant-31",
          name: "payments edge",
          connector: "nginx",
          config: { credential_ref: "secret://connectors/nginx" },
          created_at: "2026-08-21T11:00:00Z",
        },
      ],
    });
    apiMock.endpointVerifications.mockResolvedValue({
      summary: { endpoints: 1, verified: 1, diverged: 0, unreachable: 0, not_checked: 0 },
      items: [
        {
          endpoint_id: "target-31",
          address: "payments.example:443",
          vantage: "local",
          status: "verified",
          checked_sans: true,
          checked_chain: true,
          last_checked_at: "2026-08-21T11:00:00Z",
        },
        {
          endpoint_id: "unconfigured-target-31",
          address: "unconfigured.example:443",
          vantage: "local",
          status: "verified",
          checked_sans: true,
          checked_chain: true,
          last_checked_at: "2026-08-21T11:00:00Z",
        },
      ],
    });
    apiMock.identities.mockResolvedValue([
      {
        id: "identity-31",
        tenant_id: "tenant-31",
        name: "payments.example",
        kind: "x509_certificate",
        status: "issued",
        attributes: {},
        created_at: "2026-08-21T11:00:00Z",
      },
    ]);
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "delivery-31",
          tenant_id: "tenant-31",
          destination: "connector.deploy",
          connector: "nginx",
          target: "payments edge",
          status: "delivered",
          attempts: 1,
          fingerprint: "sha256:delivery-31",
          rollback_ref: "rollback:delivery-31",
          created_at: "2026-08-21T11:00:00Z",
          updated_at: "2026-08-21T11:00:00Z",
        },
      ],
    });
    apiMock.outboxCircuits.mockResolvedValue({ items: [] });
    apiMock.endpointKeyCustody.mockResolvedValue({ items: [], summary: { host_generated: 0, targets: 0, migrated_percent: 0 } });
  });

  it("answers destination coverage and health before revealing connector machinery", async () => {
    const user = userEvent.setup();
    renderConnectors();

    expect(await screen.findByRole("heading", { level: 1, name: "Where credentials are installed" })).toBeInTheDocument();
    expect(screen.getByText("Which destinations trstctl can update and whether they are healthy.", { exact: true })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 2, name: "1 destination is configured and verified" })).toBeInTheDocument();
    expect(screen.getByText("1 connector type can execute rollback for this deployment.", { exact: true })).toBeInTheDocument();

    const actions = screen.getByTestId("page-depth-operate");
    expect(within(actions).getAllByRole("button")).toHaveLength(1);
    const add = within(actions).getByRole("button", { name: "Add destination" });
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(document.querySelectorAll("main input, main select, main textarea")).toHaveLength(0);
    expect(apiMock.identities).not.toHaveBeenCalled();
    expect(apiMock.connectorDeliveries).not.toHaveBeenCalled();
    expect(apiMock.outboxCircuits).not.toHaveBeenCalled();
    expect(apiMock.endpointKeyCustody).not.toHaveBeenCalled();

    const disclosures = ["Destinations and safe actions", "Health, retries, and rollback", "Connector capabilities and plugin evidence"].map((title) =>
      screen.getByText(title, { exact: true }).closest("details"),
    );
    expect(disclosures.every((details) => details && !details.hasAttribute("open"))).toBe(true);

    await user.click(add);
    const dialog = screen.getByRole("dialog", { name: "Add destination" });
    expect(within(dialog).getByText(/Saving a destination does not deploy a credential/, { exact: false })).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Destination name", { exact: true })).toHaveFocus();
    expect(dialog).toHaveClass("max-h-[calc(100dvh-2rem)]", "overflow-y-auto", "overscroll-contain");
    expect(dialog).not.toHaveClass("motion-safe:animate-panel-in");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(apiMock.createConnectorTarget).not.toHaveBeenCalled();

    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    await waitFor(() => expect(apiMock.identities).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("table", { name: "Configured deployment destinations" })).toHaveTextContent("payments edge");
    expect(screen.getByRole("button", { name: "Deploy" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review restore" })).toBeInTheDocument();

    await user.click(screen.getByText("Health, retries, and rollback", { exact: true }));
    await waitFor(() => expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 20 }));
    expect(apiMock.outboxCircuits).toHaveBeenCalledTimes(1);
    expect(apiMock.endpointKeyCustody).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("heading", { name: "Recent delivery receipts" })).toBeInTheDocument();
    const deliveryTable = screen.getByRole("table", { name: "Recent connector delivery receipts" });
    expect(within(deliveryTable).getByText("rollback:delivery-31")).toBeInTheDocument();
    expect(deliveryTable.parentElement).toHaveAttribute("tabindex", "0");
    expect(deliveryTable.parentElement).toHaveClass("min-w-0", "max-w-full", "w-full");
    expect(deliveryTable.closest("section")).toHaveClass("min-w-0", "grid-cols-[minmax(0,1fr)]");
    expect(deliveryTable.closest("section")?.parentElement).toHaveClass("min-w-0", "grid-cols-[minmax(0,1fr)]");

    await user.click(screen.getByText("Connector capabilities and plugin evidence", { exact: true }));
    const capabilityTable = await screen.findByRole("table", { name: "Connector capability registry" });
    expect(capabilityTable).toHaveTextContent("nginx");
    expect(capabilityTable.parentElement).toHaveAttribute("tabindex", "0");
    expect(screen.getByRole("heading", { name: "Verified relay plugins" })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/BEGIN .* PRIVATE KEY|raw token hidden/i);
  });

  it("keeps exact expert scope named but closed on first view", async () => {
    const user = userEvent.setup();
    renderConnectors();
    await screen.findByRole("heading", { level: 1, name: "Where credentials are installed" });

    const technical = screen.getByTestId("page-depth-prove");
    expect(technical).not.toHaveAttribute("open");
    await user.click(within(technical).getByText("Show exact evidence", { exact: true }));
    expect(technical).toHaveTextContent("Capabilities, grants, health, retries, rollback, plugin evidence.");
  });

  it("does not call an empty deployment estate healthy", async () => {
    apiMock.connectorTargets.mockResolvedValue({ items: [] });
    apiMock.endpointVerifications.mockResolvedValue({
      summary: { endpoints: 0, verified: 0, diverged: 0, unreachable: 0, not_checked: 0 },
      items: [],
    });
    renderConnectors();

    expect(await screen.findByRole("heading", { level: 2, name: "No destinations are configured" })).toBeInTheDocument();
    expect(screen.getByText("Add one before trstctl can install or rotate a credential on another system.", { exact: true })).toBeInTheDocument();
    expect(screen.queryByText(/all destinations are healthy/i)).not.toBeInTheDocument();
  });
});
