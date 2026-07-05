import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Connectors } from "@/pages/Connectors";
import { ToastProvider } from "@/components/ToastProvider";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    connectorCatalog: vi.fn(),
    connectorDeliveries: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
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

describe("SIMP-06 connector evidence de-fixturing", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.connectorCatalog.mockReset().mockResolvedValue({
      items: [
        {
          name: "signed-nginx-plugin",
          kind: "file/process",
          delivery_mode: "signed plugin",
          rollback: "receipt:rollback-nginx-2026-06-26",
        },
        {
          name: "aws-acm-importer",
          kind: "cloud",
          delivery_mode: "native registry",
          rollback: "receipt:rollback-acm-2026-06-26",
        },
      ],
    });
    apiMock.connectorDeliveries.mockReset().mockResolvedValue({
      items: [
        {
          id: "receipt-1",
          tenant_id: "tenant-1",
          identity_id: "identity-1",
          destination: "connector.deploy",
          connector: "signed-nginx-plugin",
          target: "edge-1",
          fingerprint: "sha256:served-receipt",
          status: "delivered",
          attempts: 1,
          reason: "",
          detail: "signed plugin accepted the delivery",
          rollback_ref: "receipt:rollback-nginx-2026-06-26",
          idempotency_key: "event-1",
          created_at: "2026-06-26T14:00:00Z",
          updated_at: "2026-06-26T14:00:00Z",
        },
      ],
    });
  });

  it("renders only served registry and receipt evidence", async () => {
    renderConnectors();

    expect(screen.getByRole("heading", { name: "Connector delivery evidence" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.connectorCatalog).toHaveBeenCalledTimes(1));
    expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 20 });

    expect((await screen.findAllByText("signed-nginx-plugin")).length).toBeGreaterThan(0);
    expect(screen.getByText("aws-acm-importer")).toBeInTheDocument();
    expect(screen.getByText("signed plugin")).toBeInTheDocument();
    expect(screen.getByText("native registry")).toBeInTheDocument();
    expect(screen.getByText("sha256:served-receipt")).toBeInTheDocument();
    expect(screen.getByText("edge-1")).toBeInTheDocument();
    expect(screen.getAllByText("receipt:rollback-nginx-2026-06-26").length).toBeGreaterThan(0);

    expect(screen.queryByRole("heading", { name: "Core deployment targets" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Appliance and network targets" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Outbox delivery posture" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/secret:\/\/connectors|dry-run|test-deploy|raw token hidden|F5 BIG-IP|NetScaler|FortiGate|Palo Alto/i);
    expect(screen.queryByRole("button", { name: /deploy|dry run|test deploy|rollback/i })).not.toBeInTheDocument();
  });

  it("removes connector target fixture catalogs from the module", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Connectors.tsx"), "utf8");
    expect(source).not.toMatch(/coreConnectors|applianceConnectors|outboxStates/);
    expect(source).not.toMatch(/secret:\/\/connectors|Core deployment targets|Appliance connector fixtures|Outbox delivery posture/i);
    expect(source).not.toMatch(/dry-run|test-deploy|raw token hidden|F5 BIG-IP|NetScaler|FortiGate|Palo Alto/i);
  });
});
