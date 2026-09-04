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
    createConnectorTarget: vi.fn(),
    createEndpointBinding: vi.fn(),
    bindIdentityConnectorTarget: vi.fn(),
    testConnectorTarget: vi.fn(),
    deployConnectorTarget: vi.fn(),
    rollbackConnectorTarget: vi.fn(),
    connectorDeliveries: vi.fn(),
    outboxCircuits: vi.fn(),
    endpointVerifications: vi.fn(),
    endpointKeyCustody: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
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

describe("connector deployment disclosure surface", () => {
  beforeEach(() => {
    apiMock.connectorCatalog.mockReset().mockResolvedValue({
      items: [
        {
          name: "nginx",
          kind: "file/process",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "receipt:rollback-nginx-2026-06-26",
          executes_rollback: true,
        },
        {
          name: "f5",
          kind: "appliance",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "restore previous Client SSL profile binding",
        },
        {
          name: "netscaler",
          kind: "appliance",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "bind previous certKey to the service group",
        },
        {
          name: "a10",
          kind: "appliance",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "restore previous client-SSL template certificate/key binding",
        },
        {
          name: "kemp",
          kind: "appliance",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "rebind virtual service to previous certificate object",
        },
        {
          name: "postgresql",
          kind: "database",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "restore previous server certificate/key files",
        },
        {
          name: "mysql",
          kind: "database",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "restore previous server certificate/key files",
        },
        {
          name: "rabbitmq",
          kind: "messaging",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "restore previous broker certificate/key files",
        },
        {
          name: "elasticsearch",
          kind: "search",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "restore previous watched HTTP TLS files",
        },
        {
          name: "tomcat",
          kind: "application-server",
          delivery_mode: "native registry, signed plugin, or receipt",
          rollback: "restore previous connector certificate/key files",
        },
      ],
      relay_plugins: [
        {
          agent_id: "11111111-1111-1111-1111-111111111111",
          agent_name: "relay-plant-7",
          agent_status: "active",
          reported_at: "2026-08-12T18:30:00Z",
          signer_fingerprint: `sha256:${"b".repeat(64)}`,
          signature_verified: true,
          metadata_only: true,
          plugins: [
            {
              name: "partner-f5",
              digest: `sha256:${"a".repeat(64)}`,
              publisher: `sha256:${"c".repeat(64)}`,
              execution_context: "network_relay_wasm",
              grants: [{ capability: "net.dial", constraints: ["appliance.internal:443"] }],
            },
          ],
        },
      ],
    });
    apiMock.connectorTargets.mockReset().mockResolvedValue({
      items: [
        {
          id: "target-1",
          tenant_id: "tenant-1",
          name: "edge/prod/payments",
          connector: "nginx",
          config: { credential_ref: "secret://connectors/nginx" },
          enabled: true,
          created_at: "2026-06-20T00:00:00Z",
        },
      ],
    });
    apiMock.identities.mockReset().mockResolvedValue([
      {
        id: "identity-1",
        tenant_id: "tenant-1",
        name: "payments.example.test",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "issued",
        attributes: {},
        created_at: "2026-06-20T00:00:00Z",
      },
    ]);
    apiMock.createConnectorTarget.mockReset().mockResolvedValue({
      id: "target-created",
      tenant_id: "tenant-1",
      name: "edge/prod/payments",
      connector: "nginx",
      config: {},
      enabled: false,
      created_at: "2026-06-20T00:00:00Z",
    });
    apiMock.createEndpointBinding.mockReset().mockResolvedValue({
      identity: { id: "identity-bound", status: "issued" },
      target: { id: "target-created", name: "edge/prod/payments", connector: "nginx" },
      queued_lifecycle_intents: ["ca.issue", "connector.deploy"],
      renewal_intent: "ca.renew",
    });
    apiMock.bindIdentityConnectorTarget.mockReset().mockResolvedValue({ id: "identity-1", status: "issued" });
    apiMock.testConnectorTarget.mockReset().mockResolvedValue({
      id: "preview-1",
      destination: "connector.test",
      connector: "nginx",
      target: "edge/prod/payments",
      status: "dry_run_planned",
      detail: "a real deploy would proceed. It would: replace the certificate files; reload nginx",
      idempotency_key: "connector-test:target-1:preview-1",
    });
    apiMock.deployConnectorTarget.mockReset().mockResolvedValue({ id: "identity-1", status: "deployed" });
    apiMock.rollbackConnectorTarget.mockReset().mockResolvedValue({
      id: "rollback-1",
      destination: "connector.rollback",
      connector: "nginx",
      target: "edge/prod/payments",
      status: "rollback_queued",
      detail: "the host agent will restore the encrypted predecessor bundle and verify the listener",
    });
    apiMock.connectorDeliveries.mockReset().mockResolvedValue({
      items: [
        {
          id: "receipt-1",
          tenant_id: "tenant-1",
          identity_id: "identity-1",
          destination: "connector.deploy",
          connector: "nginx",
          target: "edge/prod/payments",
          fingerprint: "sha256:served-receipt",
          status: "delivered",
          attempts: 1,
          reason: "",
          detail: "signed plugin accepted the delivery",
          rollback_ref: "receipt:rollback-nginx-2026-06-26",
          idempotency_key: "event-1",
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:00:00Z",
        },
      ],
    });
    apiMock.outboxCircuits.mockReset().mockResolvedValue({ items: [] });
    apiMock.endpointKeyCustody.mockReset().mockResolvedValue({ items: [], summary: { host_generated: 0, targets: 0, migrated_percent: 0 } });
    apiMock.endpointVerifications.mockReset().mockResolvedValue({
      guidance: "",
      summary: { endpoints: 1, verified: 1, diverged: 0, unreachable: 0, not_checked: 0 },
      items: [
        {
          endpoint_id: "target-1",
          address: "edge-1.internal:443",
          vantage: "local",
          status: "verified",
          checked_sans: true,
          checked_chain: true,
          agent_common_name: "host-agent-edge-1",
          detail: "listener serves the deployed certificate",
          last_checked_at: "2026-06-20T00:01:00Z",
        },
      ],
    });
  });

  it("renders connector registry and receipt evidence from served data only", async () => {
    const user = userEvent.setup();
    renderConnectors();

    expect(await screen.findByRole("heading", { name: "Where credentials are installed" })).toBeInTheDocument();
    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    expect(await screen.findByRole("heading", { name: "Configured destinations" })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Target"), "target-1");
    await user.click(screen.getByText("Connector capabilities and plugin evidence", { exact: true }));
    expect(await screen.findByRole("heading", { name: "Connector registry" })).toBeInTheDocument();
    await user.click(screen.getByText("Health, retries, and rollback", { exact: true }));
    expect(await screen.findByRole("heading", { name: "Recent delivery receipts" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.connectorCatalog).toHaveBeenCalled());
    expect(apiMock.connectorTargets).toHaveBeenCalled();
    expect(apiMock.identities).toHaveBeenCalled();
    expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 20 });
    expect(screen.getAllByText("nginx").length).toBeGreaterThan(0);
    expect(screen.getAllByText("a10").length).toBeGreaterThan(0);
    expect(screen.getAllByText("kemp").length).toBeGreaterThan(0);
    expect(screen.getAllByText("postgresql").length).toBeGreaterThan(0);
    expect(screen.getAllByText("rabbitmq").length).toBeGreaterThan(0);
    expect(screen.getAllByText("edge/prod/payments").length).toBeGreaterThan(0);
    expect(screen.getAllByText("native registry, signed plugin, or receipt").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Verified relay plugins" })).toBeInTheDocument();
    expect(screen.getByText("partner-f5")).toBeInTheDocument();
    expect(screen.getByText("relay-plant-7")).toBeInTheDocument();
    expect(screen.getByText("network_relay_wasm")).toBeInTheDocument();
    expect(screen.getByText("net.dial")).toBeInTheDocument();
    expect(screen.getByText("appliance.internal:443")).toBeInTheDocument();
    expect(screen.getByText("Signed by the relay certificate")).toBeInTheDocument();
    expect(screen.getByText("Metadata only")).toBeInTheDocument();
    expect(screen.getAllByText("delivered").length).toBeGreaterThan(0);
    expect(screen.getByText("sha256:served-receipt")).toBeInTheDocument();
    expect(screen.getAllByText(/connector\.deploy/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("receipt:rollback-nginx-2026-06-26").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Deploy" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review restore" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Bind and enroll" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Credential activity timeline" })).toBeInTheDocument();
    expect(screen.getByTestId("selected-target-timeline")).toHaveTextContent("connector.deploy");
    expect(screen.getByTestId("selected-target-timeline")).toHaveTextContent("endpoint.verify");
    expect(screen.getByTestId("selected-target-timeline")).toHaveTextContent("host-agent-edge-1");
    expect(document.body.textContent).not.toMatch(/BEGIN .* PRIVATE KEY|raw token hidden/i);
    expect(screen.queryByText(/BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("keeps destination identifiers readable inside the mobile scroll region", async () => {
    const user = userEvent.setup();
    renderConnectors();

    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    const table = await screen.findByRole("table", { name: "Configured deployment destinations" });
    const identifierCell = within(table).getByText("target-1");

    expect(identifierCell).toHaveClass("whitespace-nowrap");
    expect(identifierCell).not.toHaveClass("break-all");
  });

  it("keeps the connector route usable when an older API returns null plugin arrays", async () => {
    apiMock.connectorCatalog.mockResolvedValueOnce({
      items: [],
      relay_plugins: [
        {
          agent_id: "22222222-2222-2222-2222-222222222222",
          agent_name: "relay-with-empty-census",
          agent_status: "active",
          reported_at: "2026-08-12T18:30:00Z",
          signer_fingerprint: `sha256:${"d".repeat(64)}`,
          signature_verified: true,
          metadata_only: true,
          plugins: null,
        },
        {
          agent_id: "33333333-3333-3333-3333-333333333333",
          agent_name: "relay-with-unrestricted-plugin",
          agent_status: "active",
          reported_at: "2026-08-12T18:31:00Z",
          signer_fingerprint: `sha256:${"e".repeat(64)}`,
          signature_verified: true,
          metadata_only: true,
          plugins: [
            {
              name: "partner-nginx",
              digest: `sha256:${"f".repeat(64)}`,
              publisher: `sha256:${"a".repeat(64)}`,
              execution_context: "network_relay_wasm",
              grants: [{ capability: "fs.write", constraints: null }],
            },
          ],
        },
      ],
    });

    const user = userEvent.setup();
    renderConnectors();

    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByText("Connector capabilities and plugin evidence", { exact: true }));
    expect(await screen.findByText("relay-with-empty-census")).toBeInTheDocument();
    expect(screen.getByText("No loaded plugins")).toBeInTheDocument();
    expect(screen.getByText("relay-with-unrestricted-plugin")).toBeInTheDocument();
    expect(screen.getByText("partner-nginx")).toBeInTheDocument();
    expect(screen.getByText("Unrestricted")).toBeInTheDocument();
  });

  it("renders all three E1 dispositions instead of hiding the unimplemented denominator", async () => {
    apiMock.connectorCatalog.mockResolvedValueOnce({
      items: [
        {
          name: "a10",
          kind: "appliance",
          delivery_mode: "native",
          rollback: "re-bind",
          relay_parity: {
            disposition: "migrated",
            met: [],
            missing: [],
            outstanding: [],
            relay_migrated: true,
            detail: "all gates proven",
          },
        },
        {
          name: "cisco",
          kind: "appliance",
          delivery_mode: "native",
          rollback: "unsupported",
          relay_parity: {
            disposition: "architecture_exception",
            met: [],
            missing: ["rollback", "readback"],
            outstanding: [],
            relay_migrated: false,
            cp_retained: true,
            scope_note: "device API has no addressable installed object; E1 remains open",
            detail: "open exception",
          },
        },
        {
          name: "aws-acm",
          kind: "cloud",
          delivery_mode: "native",
          rollback: "unsupported",
          relay_parity: {
            disposition: "unimplemented",
            met: ["support_matrix"],
            missing: ["relay_execution_proof", "cp_path_refusal"],
            outstanding: [],
            relay_migrated: false,
            scope_note: "execution remains in the control plane",
            detail: "not migrated",
          },
        },
      ],
    });

    const user = userEvent.setup();
    renderConnectors();

    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByText("Connector capabilities and plugin evidence", { exact: true }));
    expect(await screen.findByText("Relay-executed")).toBeInTheDocument();
    expect(screen.getByText("Open architecture exception")).toBeInTheDocument();
    expect(screen.getByText("Network-relay migration unimplemented")).toBeInTheDocument();
    expect(screen.getByText("device API has no addressable installed object; E1 remains open")).toBeInTheDocument();
    expect(screen.getByText("execution remains in the control plane")).toBeInTheDocument();
  });

  it("creates and operates a served connector target", async () => {
    const user = userEvent.setup();
    renderConnectors();

    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByRole("button", { name: "Add destination" }));
    const dialog = screen.getByRole("dialog", { name: "Add destination" });
    await user.click(within(dialog).getByRole("button", { name: "Add destination" }));
    await waitFor(() =>
      expect(apiMock.createConnectorTarget).toHaveBeenCalledWith({
        name: "edge/prod/payments",
        connector: "nginx",
        config: { credential_ref: "connector-credential-ref", host: "edge-1.internal" },
        enabled: false,
      }),
    );

    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    await screen.findByRole("heading", { name: "Configured destinations" });
    await user.selectOptions(screen.getByLabelText("Target"), "target-1");
    await user.selectOptions(screen.getByLabelText("Identity"), "identity-1");
    await user.type(screen.getByLabelText("Reason"), "verified design-partner endpoint");
    await user.type(screen.getByLabelText("Owner ID"), "owner-1");
    await user.click(screen.getByRole("button", { name: "Bind and enroll" }));
    await waitFor(() =>
      expect(apiMock.createEndpointBinding).toHaveBeenCalledWith({
        owner_id: "owner-1",
        identity_name: "payments.example.test",
        reason: "verified design-partner endpoint",
        target_id: "target-1",
      }),
    );

    // Refreshes deliberately clear selections whose IDs are not present in the
    // served collection. Reconfirm the destination and identity before the next
    // lifecycle action; the product must never guess these safety-critical inputs.
    await user.selectOptions(screen.getByLabelText("Target"), "target-1");
    await user.selectOptions(screen.getByLabelText("Identity"), "identity-1");

    await user.click(screen.getByRole("button", { name: "Bind" }));
    await waitFor(() => expect(apiMock.bindIdentityConnectorTarget).toHaveBeenCalledWith("identity-1", { target_id: "target-1" }));

    await user.click(screen.getByRole("button", { name: "Preview changes (no writes)" }));
    await waitFor(() => expect(apiMock.testConnectorTarget).toHaveBeenCalledWith("target-1"));
    expect(await screen.findByRole("heading", { name: "Target path ready — no changes made" })).toBeInTheDocument();
    expect(screen.getByText("a real deploy would proceed. It would: replace the certificate files; reload nginx")).toBeInTheDocument();
    expect(screen.getByText("Preview never installs a certificate, writes a target file, runs a reload, or changes a binding.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Deploy" }));
    await waitFor(() =>
      expect(apiMock.deployConnectorTarget).toHaveBeenCalledWith("target-1", {
        identity_id: "identity-1",
        reason: "verified design-partner endpoint",
      }),
    );

    await user.click(screen.getByRole("button", { name: "Review restore" }));
    expect(apiMock.rollbackConnectorTarget).not.toHaveBeenCalled();
    const restoreDialog = screen.getByRole("dialog", { name: "Review restore of the previous version" });
    expect(restoreDialog).toHaveTextContent("edge/prod/payments");
    expect(restoreDialog).toHaveTextContent("payments.example.test");
    expect(restoreDialog).toHaveTextContent("verified design-partner endpoint");
    await user.click(within(restoreDialog).getByRole("button", { name: "Queue restore" }));
    await waitFor(() => expect(apiMock.rollbackConnectorTarget).toHaveBeenCalledWith("target-1", expect.objectContaining({ identity_id: "identity-1" })));
    expect(await screen.findByRole("heading", { name: "Restore queued — waiting for agent proof" })).toBeInTheDocument();
    expect(screen.getByText("the host agent will restore the encrypted predecessor bundle and verify the listener")).toBeInTheDocument();
  });

  it("does not turn a local schema check into target-readiness proof", async () => {
    apiMock.testConnectorTarget.mockResolvedValue({
      id: "preview-local-only",
      destination: "connector.test",
      connector: "nginx",
      target: "edge/prod/payments",
      status: "config_validated",
      detail: "connector target metadata and credential references validated locally; the target was not contacted",
    });
    const user = userEvent.setup();
    renderConnectors();
    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    await screen.findByRole("heading", { name: "Configured destinations" });
    await user.selectOptions(screen.getByLabelText("Target"), "target-1");
    await user.click(screen.getByRole("button", { name: "Preview changes (no writes)" }));

    expect(await screen.findByRole("heading", { name: "Configuration valid — target not contacted" })).toBeInTheDocument();
    expect(screen.getByText(/Do not treat this as permission to deploy/i)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /Ready to deploy/i })).not.toBeInTheDocument();
  });

  it("refreshes an asynchronous preview by its exact receipt chain", async () => {
    apiMock.testConnectorTarget.mockResolvedValue({
      id: "preview-queued",
      destination: "connector.test",
      connector: "nginx",
      target: "edge/prod/payments",
      status: "dry_run_queued",
      detail: "a dry-run was queued for the host agent",
      idempotency_key: "connector-test:target-1:preview-queued",
    });
    apiMock.connectorDeliveries.mockResolvedValueOnce({
      items: [
        {
          id: "preview-result",
          destination: "connector.test",
          connector: "nginx",
          target: "edge/prod/payments",
          status: "dry_run_blocked",
          detail: "endpoint: connection refused",
          idempotency_key: "connector-test:target-1:preview-queued:result",
        },
      ],
    });
    const user = userEvent.setup();
    renderConnectors();
    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    await screen.findByRole("heading", { name: "Configured destinations" });
    await user.selectOptions(screen.getByLabelText("Target"), "target-1");
    await user.click(screen.getByRole("button", { name: "Preview changes (no writes)" }));

    expect(await screen.findByRole("heading", { name: "Preview queued — no result yet" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check preview result" }));
    expect(await screen.findByRole("heading", { name: "Deploy blocked — no changes made" })).toBeInTheDocument();
    expect(screen.getAllByText("endpoint: connection refused").length).toBeGreaterThan(0);
  });

  it("refuses to guess an asynchronous result when the preview has no receipt key", async () => {
    apiMock.testConnectorTarget.mockResolvedValue({
      id: "preview-queued-without-key",
      destination: "connector.test",
      connector: "nginx",
      target: "edge/prod/payments",
      status: "dry_run_queued",
      detail: "a dry-run was queued for the host agent",
    });
    apiMock.connectorDeliveries.mockResolvedValueOnce({
      items: [
        {
          id: "stale-result",
          destination: "connector.test",
          connector: "nginx",
          target: "edge/prod/payments",
          status: "dry_run_planned",
          detail: "an older preview was ready",
          idempotency_key: "connector-test:target-1:older:result",
        },
      ],
    });
    const user = userEvent.setup();
    renderConnectors();
    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    await screen.findByRole("heading", { name: "Configured destinations" });
    await user.selectOptions(screen.getByLabelText("Target"), "target-1");
    await user.click(screen.getByRole("button", { name: "Preview changes (no writes)" }));

    expect(await screen.findByRole("heading", { name: "Preview queued — no result yet" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check preview result" })).not.toBeInTheDocument();
    expect(screen.getByText(/console will not guess which result belongs to it/i)).toBeInTheDocument();
    expect(apiMock.connectorDeliveries).not.toHaveBeenCalled();
  });

  it("keeps prepared destinations inert until an operator explicitly enables them", async () => {
    apiMock.connectorTargets.mockResolvedValue({
      items: [
        {
          id: "target-prepared",
          tenant_id: "tenant-1",
          name: "Apache payments web tier (prepared, not contacted)",
          connector: "apache",
          config: { proof_state: "prepared_not_contacted" },
          enabled: false,
          created_at: "2026-06-20T00:00:00Z",
        },
      ],
    });
    apiMock.identities.mockResolvedValue([
      {
        id: "identity-iis",
        tenant_id: "tenant-1",
        name: "iis-portal.demo.trstctl.local",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "issued",
        attributes: { intended_connector: "iis" },
        created_at: "2026-06-20T00:00:00Z",
      },
    ]);

    const user = userEvent.setup();
    renderConnectors();
    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    await screen.findByRole("heading", { name: "Configured destinations" });

    expect(screen.getByText("Disabled — prepared only")).toBeInTheDocument();
    expect(screen.getByLabelText("Target")).toHaveValue("");
    expect(screen.getByLabelText("Identity")).toHaveValue("");

    await user.selectOptions(screen.getByLabelText("Target"), "target-prepared");
    await user.selectOptions(screen.getByLabelText("Identity"), "identity-iis");
    expect(
      screen.getByText("This destination is disabled. Enable it only after its agent or relay and endpoint have been verified. Nothing will be queued."),
    ).toBeInTheDocument();
    for (const name of ["Bind", "Preview changes (no writes)", "Deploy", "Review restore"]) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
    }
    expect(apiMock.bindIdentityConnectorTarget).not.toHaveBeenCalled();
    expect(apiMock.testConnectorTarget).not.toHaveBeenCalled();
    expect(apiMock.deployConnectorTarget).not.toHaveBeenCalled();
    expect(apiMock.rollbackConnectorTarget).not.toHaveBeenCalled();
  });

  it("refuses a connector-mismatched identity while still allowing a safe target test", async () => {
    apiMock.connectorTargets.mockResolvedValue({
      items: [
        {
          id: "target-apache",
          tenant_id: "tenant-1",
          name: "Verified Apache destination",
          connector: "apache",
          config: {},
          enabled: true,
          created_at: "2026-06-20T00:00:00Z",
        },
      ],
    });
    apiMock.identities.mockResolvedValue([
      {
        id: "identity-iis",
        tenant_id: "tenant-1",
        name: "iis-portal.demo.trstctl.local",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "issued",
        attributes: { intended_connector: "iis" },
        created_at: "2026-06-20T00:00:00Z",
      },
    ]);

    const user = userEvent.setup();
    renderConnectors();
    await screen.findByRole("heading", { name: "Where credentials are installed" });
    await user.click(screen.getByText("Destinations and safe actions", { exact: true }));
    await screen.findByRole("heading", { name: "Configured destinations" });
    await user.selectOptions(screen.getByLabelText("Target"), "target-apache");
    await user.selectOptions(screen.getByLabelText("Identity"), "identity-iis");
    await user.type(screen.getByLabelText("Reason"), "verified endpoint change");

    expect(screen.getByText("This identity is intended for iis, but the selected destination uses apache. Choose a matching identity.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Bind" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Deploy" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Review restore" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Preview changes (no writes)" })).toBeEnabled();
  });
});
