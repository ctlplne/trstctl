import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { AppQueryProvider } from "@/lib/query";
import { EndpointContainment } from "@/pages/connectors/EndpointContainment";
import type { DeploymentTarget } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    previewEndpointContainment: vi.fn(),
    containEndpoint: vi.fn(),
    connectorDelivery: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

const target: DeploymentTarget = {
  id: "target-1",
  tenant_id: "tenant-1",
  name: "local Apache",
  connector: "apache",
  config: {},
  created_at: "2026-10-05T00:00:00Z",
  enabled: false,
};
const plan = {
  capability: "host_endpoint_containment",
  ready: true,
  effect_free: true,
  target_id: target.id,
  target_name: target.name,
  target_revision: "revision-1",
  connector: "apache",
  target_enabled: false,
  identity_id: "identity-1",
  identity_name: "compromised.example.test",
  identity_status: "revoked",
  certificate_status: "revoked",
  expected_fingerprint: "a".repeat(64),
  required_agent_id: "agent-1",
  preview_fingerprint: "b".repeat(64),
  required_permission: "connectors:write",
  execution_effects: [],
  verification_steps: [],
  warnings: ["The destination is disabled but may still serve TLS."],
};
const queued = {
  id: "receipt-1",
  tenant_id: "tenant-1",
  outbox_id: 42,
  identity_id: "identity-1",
  destination: "endpoint.contain",
  connector: "apache",
  target: target.name,
  fingerprint: "a".repeat(64),
  status: "containment_queued",
  attempts: 0,
  created_at: "2026-10-05T00:00:00Z",
  updated_at: "2026-10-05T00:00:00Z",
};

beforeEach(() => {
  Object.values(apiMock).forEach((mock) => mock.mockReset());
  apiMock.previewEndpointContainment.mockResolvedValue(plan);
  apiMock.containEndpoint.mockResolvedValue(queued);
  apiMock.connectorDelivery.mockResolvedValue({ ...queued, status: "containment_stopped", detail: '{"report":{"state":"stopped"}}' });
});

it("reviews and executes exact containment on a disabled host target, then reads the signed result", async () => {
  const user = userEvent.setup();
  render(
    <AppQueryProvider>
      <EndpointContainment target={target} reason="key compromise" />
    </AppQueryProvider>,
  );
  await user.click(screen.getByRole("button", { name: "Review host containment" }));
  expect(await screen.findByText("The destination is disabled but may still serve TLS.")).toBeInTheDocument();
  expect(screen.getByText("a".repeat(64))).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Queue exact host stop" }));
  await waitFor(() =>
    expect(apiMock.containEndpoint).toHaveBeenCalledWith(
      target.id,
      {
        target_revision: plan.target_revision,
        identity_id: plan.identity_id,
        expected_fingerprint: plan.expected_fingerprint,
        required_agent_id: plan.required_agent_id,
        preview_fingerprint: plan.preview_fingerprint,
        reason: "key compromise",
      },
      expect.any(String),
    ),
  );
  expect(await screen.findByRole("heading", { name: "Host agent stopped TLS on the pinned listener" })).toBeInTheDocument();
  expect(apiMock.connectorDelivery).toHaveBeenCalledWith(queued.id);
});

it("refuses to queue when the server preview is not ready", async () => {
  apiMock.previewEndpointContainment.mockResolvedValue({ ...plan, ready: false });
  const user = userEvent.setup();
  render(
    <AppQueryProvider>
      <EndpointContainment target={target} reason="key compromise" />
    </AppQueryProvider>,
  );
  await user.click(screen.getByRole("button", { name: "Review host containment" }));
  expect(await screen.findByText(plan.identity_name)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Queue exact host stop" })).not.toBeInTheDocument();
  expect(apiMock.containEndpoint).not.toHaveBeenCalled();
});

it("requires the existing connector action reason before an emergency stop", async () => {
  const user = userEvent.setup();
  render(
    <AppQueryProvider>
      <EndpointContainment target={target} reason="" />
    </AppQueryProvider>,
  );
  await user.click(screen.getByRole("button", { name: "Review host containment" }));
  expect(await screen.findByRole("button", { name: "Queue exact host stop" })).toBeDisabled();
  expect(apiMock.containEndpoint).not.toHaveBeenCalled();
});
