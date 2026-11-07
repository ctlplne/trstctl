import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Decorator, Meta, StoryObj } from "@storybook/react-vite";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { PAMWindowsLocalAccountScan } from "@/lib/api-types.gen";
import { ApiError } from "@/lib/apiTransport";
import { PAMWindowsLocalAccounts } from "./PAMWindowsLocalAccounts";
const host = "58600000-0000-4000-8000-000000000001";
const run = "58600000-0000-4000-8000-000000000002";
const observation: PAMWindowsLocalAccountScan = {
  id: run,
  intent: { run_id: run, tenant_id: "58600000-0000-4000-8000-000000000003", agent_id: host, binding_digest: "a".repeat(64) },
  status: "complete",
  delivery_status: "delivered",
  queued_at: "2026-11-07T00:00:00Z",
  queued_by: "inventory-operator",
  queued_event_id: run,
  report_digest: "b".repeat(64),
  signer_fingerprint: "c".repeat(64),
  report: {
    run_id: run,
    binding_digest: "a".repeat(64),
    observed_at: "2026-11-07T00:01:00Z",
    status: "complete",
    inventory: {
      machine: { name: "OWNED-WINDOWS", sid: "S-1-5-21-1-2-3", role: 3 },
      accounts: [{ name: "OwnedAdministrator", sid: "S-1-5-21-1-2-3-1001", enabled: true, locked: false, password_required: true }],
      external_members: 1,
      group_members: 2,
      deleted_members: 0,
    },
  },
};
const reader = {
  pamWindowsLocalAccountHosts: async () => ({ items: [{ id: host, name: "owned-windows", status: "active", last_seen_at: "2026-11-07T00:01:00Z" }] }),
  pamWindowsLocalAccountScans: async () => ({ items: [{ ...observation, report: undefined }] }),
  pamWindowsLocalAccountScan: async () => observation,
};
const WithQuery: Decorator = (Story) => {
  const [client] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: false } } }));
  const navigate = useNavigate();
  useEffect(() => {
    navigate("/?windows_host=" + host + "&windows_run=" + run);
  }, [navigate]);
  return (
    <QueryClientProvider client={client}>
      <div className="max-w-6xl">
        <Story />
      </div>
    </QueryClientProvider>
  );
};
const meta = {
  title: "Access/LocalAdministratorInventory",
  component: PAMWindowsLocalAccounts,
  decorators: [WithQuery],
  args: { canManage: false, reader },
} satisfies Meta<typeof PAMWindowsLocalAccounts>;
export default meta;
type Story = StoryObj<typeof meta>;
export const SignedInventory: Story = {};
export const EmptyCompletedInventory: Story = {
  args: {
    reader: {
      ...reader,
      pamWindowsLocalAccountScan: async () => ({
        ...observation,
        report: { ...observation.report!, inventory: { ...observation.report!.inventory!, accounts: [] } },
      }),
    },
  },
};
export const UnavailableNativeRead: Story = {
  args: {
    reader: {
      ...reader,
      pamWindowsLocalAccountScan: async () => ({
        ...observation,
        status: "failed",
        failure: "native_read_failed",
        report: { ...observation.report!, status: "unavailable", failure: "native_read_failed", inventory: undefined },
      }),
    },
  },
};
export const PermissionDenied: Story = {
  args: {
    reader: {
      ...reader,
      pamWindowsLocalAccountScan: async () => {
        throw new ApiError(403, "Owned fixture denies scan reads");
      },
    },
  },
};
