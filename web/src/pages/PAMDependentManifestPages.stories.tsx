import { useState } from "react";
import type { Decorator, Meta, StoryObj } from "@storybook/react-vite";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { PAMServiceDependentReviewPage, PAMServiceDependentRotationIntent } from "@/lib/api-types.gen";
import { PAMDependentManifestPages } from "./PAMDependentManifestPages";

const id = "58200000-0000-4000-8000-000000000001";
const header = "a".repeat(64),
  tail = "b".repeat(64),
  digest = "d".repeat(64);
const expires = "2099-01-01T00:00:00Z";
const account = {
  account_id: "58200000-0000-4000-8000-000000000002",
  dn: "CN=svc-payments,OU=Services,DC=example,DC=test",
  guid: "e".repeat(32),
  name: "svc-payments",
  provider_id: "owned-ad-profile",
  sid: "S-1-5-21-1-2-3-1001",
};
const host = {
  binding: { account, agent_id: "58200000-0000-4000-8000-000000000003", revision: 7, enabled: true },
  inventory_run_id: "58200000-0000-4000-8000-000000000004",
  inventory_digest: "f".repeat(64),
  observed_at: "2026-11-07T06:00:00Z",
};
const intent: PAMServiceDependentRotationIntent = {
  expected_version: 7,
  provider_binding: header,
  probes: [],
  plan: {
    version: 2,
    id,
    account,
    secret_name: "ad/payments",
    digest: "c".repeat(64),
    created_at: "2026-11-07T06:01:00Z",
    expires_at: expires,
    hosts: [],
    order: [],
    manifest: {
      version: 1,
      id,
      header_digest: header,
      digest: "c".repeat(64),
      tail_digest: tail,
      page_count: 1,
      entry_count: 1,
      host_count: 1,
      expires_at: expires,
    },
  },
};
const page: PAMServiceDependentReviewPage = {
  version: 1,
  id,
  header_digest: header,
  previous_digest: header,
  page_number: 0,
  digest: tail,
  hosts: [host],
  entries: [{ host, ref: { agent_id: host.binding.agent_id, family: "services", name: "PaymentsWorker" }, probe_id: "payments-health" }],
};
const WithQuery: Decorator = (Story) => {
  const [client] = useState(() => new QueryClient());
  return (
    <QueryClientProvider client={client}>
      <div className="max-w-3xl">
        <Story />
      </div>
    </QueryClientProvider>
  );
};
const meta = {
  title: "Access/NativeDependentReview",
  component: PAMDependentManifestPages,
  decorators: [WithQuery],
  args: { intent, digest, readPage: async () => page },
} satisfies Meta<typeof PAMDependentManifestPages>;
export default meta;
type Story = StoryObj<typeof meta>;
export const CompletePage: Story = {};
export const ApproverPage: Story = { args: { access: "approver" } };
export const UnavailablePage: Story = {
  args: {
    readPage: async () => {
      throw new Error("Owned story page unavailable");
    },
  },
};
export const ExpiredReview: Story = {
  args: {
    intent: {
      ...intent,
      plan: { ...intent.plan, expires_at: "2000-01-01T00:00:00Z", manifest: { ...intent.plan.manifest!, expires_at: "2000-01-01T00:00:00Z" } },
    },
  },
};
