import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { AuditFeedPanel } from "@/pages/audit/AuditFeedPanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    auditFeeds: vi.fn(),
    previewAuditFeed: vi.fn(),
    putAuditFeed: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const deliveredFeed = {
  id: "11111111-1111-4111-8111-111111111111",
  tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  name: "Security Splunk",
  provider: "splunk-hec" as const,
  endpoint_url: "https://splunk.example.test/services/collector/event",
  token_ref: "env:SPLUNK_HEC_TOKEN",
  interval_seconds: 300,
  batch_size: 100,
  enabled: true,
  allow_private_endpoint: false,
  private_egress_cidrs: [],
  status: "delivered" as const,
  last_batch_start_sequence: 91,
  last_queued_sequence: 100,
  last_delivered_sequence: 100,
  last_batch_record_count: 10,
  lag_records: 0,
  attempts: 1,
  collector_request_id: "splunk-req-52",
  next_run_at: "2026-08-13T06:10:00Z",
  updated_at: "2026-08-13T06:05:00Z",
};

const retryingFeed = {
  ...deliveredFeed,
  id: "22222222-2222-4222-8222-222222222222",
  name: "Sentinel SOC",
  provider: "sentinel" as const,
  endpoint_url: "https://sentinel.example.test/api/logs",
  token_ref: "env:SENTINEL_TOKEN",
  status: "retrying" as const,
  last_delivered_sequence: 90,
  lag_records: 10,
  attempts: 2,
  last_error_code: "collector_http_503",
  collector_request_id: "sentinel-req-52",
  next_attempt_at: "2026-08-13T06:06:00Z",
};

const preview = {
  capability: "audit_feed_configuration",
  ready: true,
  effect_free: true,
  feed_id: "33333333-3333-4333-8333-333333333333",
  endpoint_host: "collector.example.test",
  request_fingerprint: "sha256:f9-preview",
  required_permission: "audit:write",
  normalized_request: {
    name: "Production Splunk",
    provider: "splunk-hec" as const,
    endpoint_url: "https://collector.example.test/services/collector/event",
    token_ref: "env:PROD_SPLUNK_TOKEN",
    interval_seconds: 300,
    batch_size: 100,
    enabled: true,
    allow_private_endpoint: false,
    private_egress_cidrs: [],
  },
  prerequisites: ["Credential reference is allowlisted.", "Public destination uses HTTPS.", "Execution requires audit:write."],
  preview_writes: [],
  preview_external_effects: [],
  execution_writes: ["Append one tenant-scoped configuration event.", "Project the durable feed."],
  execution_external_effects: ["A later bounded outbox worker delivers exact batches to collector.example.test."],
  verification_steps: ["Read the configured feed.", "Follow the collector receipt."],
  recovery_steps: ["Failed batches retry without advancing the cursor.", "Disable the schedule to stop new batches."],
  warnings: [],
  guidance: "Preview performs no write and makes no network call.",
};

beforeEach(() => {
  apiMock.auditFeeds.mockReset().mockResolvedValue({ items: [deliveredFeed, retryingFeed] });
  apiMock.previewAuditFeed.mockReset().mockResolvedValue(preview);
  apiMock.putAuditFeed.mockReset().mockResolvedValue(deliveredFeed);
});

describe("AUD-52 scheduled audit collector feeds", () => {
  it("shows durable lag and receipt evidence, then saves only a credential reference", async () => {
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <AuditFeedPanel />
      </AppQueryProvider>,
    );

    expect(await screen.findByRole("heading", { name: "Scheduled collector feeds" })).toBeInTheDocument();
    expect(await screen.findByText("Security Splunk")).toBeInTheDocument();
    expect(screen.getByText("Sentinel SOC")).toBeInTheDocument();
    expect(screen.getByText("Retrying exact batch")).toBeInTheDocument();
    expect(screen.getByText("10 queued records")).toBeInTheDocument();
    expect(screen.getByText("collector_http_503")).toBeInTheDocument();
    expect(screen.getByText("sentinel-req-52")).toBeInTheDocument();
    expect(screen.queryByText("super-secret-token-value")).not.toBeInTheDocument();

    await user.clear(screen.getByLabelText("Feed ID"));
    await user.type(screen.getByLabelText("Feed ID"), "33333333-3333-4333-8333-333333333333");
    await user.type(screen.getByLabelText("Name"), "Production Splunk");
    await user.type(screen.getByLabelText("Collector endpoint URL"), "https://collector.example.test/services/collector/event");
    await user.type(screen.getByLabelText("Credential reference"), "env:PROD_SPLUNK_TOKEN");
    expect(screen.getByText("A failed batch retries automatically without advancing the delivered cursor.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save collector feed" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Review collector feed" }));

    const exactRequest = {
      name: "Production Splunk",
      provider: "splunk-hec",
      endpoint_url: "https://collector.example.test/services/collector/event",
      token_ref: "env:PROD_SPLUNK_TOKEN",
      interval_seconds: 300,
      batch_size: 100,
      enabled: true,
      allow_private_endpoint: false,
      private_egress_cidrs: [],
    };
    await waitFor(() => expect(apiMock.previewAuditFeed).toHaveBeenCalledWith("33333333-3333-4333-8333-333333333333", exactRequest));
    expect(await screen.findByRole("heading", { name: "Review collector feed" })).toBeInTheDocument();
    expect(screen.getByText("collector.example.test")).toBeInTheDocument();
    expect(screen.getByText("Preview performs no write and makes no network call.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save collector feed" })).toBeEnabled();

    await user.type(screen.getByLabelText("Name"), " changed");
    expect(screen.getByText("Configuration changed. Review it again before saving.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save collector feed" })).toBeDisabled();
    await user.clear(screen.getByLabelText("Name"));
    await user.type(screen.getByLabelText("Name"), "Production Splunk");
    await user.click(screen.getByRole("button", { name: "Review collector feed" }));
    await waitFor(() => expect(apiMock.previewAuditFeed).toHaveBeenCalledTimes(2));
    await user.click(screen.getByRole("button", { name: "Save collector feed" }));

    await waitFor(() => expect(apiMock.putAuditFeed).toHaveBeenCalledWith("33333333-3333-4333-8333-333333333333", exactRequest));
    expect(await screen.findByRole("status")).toHaveTextContent("Collector feed saved");
  });
});
