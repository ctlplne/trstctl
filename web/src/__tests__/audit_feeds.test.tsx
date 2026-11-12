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

  // P5-L2: a syslog feed names the client certificate it presents to a
  // receiver that requires mutual TLS; no other collector offers the field.
  it("saves a syslog feed with a client certificate for mutual TLS", async () => {
    const user = userEvent.setup();
    const syslogRequest = {
      name: "rsyslog SOC",
      provider: "syslog",
      endpoint_url: "syslog+tls://rsyslog.example.test:6514",
      token_ref: "env:SYSLOG_CA",
      interval_seconds: 300,
      batch_size: 100,
      enabled: true,
      allow_private_endpoint: false,
      private_egress_cidrs: [],
      client_cert_ref: "env:SYSLOG_CLIENT",
    };
    apiMock.previewAuditFeed.mockResolvedValue({ ...preview, endpoint_host: "rsyslog.example.test", normalized_request: syslogRequest });
    render(
      <AppQueryProvider>
        <AuditFeedPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByText("Security Splunk")).toBeInTheDocument();
    expect(screen.queryByLabelText("Client certificate reference")).not.toBeInTheDocument();
    await user.clear(screen.getByLabelText("Feed ID"));
    await user.type(screen.getByLabelText("Feed ID"), "55555555-5555-4555-8555-555555555555");
    await user.type(screen.getByLabelText("Name"), "rsyslog SOC");
    await user.selectOptions(screen.getByLabelText("Collector"), "syslog");
    await user.type(screen.getByLabelText("Collector endpoint URL"), "syslog+tls://rsyslog.example.test:6514");
    await user.type(screen.getByLabelText("Credential reference"), "env:SYSLOG_CA");
    await user.type(screen.getByLabelText("Client certificate reference"), "env:SYSLOG_CLIENT");
    await user.click(screen.getByRole("button", { name: "Review collector feed" }));
    await waitFor(() => expect(apiMock.previewAuditFeed).toHaveBeenCalledWith("55555555-5555-4555-8555-555555555555", syslogRequest));
    expect(await screen.findByText("Client certificate")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save collector feed" }));
    await waitFor(() => expect(apiMock.putAuditFeed).toHaveBeenCalledWith("55555555-5555-4555-8555-555555555555", syslogRequest));
  });

  // P5-L4: an Elasticsearch feed chooses how its credential is presented; no
  // other collector offers the choice.
  it("saves an Elasticsearch feed with basic authentication", async () => {
    const user = userEvent.setup();
    const elasticRequest = {
      name: "Elastic SOC",
      provider: "elastic",
      endpoint_url: "https://elastic.example.test/trstctl-audit/_bulk",
      token_ref: "env:ELASTIC_WRITER",
      interval_seconds: 300,
      batch_size: 100,
      enabled: true,
      allow_private_endpoint: false,
      private_egress_cidrs: [],
      auth_scheme: "basic",
    };
    apiMock.previewAuditFeed.mockResolvedValue({ ...preview, endpoint_host: "elastic.example.test", normalized_request: elasticRequest });
    render(
      <AppQueryProvider>
        <AuditFeedPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByText("Security Splunk")).toBeInTheDocument();
    expect(screen.queryByLabelText("Elasticsearch authentication")).not.toBeInTheDocument();
    await user.clear(screen.getByLabelText("Feed ID"));
    await user.type(screen.getByLabelText("Feed ID"), "44444444-4444-4444-8444-444444444444");
    await user.type(screen.getByLabelText("Name"), "Elastic SOC");
    await user.selectOptions(screen.getByLabelText("Collector"), "elastic");
    await user.type(screen.getByLabelText("Collector endpoint URL"), "https://elastic.example.test/trstctl-audit/_bulk");
    await user.type(screen.getByLabelText("Credential reference"), "env:ELASTIC_WRITER");
    const scheme = screen.getByLabelText("Elasticsearch authentication");
    expect(scheme).toHaveValue("api_key");
    await user.selectOptions(scheme, "basic");
    await user.click(screen.getByRole("button", { name: "Review collector feed" }));
    await waitFor(() => expect(apiMock.previewAuditFeed).toHaveBeenCalledWith("44444444-4444-4444-8444-444444444444", elasticRequest));
    expect(await screen.findByText("Authentication")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save collector feed" }));
    await waitFor(() => expect(apiMock.putAuditFeed).toHaveBeenCalledWith("44444444-4444-4444-8444-444444444444", elasticRequest));
  });
});
