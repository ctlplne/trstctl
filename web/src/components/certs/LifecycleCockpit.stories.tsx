import type { Meta, StoryObj } from "@storybook/react-vite";
import { MemoryRouter } from "react-router-dom";
import { LifecycleCockpit } from "@/components/certs/LifecycleCockpit";

const now = Date.now();
const isoDays = (days: number) => new Date(now + days * 86_400_000).toISOString();

const meta = {
  title: "Certificate Lifecycle/Lifecycle cockpit",
  component: LifecycleCockpit,
  decorators: [
    (Story) => (
      <MemoryRouter>
        <Story />
      </MemoryRouter>
    ),
  ],
  parameters: { a11y: { test: "error" }, layout: "padded" },
  args: {
    certificates: [
      {
        id: "cert-checkout",
        tenant_id: "storybook",
        subject: "CN=checkout.prod.example",
        issuer: "CN=Production CA",
        status: "active",
        fingerprint: "fp-checkout",
        not_after: isoDays(-1),
        deployment_location: "production / ingress / checkout",
      },
      {
        id: "cert-api",
        tenant_id: "storybook",
        subject: "CN=api.prod.example",
        issuer: "CN=Production CA",
        status: "active",
        fingerprint: "fp-api",
        not_after: isoDays(5),
        owner_id: "team-platform",
        deployment_location: "production / load balancer / api",
      },
    ],
    health: {
      generated_at: new Date(now).toISOString(),
      inventory_path: "/certificates",
      expiring_path: "/certificates?expiry=30d",
      expiring: [],
      expiry_buckets: [],
      source_breakdown: [],
      summary: {
        total: 2,
        active: 2,
        expired: 1,
        expiring_7d: 2,
        expiring_30d: 2,
        expiring_90d: 2,
        revoked: 0,
        superseded: 0,
        external_source_count: 0,
        imported_count: 0,
        discovered_count: 0,
        unknown_expiry_count: 0,
        health: "critical",
      },
    },
    owners: [
      {
        id: "team-platform",
        tenant_id: "storybook",
        kind: "team",
        name: "Platform Trust",
        email: "platform@example.test",
        escalation_chain: ["oncall@example.test"],
        ownership_attested: true,
        ownership_complete: true,
        ownership_current: true,
      },
    ],
    identities: [{ id: "identity-api", kind: "x509_certificate", name: "api.prod.example", owner_id: "team-platform", status: "active" }],
    rotationRuns: [
      {
        id: "rotation-failed",
        tenant_id: "storybook",
        identity_id: "identity-api",
        predecessor_fingerprint: "fp-api",
        status: "failed",
        trigger: "scheduled",
        error: "upstream CA timed out",
        created_at: new Date(now - 3_600_000).toISOString(),
        updated_at: new Date(now - 3_300_000).toISOString(),
      },
    ],
    deliveries: [],
    notifications: [
      {
        id: "alert-dead",
        tenant_id: "storybook",
        certificate_id: "cert-checkout",
        destination: "payments-oncall@example.test",
        status: "dead",
        attempts: 4,
        created_at: new Date(now - 7_200_000).toISOString(),
      },
    ],
    channels: [{ id: "email", label: "Email", category: "email", delivery: "outbox", configured: true, enabled: true }],
    routingPolicies: [
      {
        id: "urgent-certificates",
        tenant_id: "storybook",
        name: "Urgent certificates",
        scope_kind: "workspace",
        default_channels: ["email"],
        channels_by_severity: { critical: ["email"] },
        digest_interval_seconds: 0,
        digest_timezone: "UTC",
        digest_preview: { interval_seconds: 0, next_run_at: new Date(now).toISOString(), timezone: "UTC" },
        created_at: new Date(now).toISOString(),
        updated_at: new Date(now).toISOString(),
      },
    ],
  },
} satisfies Meta<typeof LifecycleCockpit>;

export default meta;
type Story = StoryObj<typeof meta>;

export const UrgentWork: Story = {};

export const RefreshingServerTotals: Story = { args: { healthRefreshing: true } };

export const ExpiryTotalsUnavailable: Story = { args: { healthUnavailable: true } };

export const EvidenceUnavailable: Story = {
  args: {
    owners: null,
    identities: null,
    rotationRuns: null,
    deliveries: null,
    notifications: null,
    channels: null,
    routingPolicies: null,
  },
};
