import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { NhiInventory } from "@/components/nhi";
import type { Identity, CredentialRisk, NHIInventory as NHIInventoryResponse } from "@/lib/api";

const identities = [
  { id: "i1", name: "payments-worker", kind: "workload_identity", owner_id: "team-pay", status: "issued" },
  { id: "i2", name: "ci-runner", kind: "agent", status: "issued" },
] as unknown as Identity[];
const risks = [{ credential_id: "i1", score: 82 }] as unknown as CredentialRisk[];
const servedInventory = {
  generated_at: "2026-06-28T12:00:00Z",
  coverage: ["certificate", "service_account", "api_key", "oauth_app", "token", "personal_access_token", "secret", "iam_role", "ssh_key", "webhook", "workload_identity"],
  summary: {
    certificate: 1,
    service_account: 1,
    api_key: 1,
    oauth_app: 1,
    token: 1,
    secret: 1,
    iam_role: 1,
    ssh_key: 1,
    webhook: 1,
    workload_identity: 1,
  },
  items: [
    { id: "cert/1", tenant_id: "t1", kind: "certificate", source: "certificate_inventory", display_name: "CN=api", status: "active", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "sa/1", tenant_id: "t1", kind: "service_account", source: "discovery_finding", display_name: "svc-payments", status: "unmanaged", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "key/1", tenant_id: "t1", kind: "api_key", source: "discovery_finding", display_name: "payments-key", status: "unmanaged", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "oauth/1", tenant_id: "t1", kind: "oauth_app", source: "discovery_finding", display_name: "payments-oauth", status: "unmanaged", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "tok/1", tenant_id: "t1", kind: "token", source: "access_api_token", display_name: "ci-pat", status: "active", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "sec/1", tenant_id: "t1", kind: "secret", source: "discovery_finding", display_name: "db-secret", status: "unmanaged", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "role/1", tenant_id: "t1", kind: "iam_role", source: "discovery_finding", display_name: "payments-role", status: "unmanaged", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "ssh/1", tenant_id: "t1", kind: "ssh_key", source: "discovery_finding", display_name: "deploy-key", status: "unmanaged", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "hook/1", tenant_id: "t1", kind: "webhook", source: "discovery_finding", display_name: "payments-webhook", status: "unmanaged", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
    { id: "wid/1", tenant_id: "t1", kind: "workload_identity", source: "discovery_finding", display_name: "payments-workload", status: "unmanaged", metadata: {}, created_at: "2026-06-28T12:00:00Z" },
  ],
} as NHIInventoryResponse;

describe("U3-1 unified NHI inventory", () => {
  it("summarizes machine identities by type with a risk lens", () => {
    render(<NhiInventory identities={identities} inventory={servedInventory} risks={risks} />);
    expect(screen.getByText("Total identities")).toBeInTheDocument();
    expect(screen.getByText("Certificate")).toBeInTheDocument();
    expect(screen.getByText("Service account")).toBeInTheDocument();
    expect(screen.getByText("API key")).toBeInTheDocument();
    expect(screen.getByText("OAuth app")).toBeInTheDocument();
    expect(screen.getByText("Token")).toBeInTheDocument();
    expect(screen.getByText("Secret")).toBeInTheDocument();
    expect(screen.getByText("IAM role")).toBeInTheDocument();
    expect(screen.getByText("SSH key")).toBeInTheDocument();
    expect(screen.getByText("Webhook")).toBeInTheDocument();
    expect(screen.getByText("Workload identity")).toBeInTheDocument();
    expect(screen.getByText("High risk")).toBeInTheDocument();
  });
});
