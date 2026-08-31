import type { BrokerAgentIdentityHistory, BrokerAgentIdentityHistoryList, BrokerAgentIdentityPreview } from "@/lib/api-types.gen";
import { attestedPreviewFixture } from "./attestedSVID";

export const brokerPreviewFixture: BrokerAgentIdentityPreview = {
  ...attestedPreviewFixture,
  capability: "agent_broker",
  agent_id: "agent-build-1",
  scopes: ["tool:inventory.read"],
  policy_evaluation: "execution_only",
  task_envelope_sha256: "",
  task_envelope_verification: "not_requested",
};
export const brokerHistoryFixture: BrokerAgentIdentityHistory = {
  certificate_id: "11111111-1111-1111-1111-111111111111",
  certificate_subject: "spiffe://example.test/agent/build-1",
  fingerprint: "a".repeat(64),
  serial: "01",
  recorded_at: "2026-08-31T12:00:00Z",
  generated_at: "2026-08-31T12:01:00Z",
  lifecycle_status: "active",
  state: "valid",
  state_reason: "The certificate is within its validity window.",
  not_before: "2026-08-31T12:00:00Z",
  not_after: "2026-08-31T12:10:00Z",
  metadata_state: "recorded",
  projection_state: "current",
  issuance: {
    agent_id: "agent-build-1",
    subject: "ns/default/sa/build",
    method: "k8s_sat",
    owner_id: "22222222-2222-2222-2222-222222222222",
    scopes: ["tool:inventory.read"],
    requested_ttl_seconds: 600,
    effective_ttl_seconds: 600,
  },
};
export function brokerHistoryPage(items: BrokerAgentIdentityHistory[] = [brokerHistoryFixture]): BrokerAgentIdentityHistoryList {
  return { items, next_cursor: "", history_scope: "broker_issued_certificates", generated_at: brokerHistoryFixture.generated_at, projection_state: "current" };
}
