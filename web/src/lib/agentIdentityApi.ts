import { mutate } from "./apiTransport";
import type { BrokerAgentIdentityRevokeRequest, BulkRevokeResult } from "./api";

// Q4: revoke one AI agent's broker identity in one call. The server runs the
// same exact certificate revocation as the revocation center, for this one
// broker certificate, so OCSP, the CRL and the agent key set all follow.
export const revokeBrokerAgentIdentity = (id: string, input: BrokerAgentIdentityRevokeRequest, idempotencyKey?: string) =>
  mutate<BulkRevokeResult>("POST", `/api/v1/broker/agent-identities/${encodeURIComponent(id)}/revoke`, input, idempotencyKey);
