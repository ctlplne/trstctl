// PCAS is attached through a core-family OpenAPI seam. These shapes mirror
// internal/succession/api/openapi.pcas.json and keep its operator flow typed.
import { mutate, req } from "./apiTransport";

export interface PCASGenesisRequest {
  identity_id: string;
  algorithm: string;
  deployment_scope: string;
}

export interface PCASSuccessionRequest {
  identity_id: string;
  credential_type: string;
  target_algorithm: string;
  policy_ref: string;
  deployment_scope: string;
}

export interface PCASAcceptedRequest {
  request_id: string;
  status: string;
  status_url: string;
  identity_id: string;
}

export interface PCASRequestStatus {
  request_id: string;
  kind: string;
  status: string;
  attempts: number;
  created_at: string;
  delivered_at?: string;
}

export interface PCASGenesis {
  deployment_scope: string;
  identity_id: string;
  tenant_id: string;
  algorithm: string;
  public_key: string;
  epoch: number;
  trust_root_att: string;
}

export interface PCASChain {
  identity_id: string;
  genesis?: PCASGenesis;
  trust_root_public_der?: string;
  records: string[];
  count: number;
}

export interface PCASCheckpoint {
  identity_id: string;
  epoch: number;
  log_tree_size: number;
  log_root: string;
  signature: string;
  signer_public_der?: string;
  checkpoint: Record<string, unknown>;
  issued_at: string;
}

export interface PCASRetirementMember {
  relying_party: string;
  public_der: string;
}

export interface PCASRetirementPolicyRequest {
  identity_id: string;
  predecessor_epoch: number;
  threshold: number;
  roster: PCASRetirementMember[];
  validity_window_seconds: number;
  predecessor_handle?: string;
}

export interface PCASRetirementPolicy extends PCASRetirementPolicyRequest {
  status: string;
  updated_at: string;
  rewrap_complete: boolean;
}

export const pcasApi = {
  registerGenesis: (body: PCASGenesisRequest) => mutate<PCASAcceptedRequest>("POST", "/api/v1/pcas/genesis", body),
  requestSuccession: (body: PCASSuccessionRequest) => mutate<PCASAcceptedRequest>("POST", "/api/v1/pcas/successions", body),
  requestStatus: (requestId: string) => req<PCASRequestStatus>(`/api/v1/pcas/requests/${encodeURIComponent(requestId)}`),
  chain: (identityId: string) => req<PCASChain>(`/api/v1/pcas/chain?identity_id=${encodeURIComponent(identityId)}`),
  checkpoint: (identityId: string) => req<PCASCheckpoint>(`/api/v1/pcas/checkpoints?identity_id=${encodeURIComponent(identityId)}`),
  retirementStatus: (identityId: string, predecessorEpoch: number) =>
    req<PCASRetirementPolicy>(`/api/v1/pcas/retirement?identity_id=${encodeURIComponent(identityId)}&predecessor_epoch=${predecessorEpoch}`),
  configureRetirement: (body: PCASRetirementPolicyRequest) => mutate<PCASRetirementPolicy>("POST", "/api/v1/pcas/retirement/policies", body),
};
