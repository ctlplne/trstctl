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

export interface PCASDelegationScope {
  scope_id: string;
  parent_scope_id?: string;
  epoch_floor: number;
  updated_at: string;
  signer_confirmed: boolean;
  signer_receipt?: {
    operation_id: string;
    applied_floor: number;
    applied_parent_scope_id: string;
    public_key_der: string;
    signature: string;
  };
}

export interface PCASDelegationAccepted {
  request_id: string;
  scope_id: string;
  parent_scope_id?: string;
  epoch_floor: number;
  status: string;
  status_url: string;
}

export interface PCASRecoveryApprover {
  ID: string;
  PubDER: string;
}

export interface PCASRecoveryPolicy {
  identity_id: string;
  threshold: number;
  roster: PCASRecoveryApprover[];
  trust_root_der: string;
  updated_at: string;
}

export interface PCASRecoverySuccessor {
  identity_id: string;
  deployment_scope: string;
  epoch: number;
  algorithm: string;
  handle: string;
  public_key_der: string;
  request_id: string;
  signer_signature: string;
  event_id: string;
}

export interface PCASRecoveryRequest {
  identity_id: string;
  deployment_scope: string;
  target_algorithm: string;
  successor_handle: string;
  predecessor_epoch: number;
  epoch: number;
  predecessor_algorithm: string;
  predecessor_public_der: string;
  trust_root_der: string;
  authorization: Record<string, unknown>;
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
  delegationScopes: () => req<{ scopes: PCASDelegationScope[]; count: number }>("/api/v1/pcas/delegation/scopes"),
  configureDelegationScope: (body: { scope_id: string; parent_scope_id?: string; epoch_floor: number }) =>
    mutate<PCASDelegationAccepted>("POST", "/api/v1/pcas/delegation/scopes", body),
  raiseDelegationFloor: (body: { scope_id: string; epoch_floor: number }) => mutate<PCASDelegationAccepted>("POST", "/api/v1/pcas/delegation/floors", body),
  recoveryPolicy: (identityId: string) => req<PCASRecoveryPolicy>("/api/v1/pcas/recovery/policies?identity_id=" + encodeURIComponent(identityId)),
  configureRecoveryPolicy: (body: Pick<PCASRecoveryPolicy, "identity_id" | "threshold" | "roster" | "trust_root_der">) =>
    mutate<{ identity_id: string; status: string; updated_at: string }>("POST", "/api/v1/pcas/recovery/policies", body),
  prepareRecoverySuccessor: (body: { identity_id: string; deployment_scope: string; epoch: number; algorithm: string }) =>
    mutate<PCASAcceptedRequest>("POST", "/api/v1/pcas/recovery/successors/prepare", body),
  recoverySuccessor: (identityId: string, epoch: number) =>
    req<PCASRecoverySuccessor>("/api/v1/pcas/recovery/successors?identity_id=" + encodeURIComponent(identityId) + "&epoch=" + epoch),
  requestRecovery: (body: PCASRecoveryRequest) => mutate<PCASAcceptedRequest>("POST", "/api/v1/pcas/recovery/requests", body),
};
