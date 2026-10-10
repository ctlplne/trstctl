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

export const pcasApi = {
  registerGenesis: (body: PCASGenesisRequest) => mutate<PCASAcceptedRequest>("POST", "/api/v1/pcas/genesis", body),
  requestSuccession: (body: PCASSuccessionRequest) => mutate<PCASAcceptedRequest>("POST", "/api/v1/pcas/successions", body),
  requestStatus: (requestId: string) => req<PCASRequestStatus>(`/api/v1/pcas/requests/${encodeURIComponent(requestId)}`),
  chain: (identityId: string) => req<PCASChain>(`/api/v1/pcas/chain?identity_id=${encodeURIComponent(identityId)}`),
};
