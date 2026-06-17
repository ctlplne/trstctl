// Code generated from the served OpenAPI contract by web/scripts/gen-api-types.mjs.
// DO NOT EDIT by hand. Regenerate with: npm run gen:api
//
// Source: internal/api/testdata/openapi.golden.json (pinned == the served spec by the
// Go test TestOpenAPIGolden). These types are the single FE↔BE contract for the trstctl
// console (SURFACE-005 / EXC-WIRE-04); web/src/lib/api.ts is type-checked against them so
// a backend field change that is not reflected here fails the build instead of silently
// desyncing the SPA.
// OpenAPI: 3.1.0  API: trstctl API v1

/* eslint-disable */
export interface AIAnswer {
  citations?: string[];
  grounded?: boolean;
  sufficient: boolean;
  text: string;
}

export interface AIQueryRequest {
  limit?: number;
  question?: string;
  subject?: string;
  surfaces: string[];
}

export interface Agent {
  id: string;
  last_seen_at?: string;
  name: string;
  status: string;
  version?: string;
}

export interface AgentList {
  agents: Agent[];
  next_cursor?: string;
}

export interface Approval {
  action: "issue" | "revoke";
  approvals: number;
  approver: string;
  resource: string;
}

export interface ApprovalRequest {
  action: "issue" | "revoke";
}

export interface AuditBundle {
  bundle: string;
  format: string;
}

export interface AuditEvent {
  actor?: Record<string, unknown>;
  data?: Record<string, unknown>;
  hash?: string;
  id?: string;
  sequence: number;
  tenant_id: string;
  time: string;
  type: string;
}

export interface AuditEventList {
  count?: number;
  events: AuditEvent[];
}

export interface Certificate {
  created_at?: string;
  deployment_location?: string;
  fingerprint: string;
  id: string;
  issuer?: string;
  key_algorithm?: string;
  not_after?: string;
  not_before?: string;
  owner_id?: string;
  revocation_reason?: string;
  revoked_at?: string;
  sans?: string[];
  serial?: string;
  source?: string;
  status: "active" | "superseded" | "revoked";
  subject: string;
  tenant_id: string;
}

export interface CertificateIngest {
  deployment_location?: string;
  owner_id?: string;
  pem: string;
  source?: string;
}

export interface CertificateList {
  items: Certificate[];
  next_cursor?: string;
}

export interface CredentialRisk {
  components: RiskComponents;
  credential_id: string;
  expires_at: string;
  exposure: number;
  kind: string;
  owner_active: boolean;
  privilege: number;
  score: number;
  sensitivity: number;
  subject: string;
}

export interface CredentialRiskList {
  credentials: CredentialRisk[];
}

export interface EnrollmentToken {
  enroll_path?: string;
  token: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  type: string;
}

export interface GraphImpact {
  affected: GraphNode[];
  by_kind: Record<string, unknown>;
  node: GraphNode;
}

export interface GraphNode {
  attrs?: Record<string, unknown>;
  id: string;
  kind: string;
  name: string;
}

export interface GraphQueryResult {
  rows: Record<string, unknown>[];
}

export interface GraphReachable {
  from: string;
  nodes: GraphNode[];
}

export interface GraphResponse {
  edges: GraphEdge[];
  nodes: GraphNode[];
}

export interface Identity {
  attributes?: Record<string, unknown>;
  created_at?: string;
  id: string;
  issuer_id?: string;
  kind: "x509_certificate" | "ssh_certificate" | "ssh_key" | "secret" | "api_key" | "workload_identity";
  name: string;
  not_after?: string;
  not_before?: string;
  owner_id: string;
  status: string;
  tenant_id?: string;
}

export interface IdentityList {
  items: Identity[];
  next_cursor?: string;
}

export interface IdentityRequest {
  attributes?: Record<string, unknown>;
  issuer_id?: string;
  kind: "x509_certificate" | "ssh_certificate" | "ssh_key" | "secret" | "api_key" | "workload_identity";
  name: string;
  owner_id: string;
}

export interface Issuer {
  chain?: string[];
  chainless?: boolean;
  created_at?: string;
  id: string;
  internal?: boolean;
  kind: "x509_ca" | "ssh_ca";
  name: string;
  public_key?: string;
  tenant_id?: string;
}

export interface IssuerList {
  items: Issuer[];
  next_cursor?: string;
}

export interface IssuerRequest {
  chain?: string[];
  internal?: boolean;
  kind: "x509_ca" | "ssh_ca";
  name: string;
  public_key?: string;
}

export interface MCPToolCall {
  subject?: string;
}

export interface MCPToolList {
  identity?: string;
  read_only: boolean;
  tools: string[];
}

export interface MCPToolResult {
  citations?: string[];
  text: string;
  tool: string;
}

export interface MachineLoginRequest {
  credential: string;
  method?: string;
}

export interface MachineLoginResponse {
  expires_at: string;
  method: string;
  principal: string;
  scopes: string[];
  session_id: string;
}

export interface Owner {
  created_at?: string;
  email?: string;
  id: string;
  kind: "user" | "team" | "workload" | "service";
  name: string;
  tenant_id: string;
}

export interface OwnerList {
  items: Owner[];
  next_cursor?: string;
}

export interface OwnerRequest {
  email?: string;
  kind: "user" | "team" | "workload" | "service";
  name: string;
}

export interface PKISecret {
  certificate: string;
  common_name?: string;
  private_key: string;
  serial: string;
}

export interface PKISecretRequest {
  common_name: string;
  ttl_seconds?: number;
}

export interface Problem {
  detail?: string;
  instance?: string;
  status?: number;
  title?: string;
  type?: string;
}

export interface Profile {
  active?: boolean;
  created_by?: string;
  id: string;
  name: string;
  spec?: Record<string, unknown>;
  version: number;
}

export interface ProfileList {
  items: Profile[];
  next_cursor?: string;
}

export interface ProfileRequest {
  name: string;
  spec: Record<string, unknown>;
}

export interface RCARequest {
  question: string;
  subject?: string;
}

export interface RiskComponents {
  age: number;
  exposure: number;
  owner: number;
  privilege: number;
  rotation: number;
  sensitivity: number;
}

export interface SecretMeta {
  created_at?: string;
  name: string;
  updated_at?: string;
  version: number;
}

export interface SecretMetaList {
  items: SecretMeta[];
  next_cursor?: string;
}

export interface SecretRequest {
  name: string;
  value: string;
}

export interface SecretValue {
  name: string;
  value: string;
  version?: number;
}

export interface ShareRedeemRequest {
  token: string;
}

export interface ShareRequest {
  ttl_seconds?: number;
  value: string;
}

export interface ShareToken {
  expires_at?: string;
  token: string;
}

export interface ShareValue {
  value: string;
}

export interface TransitionRequest {
  reason?: string;
  to: "issued" | "deployed" | "renewing" | "revoked" | "retired";
}
