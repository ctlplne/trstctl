import { mutate, req } from "./apiTransport";
import type {
  GraphImpact,
  GraphReachable,
  GraphTrustStores,
  MigrationAssessment,
  MigrationRun,
  MigrationRunActionRequest,
  MigrationRunList,
  MigrationRunStartPending,
  MigrationRunStartRequest,
  CARetirementReceipt,
  CARetirementRequest,
  CARetirementRetryReceipt,
  CARetirementRetryRequest,
  CAKeyDependentReleaseRequest,
  CAKeyDependentReleaseReceipt,
  CAReprotectionSelection,
  CAReprotectionPlan,
  CAReprotectionPreview,
  CAReprotectionStartReceipt,
  RetirementChecklist,
  UnownedQueue,
} from "./api";

// Estate-shape reads: trust, migration, ownership and retirement (H1/H2/H4/I1).
//
// Split out of the main client because these four answer one class of question —
// what does the estate look like, and what is blocking a change to it — and
// because the served-file budget is a real guard against one module accreting
// every operation the product has. The split is by workflow, not by size.

/** Reachability from a node — what a credential can reach. */
export const graphReachable = (id: string) => req<GraphReachable>(`/api/v1/graph/reachable/${encodeURIComponent(id)}`);

/** Blast radius — what breaks if a node is compromised. */
export const graphBlastRadius = (id: string) => req<GraphImpact>(`/api/v1/graph/blast-radius/${encodeURIComponent(id)}`);

/** H1: which discovered trust stores carry a CA's anchor, and where they sit. */
export const graphTrustStores = (id: string) => req<GraphTrustStores>(`/api/v1/graph/trust-stores/${encodeURIComponent(id)}`);

/** H2: read-only assessment of a migration plan. Mutates nothing. */
export const assessMigration = (request: unknown) =>
  req<MigrationAssessment>("/api/v1/migrations/assess", {
    method: "POST",
    body: JSON.stringify(request),
    headers: { "Content-Type": "application/json" },
  });

/** H2: start one durable trust-before-leaf run. */
export const startMigrationRun = (request: MigrationRunStartRequest) =>
  mutate<MigrationRun | MigrationRunStartPending>("POST", "/api/v1/migrations/runs", request);

/** H2: tenant-scoped executable runs and their retained gates. */
export const migrationRuns = () => req<MigrationRunList>("/api/v1/migrations/runs");
export const migrationRun = (id: string) => req<MigrationRun>(`/api/v1/migrations/runs/${encodeURIComponent(id)}`);

/** H2: operator controls never skip the aggregate's current gate. */
export const pauseMigrationRun = (id: string, request?: MigrationRunActionRequest) =>
  mutate<MigrationRun>("POST", `/api/v1/migrations/runs/${encodeURIComponent(id)}/pause`, request);
export const resumeMigrationRun = (id: string) => mutate<MigrationRun>("POST", `/api/v1/migrations/runs/${encodeURIComponent(id)}/resume`);
export const rollbackMigrationRun = (id: string, request?: MigrationRunActionRequest) =>
  mutate<MigrationRun>("POST", `/api/v1/migrations/runs/${encodeURIComponent(id)}/rollback`, request);

/** I1: managed identities whose ownership cannot answer an incident question. */
export const unownedIdentities = () => req<UnownedQueue>("/api/v1/owners/unowned");

/** H4: what blocks a CA key's destruction, and the record once it does not. */
export const caRetirementChecklist = (keyId: string) => req<RetirementChecklist>(`/api/v1/ca/keys/${encodeURIComponent(keyId)}/retirement`);

/** H4: record one exact irreversible command; the outbox owns signer I/O. */
export const retireCAKey = (keyId: string, request: CARetirementRequest) =>
  mutate<CARetirementReceipt>("POST", `/api/v1/ca/keys/${encodeURIComponent(keyId)}/retirement`, request);

/** H4: one audited attempt on the same failed outbox row and frozen signer command. */
export const retryCAKeyRetirement = (keyId: string, request: CARetirementRetryRequest) =>
  mutate<CARetirementRetryReceipt>("POST", `/api/v1/ca/keys/${encodeURIComponent(keyId)}/retirement/retry`, request);

/** H4: source-bound, two-custodian disposition of one expired requester-held leaf. */
export const releaseCAKeyDependent = (keyId: string, request: CAKeyDependentReleaseRequest) =>
  mutate<CAKeyDependentReleaseReceipt>("POST", `/api/v1/ca/keys/${encodeURIComponent(keyId)}/dependencies/release`, request);

/** Review only: the server derives the bound host, key, CA, route and probe. */
export const previewCAKeyReprotectionPlan = (keyId: string, input: CAReprotectionSelection) =>
  req<CAReprotectionPreview>(`/api/v1/ca/keys/${encodeURIComponent(keyId)}/reprotect/plans/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });

/** Persist the exact public selection after the operator reviews the preview. */
export const registerCAKeyReprotectionPlan = (keyId: string, input: CAReprotectionSelection) =>
  mutate<CAReprotectionPlan>("POST", `/api/v1/ca/keys/${encodeURIComponent(keyId)}/reprotect/plans`, input);

export const caKeyReprotectionPlan = (keyId: string, jobId: string) =>
  req<CAReprotectionPlan>(`/api/v1/ca/keys/${encodeURIComponent(keyId)}/reprotect/plans/${encodeURIComponent(jobId)}`);

export const startCAKeyReprotection = (keyId: string) => mutate<CAReprotectionStartReceipt>("POST", `/api/v1/ca/keys/${encodeURIComponent(keyId)}/reprotect`);
