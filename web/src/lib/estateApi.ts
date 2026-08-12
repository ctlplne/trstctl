import { mutate, req } from "./api";
import type {
  GraphImpact,
  GraphReachable,
  GraphTrustStores,
  MigrationAssessment,
  MigrationRun,
  MigrationRunActionRequest,
  MigrationRunList,
  MigrationRunStartRequest,
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
export const startMigrationRun = (request: MigrationRunStartRequest) => mutate<MigrationRun>("POST", "/api/v1/migrations/runs", request);

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
