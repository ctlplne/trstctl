import { createContext, useContext, type ReactNode } from "react";
import { bootstrapApi as api } from "@/lib/bootstrapApi";
import type { Api } from "@/lib/api";
import type { CapabilityRuntimeOperation, CapabilityUnavailableAction, CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";
import { canonicalCapabilityIDs, type CanonicalCapabilityID } from "@/lib/feature-contracts.gen";
import { useApiQuery, useHasAppQueryProvider } from "@/lib/query";
import { translateNow } from "@/i18n/I18nProvider";

export type CapabilitySurfaceState = "ready" | "limited" | "permission_blocked" | "unavailable" | "unknown";

export interface CapabilityStateCounts {
  ready: number;
  limited: number;
  permission_blocked: number;
  unavailable: number;
  unknown: number;
}

export interface CapabilitySurfaceSummary {
  state: CapabilitySurfaceState;
  items: CapabilityViewItem[];
  missingIds: CanonicalCapabilityID[];
  counts: CapabilityStateCounts;
  total: number;
}

export type CapabilityActionState = "allowed" | "scoped" | "denied" | "unavailable" | "unknown";

export interface CapabilityActionPosture {
  state: CapabilityActionState;
  capability: CapabilityViewItem | null;
  unavailable: CapabilityUnavailableAction | null;
}

export interface CapabilityExecutionPosture extends CapabilityActionPosture {
  /** False only in isolated workbenches/legacy tests where no runtime provider
   * exists. The real authenticated shell always enables enforcement. */
  enforced: boolean;
  checking: boolean;
  runnable: boolean;
}

export interface RuntimeOperationPosture {
  state: CapabilityActionState;
  operation: CapabilityRuntimeOperation | null;
  unavailable: CapabilityUnavailableAction | null;
}

export interface RuntimeOperationExecutionPosture extends RuntimeOperationPosture {
  enforced: boolean;
  checking: boolean;
  runnable: boolean;
}

interface CapabilityContextValue {
  view: CapabilityView | null;
  loading: boolean;
  error: boolean;
  enabled: boolean;
  refetch: () => void;
}

const idleCapabilityContext: CapabilityContextValue = {
  view: null,
  loading: false,
  error: false,
  enabled: false,
  refetch: () => undefined,
};

const CapabilityContext = createContext<CapabilityContextValue>(idleCapabilityContext);
const capabilityIdSet = new Set<string>(canonicalCapabilityIDs);
const runtimeStates = new Set(["catalog_only", "unavailable", "partially_available", "available"]);
const authorizationStates = new Set(["catalog_only", "none", "scoped", "partial", "full"]);
const dependencyStates = new Set(["none", "documented_not_runtime_verified"]);
const unavailableCodes = new Set(["not_attached", "not_implemented", "dependency_not_configured"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isCapabilityViewItem(value: unknown): value is CapabilityViewItem {
  if (!isRecord(value) || !capabilityIdSet.has(String(value.capability_id)) || !isRecord(value.actions)) return false;
  const actions = value.actions;
  return (
    runtimeStates.has(String(value.runtime_state)) &&
    authorizationStates.has(String(value.authorization_state)) &&
    dependencyStates.has(String(value.dependency_state)) &&
    isStringArray(actions.allowed) &&
    isStringArray(actions.scoped) &&
    isStringArray(actions.denied) &&
    Array.isArray(actions.unavailable) &&
    actions.unavailable.every(
      (action) => isRecord(action) && typeof action.operation_id === "string" && typeof action.detail === "string" && unavailableCodes.has(String(action.code)),
    ) &&
    Array.isArray(value.stages) &&
    value.stages.every((stage) => isRecord(stage) && typeof stage.name === "string" && typeof stage.completion === "string")
  );
}

function isCapabilityRuntimeOperation(value: unknown): value is CapabilityRuntimeOperation {
  if (!isRecord(value) || typeof value.operation_id !== "string") return false;
  if (!new Set(["allowed", "scoped", "denied", "unavailable"]).has(String(value.state))) return false;
  if (value.code !== undefined && !new Set(["not_implemented", "dependency_not_configured"]).has(String(value.code))) return false;
  if (value.detail !== undefined && typeof value.detail !== "string") return false;
  return value.state !== "unavailable" || (typeof value.code === "string" && typeof value.detail === "string");
}

/** Rejects malformed, partial, or stale capability projections before shell
 * chrome consumes them. A future contract must update the generated client and
 * this boundary together; an old browser never guesses from a new schema. */
export function isCapabilityView(value: unknown): value is CapabilityView {
  if (!isRecord(value) || value.schema_version !== 2 || value.contract_schema_version !== 3 || !Array.isArray(value.items) || !Array.isArray(value.operations))
    return false;
  if (!isRecord(value.license) || typeof value.enforcement_note !== "string") return false;
  if (!value.items.every(isCapabilityViewItem)) return false;
  if (!value.operations.every(isCapabilityRuntimeOperation)) return false;
  const ids = value.items.map((item) => item.capability_id);
  const operationIds = value.operations.map((operation) => operation.operation_id);
  return ids.length === new Set(ids).size && operationIds.length === new Set(operationIds).size;
}

function emptyCounts(): CapabilityStateCounts {
  return { ready: 0, limited: 0, permission_blocked: 0, unavailable: 0, unknown: 0 };
}

/** capabilitySurfaceState translates the server's separate attachment, RBAC,
 * and dependency facts into one display state. It never grants authority: the
 * server still re-checks every operation when it executes. */
export function capabilitySurfaceState(item: CapabilityViewItem): CapabilitySurfaceState {
  if (item.runtime_state === "unavailable" || item.runtime_state === "catalog_only") return "unavailable";
  if (item.authorization_state === "none") return "permission_blocked";
  if (
    item.runtime_state === "partially_available" ||
    item.authorization_state === "partial" ||
    item.authorization_state === "scoped" ||
    item.actions.unavailable.length > 0 ||
    item.actions.denied.length > 0
  ) {
    return "limited";
  }
  if (item.runtime_state === "available" && item.authorization_state === "full") return "ready";
  return "unknown";
}

/** summarizeCapabilities is the shared route/tool truth reducer. Missing rows
 * remain unknown instead of being treated as either allowed or absent. */
export function summarizeCapabilities(view: CapabilityView | null, capabilityIds: readonly CanonicalCapabilityID[]): CapabilitySurfaceSummary {
  const ids = Array.from(new Set(capabilityIds));
  const counts = emptyCounts();
  if (!isCapabilityView(view)) {
    counts.unknown = ids.length;
    return { state: "unknown", items: [], missingIds: ids, counts, total: ids.length };
  }

  const byId = new Map(view.items.map((item) => [item.capability_id, item]));
  const items: CapabilityViewItem[] = [];
  const missingIds: CanonicalCapabilityID[] = [];
  for (const id of ids) {
    const item = byId.get(id);
    if (!item) {
      missingIds.push(id);
      counts.unknown += 1;
      continue;
    }
    items.push(item);
    counts[capabilitySurfaceState(item)] += 1;
  }

  let state: CapabilitySurfaceState = "ready";
  if (counts.ready === ids.length) state = "ready";
  else if (counts.permission_blocked === ids.length) state = "permission_blocked";
  else if (counts.unavailable === ids.length) state = "unavailable";
  else if (counts.unknown === ids.length) state = "unknown";
  else state = "limited";
  return { state, items, missingIds, counts, total: ids.length };
}

/** resolveCapabilityAction is the reusable button/workflow preflight. Unknown
 * operation IDs fail visibly as unknown; they are never promoted to allowed.
 * This is explanatory UX only, not an authorization decision. */
export function resolveCapabilityAction(view: CapabilityView | null, capabilityId: CanonicalCapabilityID, operationId: string): CapabilityActionPosture {
  const capability = isCapabilityView(view) ? (view.items.find((item) => item.capability_id === capabilityId) ?? null) : null;
  if (!capability) return { state: "unknown", capability: null, unavailable: null };

  const unavailable = capability.actions.unavailable.find((action) => action.operation_id === operationId) ?? null;
  if (unavailable) return { state: "unavailable", capability, unavailable };
  if (capability.actions.denied.includes(operationId)) return { state: "denied", capability, unavailable: null };
  if (capability.actions.scoped.includes(operationId)) return { state: "scoped", capability, unavailable: null };
  if (capability.actions.allowed.includes(operationId)) return { state: "allowed", capability, unavailable: null };
  if (capability.runtime_state === "unavailable" || capability.runtime_state === "catalog_only") {
    return { state: "unavailable", capability, unavailable: null };
  }
  return { state: "unknown", capability, unavailable: null };
}

/** Exact process-level preflight for routes that cannot live in the core feature
 * catalog, including routes attached through the attach seams.
 * A valid registry that omits an operation proves it is not attached. */
export function resolveRuntimeOperation(view: CapabilityView | null, operationId: string): RuntimeOperationPosture {
  if (!isCapabilityView(view)) return { state: "unknown", operation: null, unavailable: null };
  const operation = view.operations.find((candidate) => candidate.operation_id === operationId) ?? null;
  if (!operation) {
    return {
      state: "unavailable",
      operation: null,
      unavailable: {
        operation_id: operationId,
        code: "not_attached",
        detail: translateNow("capabilities.reason.notAttached"),
      },
    };
  }
  if (operation.state === "unavailable") {
    return {
      state: "unavailable",
      operation,
      unavailable: {
        operation_id: operation.operation_id,
        code: operation.code ?? "not_implemented",
        detail: operation.detail ?? translateNow("capabilities.reason.unknown"),
      },
    };
  }
  return { state: operation.state, operation, unavailable: null };
}

export function capabilityLimitationReason(item: CapabilityViewItem): string | null {
  const unavailable = item.actions.unavailable[0];
  if (unavailable?.detail) return unavailable.detail;
  const incompleteStage = item.stages.find((stage) => stage.completion === "blocked" || stage.completion === "missing");
  return incompleteStage?.reason ?? null;
}

export function CapabilityProvider({ children, enabled = true }: { children: ReactNode; enabled?: boolean }) {
  const hasQueryProvider = useHasAppQueryProvider();
  const capabilityReader = (api as Partial<Api>).capabilities;
  if (!enabled || !hasQueryProvider || typeof capabilityReader !== "function") {
    return <CapabilityContext.Provider value={idleCapabilityContext}>{children}</CapabilityContext.Provider>;
  }
  return <LiveCapabilityProvider reader={capabilityReader.bind(api)}>{children}</LiveCapabilityProvider>;
}

/** Deterministic component-workbench provider. It exercises the same reducers
 * and UI as live data, but it is never accepted as served qualification proof. */
export function CapabilityFixtureProvider({
  children,
  view,
  loading = false,
  error = false,
}: {
  children: ReactNode;
  view: CapabilityView | null;
  loading?: boolean;
  error?: boolean;
}) {
  return <CapabilityContext.Provider value={{ view, loading, error, enabled: true, refetch: () => undefined }}>{children}</CapabilityContext.Provider>;
}

function LiveCapabilityProvider({ children, reader }: { children: ReactNode; reader: () => Promise<CapabilityView> }) {
  const query = useApiQuery(["runtime-capabilities"], reader, { live: { intervalMs: 60_000 } });
  const view = isCapabilityView(query.data) ? query.data : null;
  const value: CapabilityContextValue = {
    view,
    loading: query.loading,
    error: query.error !== null || (query.data !== null && view === null),
    enabled: true,
    refetch: query.refetch,
  };
  return <CapabilityContext.Provider value={value}>{children}</CapabilityContext.Provider>;
}

export function useCapabilities(): CapabilityContextValue {
  return useContext(CapabilityContext);
}

export function useCapabilityAction(capabilityId: CanonicalCapabilityID, operationId: string): CapabilityActionPosture {
  return resolveCapabilityAction(useCapabilities().view, capabilityId, operationId);
}

export function useCapabilityExecution(capabilityId: CanonicalCapabilityID, operationId: string): CapabilityExecutionPosture {
  const context = useCapabilities();
  const posture = resolveCapabilityAction(context.view, capabilityId, operationId);
  const checking = context.enabled && context.loading;
  return {
    ...posture,
    enforced: context.enabled,
    checking,
    runnable: !context.enabled || (!checking && (posture.state === "allowed" || posture.state === "scoped")),
  };
}

export function useRuntimeOperationExecution(operationId: string): RuntimeOperationExecutionPosture {
  const context = useCapabilities();
  const posture = resolveRuntimeOperation(context.view, operationId);
  const checking = context.enabled && context.loading;
  return {
    ...posture,
    enforced: context.enabled,
    checking,
    runnable: !context.enabled || (!checking && (posture.state === "allowed" || posture.state === "scoped")),
  };
}
