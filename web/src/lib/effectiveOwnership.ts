import type { ContextualRiskPriority, OwnershipAttribution } from "@/lib/api";

export type EffectiveOwner = { state: "named"; name: string } | { state: "present" } | { state: "missing" } | { state: "unknown" };

type RiskOwnerSubject = Pick<ContextualRiskPriority, "credential_id" | "subject" | "owner_active">;

function normalizedKey(value: string | undefined): string {
  return value?.trim().toLocaleLowerCase() ?? "";
}

/** Risk and ownership are separate projections. A later asset-level ownership
 * assignment can therefore be newer than the risk row. Join their exact stable
 * id, reference, or displayed subject before showing accountability; never let
 * a stale risk boolean overwrite the current ownership authority. */
export function effectiveOwnerForRisk(
  risk: RiskOwnerSubject,
  attribution: OwnershipAttribution | null | undefined,
  attributionUnavailable: boolean,
): EffectiveOwner {
  if (attributionUnavailable || !attribution) return { state: "unknown" };

  const riskKeys = new Set([normalizedKey(risk.credential_id), normalizedKey(risk.subject)].filter(Boolean));
  const match = attribution.items.find((item) => [item.id, item.ref, item.display_name].some((candidate) => riskKeys.has(normalizedKey(candidate))));

  if (match) {
    if (match.attribution_status === "attributed" && match.owner?.name.trim()) return { state: "named", name: match.owner.name.trim() };
    if (match.attribution_status === "attributed") return { state: "present" };
    return { state: "missing" };
  }

  return risk.owner_active ? { state: "present" } : { state: "missing" };
}
