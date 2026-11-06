import { z } from "zod";
import { mutate, req } from "./apiTransport";
import type {
  CloudMachineChange,
  CloudMachineChangeList,
  CloudMachineChangeRequest,
  DiscoveryFindingList,
  DynamicSecretProviderCatalog,
} from "./api-types.gen";

export const cloudChangesKey = (findingID: string) => ["cloud-machine-changes", findingID] as const;
export const listCloudMachineChanges = (findingID: string, signal?: AbortSignal) =>
  req<CloudMachineChangeList>(`/api/v1/cloud-entitlements/changes?finding_id=${encodeURIComponent(findingID)}&limit=200`, { signal });
export const proposeCloudMachineChange = (input: CloudMachineChangeRequest, key: string) =>
  mutate<CloudMachineChange>("POST", "/api/v1/cloud-entitlements/changes", input, key);
export const executeCloudMachineChange = (id: string, key: string) =>
  mutate<CloudMachineChange>("POST", `/api/v1/cloud-entitlements/changes/${encodeURIComponent(id)}/execute`, undefined, key);

export const getCloudMachineChange = (id: string, signal?: AbortSignal) =>
  req<CloudMachineChange>(`/api/v1/cloud-entitlements/changes/${encodeURIComponent(id)}`, { signal });

const nativeRoleEvidence = z.object({
  source_origin: z.string().min(1),
  collected_at: z.string(),
  identity: z.object({ native_id: z.string().min(1), principal: z.object({ arn: z.string().regex(/^arn:aws(?:-cn|-us-gov)?:iam::[0-9]{12}:role\//) }) }),
});

export async function loadCloudReplacementChoices(signal?: AbortSignal) {
  const catalog = await req<DynamicSecretProviderCatalog>("/api/v1/secrets/leases/providers", { signal });
  const roles = new Map<string, { id: string; arn: string; collectedAt: string }>();
  let cursor = "";
  for (let page = 0; page < 10; page++) {
    const query = new URLSearchParams({
      kind: "cloud_machine_entitlement",
      source_kind: "cloud_machine_entitlement",
      limit: "200",
      ...(cursor ? { cursor } : {}),
    });
    const findings = await req<DiscoveryFindingList>(`/api/v1/discovery/findings?${query}`, { signal });
    for (const finding of findings.items) {
      const parsed = nativeRoleEvidence.safeParse(finding.metadata);
      if (!parsed.success) continue;
      const entry = { id: finding.id, arn: parsed.data.identity.principal.arn, collectedAt: parsed.data.collected_at };
      if (!roles.has(entry.arn) || entry.collectedAt > (roles.get(entry.arn)?.collectedAt ?? "")) roles.set(entry.arn, entry);
    }
    cursor = findings.next_cursor ?? "";
    if (!cursor) break;
  }
  if (cursor) throw new Error("cloud_replacement_catalog_limit");
  return { providers: catalog.configured_providers.filter((p) => p.type === "aws-sts" && p.ready && p.maximum_ttl_seconds >= 900), roles: [...roles.values()] };
}
