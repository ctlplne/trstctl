import { mutate, req } from "./apiTransport";
import type { CloudMachineChange, CloudMachineChangeList, CloudMachineChangeRequest } from "./api-types.gen";

export const cloudChangesKey = (findingID: string) => ["cloud-machine-changes", findingID] as const;
export const listCloudMachineChanges = (findingID: string, signal?: AbortSignal) =>
  req<CloudMachineChangeList>(`/api/v1/cloud-entitlements/changes?finding_id=${encodeURIComponent(findingID)}&limit=200`, { signal });
export const proposeCloudMachineChange = (input: CloudMachineChangeRequest, key: string) =>
  mutate<CloudMachineChange>("POST", "/api/v1/cloud-entitlements/changes", input, key);
export const executeCloudMachineChange = (id: string, key: string) =>
  mutate<CloudMachineChange>("POST", `/api/v1/cloud-entitlements/changes/${encodeURIComponent(id)}/execute`, undefined, key);

export const getCloudMachineChange = (id: string, signal?: AbortSignal) =>
  req<CloudMachineChange>(`/api/v1/cloud-entitlements/changes/${encodeURIComponent(id)}`, { signal });
