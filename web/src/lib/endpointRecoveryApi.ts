import { mutate, req } from "./apiTransport";
import type { EndpointRecoveryCheck, EndpointRecoveryCheckRequest } from "./api-types.gen";

// Recovery checks of contained host targets: the replacement flow asks the
// target's enrolled host whether the listener containment stopped can come back.
// Split out of the main client by workflow, like the other operation modules.

/** Queue a read-only recovery check on the target's enrolled host. */
export const requestEndpointRecoveryCheck = (targetId: string, input: EndpointRecoveryCheckRequest, idempotencyKey?: string) =>
  mutate<EndpointRecoveryCheck>("POST", `/api/v1/connectors/targets/${encodeURIComponent(targetId)}/recovery-check`, input, idempotencyKey);

/** Read the target's latest recovery check and the host's signed answer. */
export const getEndpointRecoveryCheck = (targetId: string) =>
  req<EndpointRecoveryCheck>(`/api/v1/connectors/targets/${encodeURIComponent(targetId)}/recovery-check`);
