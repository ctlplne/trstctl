import { mutate, req } from "./apiTransport";
import type {
  SecretScopedSync,
  SecretScopedSyncApplyRequest,
  SecretScopedSyncList,
  SecretScopedSyncModeRequest,
  SecretScopedSyncReceipt,
  SecretScopedSyncRequest,
} from "./api";

// A237: scoped secret sync. A definition keeps every secret under a source
// prefix in step with a KV v2 destination. Reads never return values; the
// preview is a read-only POST (api.ts) and apply takes the plan's digest.

export const listSecretScopedSyncs = () => req<SecretScopedSyncList>("/api/v1/secrets/scoped-syncs");

export const getSecretScopedSync = (id: string) => req<SecretScopedSync>(`/api/v1/secrets/scoped-syncs/${encodeURIComponent(id)}`);

export const defineSecretScopedSync = (input: SecretScopedSyncRequest, idempotencyKey?: string) =>
  mutate<SecretScopedSync>("POST", "/api/v1/secrets/scoped-syncs", input, idempotencyKey);

// A237-L3: replace a definition in place; moving the destination releases the
// keys it managed there, which stay.
export const replaceSecretScopedSync = (id: string, input: SecretScopedSyncRequest, idempotencyKey?: string) =>
  mutate<SecretScopedSync>("PUT", `/api/v1/secrets/scoped-syncs/${encodeURIComponent(id)}`, input, idempotencyKey);

export const setSecretScopedSyncMode = (id: string, input: SecretScopedSyncModeRequest, idempotencyKey?: string) =>
  mutate<SecretScopedSync>("PUT", `/api/v1/secrets/scoped-syncs/${encodeURIComponent(id)}/mode`, input, idempotencyKey);

export const applySecretScopedSync = (id: string, input: SecretScopedSyncApplyRequest, idempotencyKey?: string) =>
  mutate<SecretScopedSyncReceipt>("POST", `/api/v1/secrets/scoped-syncs/${encodeURIComponent(id)}/apply`, input, idempotencyKey);
