import { mutate, req } from "./apiTransport";
import type { SecretMigration, SecretMigrationList, SecretMigrationRequest } from "./api";

// A243: a migration run. Assess and stage carry the export's values (the
// request is the export); every answer is value-free. Staging, cutover,
// reissue and rollback are mutations bound to their idempotency keys.

export const listSecretMigrations = () => req<SecretMigrationList>("/api/v1/secrets/migrations");

export const getSecretMigration = (id: string) => req<SecretMigration>(`/api/v1/secrets/migrations/${encodeURIComponent(id)}`);

export const assessSecretMigration = (input: SecretMigrationRequest, idempotencyKey?: string) =>
  mutate<SecretMigration>("POST", "/api/v1/secrets/migrations/assess", input, idempotencyKey);

export const stageSecretMigration = (id: string, input: SecretMigrationRequest, idempotencyKey?: string) =>
  mutate<SecretMigration>("POST", `/api/v1/secrets/migrations/${encodeURIComponent(id)}/stage`, input, idempotencyKey);

export const applySecretMigrationPermissions = (id: string, idempotencyKey?: string) =>
  mutate<SecretMigration>("POST", `/api/v1/secrets/migrations/${encodeURIComponent(id)}/permissions`, undefined, idempotencyKey);

export const cutOverSecretMigration = (id: string, noConsumers: boolean, idempotencyKey?: string) =>
  mutate<SecretMigration>("POST", `/api/v1/secrets/migrations/${encodeURIComponent(id)}/cutover`, { no_consumers: noConsumers }, idempotencyKey);

export const reissueSecretMigrationCredentials = (id: string, names: string[], idempotencyKey?: string) =>
  mutate<SecretMigration>("POST", `/api/v1/secrets/migrations/${encodeURIComponent(id)}/reissue`, { names }, idempotencyKey);

export const rollBackSecretMigration = (id: string, idempotencyKey?: string) =>
  mutate<SecretMigration>("POST", `/api/v1/secrets/migrations/${encodeURIComponent(id)}/rollback`, undefined, idempotencyKey);
