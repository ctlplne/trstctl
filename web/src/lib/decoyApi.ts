import { mutate, req } from "./apiTransport";
import type {
  DatabaseDecoy,
  DatabaseDecoyCreateRequest,
  DatabaseDecoyCreateResponse,
  DatabaseDecoyList,
  DecoySecret,
  DecoySecretList,
  DecoySecretRegisterRequest,
} from "./api";

// Q6: decoy secrets. A stored application secret registered as bait; every
// served read of its value alerts, naming the reader. The registry needs
// secrets:write, so a caller who can only read secrets never learns which
// secrets are bait.

export const registerDecoySecret = (input: DecoySecretRegisterRequest, idempotencyKey?: string) =>
  mutate<DecoySecret>("POST", "/api/v1/secrets/honeytokens/secrets", input, idempotencyKey);

export const listDecoySecrets = (cursor?: string) =>
  req<DecoySecretList>(`/api/v1/secrets/honeytokens/secrets${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);

export const retireDecoySecret = (id: string) => mutate<DecoySecret>("POST", `/api/v1/secrets/honeytokens/secrets/${encodeURIComponent(id)}/retire`);

// Decoy database logins: bait PostgreSQL logins minted by a provider that
// lists the role "decoy"; any use raises one critical alert.
export const createDatabaseDecoy = (input: DatabaseDecoyCreateRequest, idempotencyKey?: string) =>
  mutate<DatabaseDecoyCreateResponse>("POST", "/api/v1/secrets/honeytokens/databases", input, idempotencyKey);

export const listDatabaseDecoys = () => req<DatabaseDecoyList>("/api/v1/secrets/honeytokens/databases");

export const retireDatabaseDecoy = (id: string) => mutate<DatabaseDecoy>("POST", `/api/v1/secrets/honeytokens/databases/${encodeURIComponent(id)}/retire`);
