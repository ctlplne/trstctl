import { mutate, req } from "./apiTransport";
import type {
  DatabaseDecoy,
  DatabaseDecoyCreateRequest,
  DatabaseDecoyCreateResponse,
  DatabaseDecoyList,
  DecoyFile,
  DecoyFileList,
  KubernetesDecoy,
  KubernetesDecoyList,
  KubernetesDecoyRegisterRequest,
  KubernetesDecoyRegistration,
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

// Decoy files (Q6-O1): SSH private keys a host agent planted where no file was
// (trstctl-agent --decoy-ssh-keys); each program that opens one alerts once.
export const listDecoyFiles = (cursor?: string) =>
  req<DecoyFileList>(`/api/v1/secrets/honeytokens/files${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);

export const retireDecoyFile = (id: string) => mutate<DecoyFile>("POST", `/api/v1/secrets/honeytokens/files/${encodeURIComponent(id)}/retire`);

// Kubernetes token decoys (Q6-O2): a service account bound to nothing and its
// token Secret; the cluster's audit webhook reports reads and uses.
export const registerKubernetesDecoy = (input: KubernetesDecoyRegisterRequest, idempotencyKey?: string) =>
  mutate<KubernetesDecoyRegistration>("POST", "/api/v1/secrets/honeytokens/kubernetes", input, idempotencyKey);

export const listKubernetesDecoys = (cursor?: string) =>
  req<KubernetesDecoyList>(`/api/v1/secrets/honeytokens/kubernetes${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);

export const retireKubernetesDecoy = (id: string) => mutate<KubernetesDecoy>("POST", `/api/v1/secrets/honeytokens/kubernetes/${encodeURIComponent(id)}/retire`);
