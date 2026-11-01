import { mutate, req } from "./apiTransport";
import type { DecoySecret, DecoySecretList, DecoySecretRegisterRequest } from "./api";

// Q6: decoy secrets. A stored application secret registered as bait; every
// served read of its value alerts, naming the reader. The registry needs
// secrets:write, so a caller who can only read secrets never learns which
// secrets are bait.

export const registerDecoySecret = (input: DecoySecretRegisterRequest, idempotencyKey?: string) =>
  mutate<DecoySecret>("POST", "/api/v1/secrets/honeytokens/secrets", input, idempotencyKey);

export const listDecoySecrets = (cursor?: string) =>
  req<DecoySecretList>(`/api/v1/secrets/honeytokens/secrets${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`);

export const retireDecoySecret = (id: string) => mutate<DecoySecret>("POST", `/api/v1/secrets/honeytokens/secrets/${encodeURIComponent(id)}/retire`);
