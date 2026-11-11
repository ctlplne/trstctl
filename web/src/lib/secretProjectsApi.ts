import { mutate, req } from "./apiTransport";
import type {
  SecretProject,
  SecretProjectCreateRequest,
  SecretProjectEnvironmentRequest,
  SecretProjectList,
  SecretProjectMemberRequest,
  SecretProjectRenameRequest,
  SecretPromotionRequest,
  SecretRestoreRequest,
  SecretVersionBatchReceipt,
} from "./api";

// A235: the secrets workspace. A project groups an application's secrets by
// environment over the same native store; a restricted environment is open
// only to the members granted it. Reads list names, owners and versions —
// never values. Managing projects needs access:write; members change under
// access:write or by the project's admin holding secrets:write (A235-L1).

export const listSecretProjects = () => req<SecretProjectList>("/api/v1/secrets/projects");

export const getSecretProject = (project: string) => req<SecretProject>(`/api/v1/secrets/projects/${encodeURIComponent(project)}`);

export const createSecretProject = (input: SecretProjectCreateRequest, idempotencyKey?: string) =>
  mutate<SecretProject>("POST", "/api/v1/secrets/projects", input, idempotencyKey);

export const addSecretProjectEnvironment = (project: string, input: SecretProjectEnvironmentRequest, idempotencyKey?: string) =>
  mutate<SecretProject>("POST", `/api/v1/secrets/projects/${encodeURIComponent(project)}/environments`, input, idempotencyKey);

export const putSecretProjectMember = (project: string, subject: string, input: SecretProjectMemberRequest, idempotencyKey?: string) =>
  mutate<SecretProject>("PUT", `/api/v1/secrets/projects/${encodeURIComponent(project)}/members/${encodeURIComponent(subject)}`, input, idempotencyKey);

// A235-L3: renaming changes a display name; the slug, which every secret
// name in the project begins with, stays.
export const renameSecretProject = (project: string, input: SecretProjectRenameRequest, idempotencyKey?: string) =>
  mutate<SecretProject>("POST", `/api/v1/secrets/projects/${encodeURIComponent(project)}/rename`, input, idempotencyKey);

export const renameSecretProjectEnvironment = (project: string, environment: string, input: SecretProjectRenameRequest, idempotencyKey?: string) =>
  mutate<SecretProject>(
    "POST",
    `/api/v1/secrets/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(environment)}/rename`,
    input,
    idempotencyKey,
  );

export const deleteSecretProjectMember = (project: string, subject: string) =>
  mutate<SecretProject>("DELETE", `/api/v1/secrets/projects/${encodeURIComponent(project)}/members/${encodeURIComponent(subject)}`);

// A236: promotion and restore apply a reviewed plan by its digest as one
// batch of new versions. Their previews are read-only POSTs (api.ts).
export const applySecretPromotion = (project: string, input: SecretPromotionRequest, idempotencyKey?: string) =>
  mutate<SecretVersionBatchReceipt>("POST", `/api/v1/secrets/projects/${encodeURIComponent(project)}/promotions`, input, idempotencyKey);

export const applySecretRestore = (project: string, input: SecretRestoreRequest, idempotencyKey?: string) =>
  mutate<SecretVersionBatchReceipt>("POST", `/api/v1/secrets/projects/${encodeURIComponent(project)}/restores`, input, idempotencyKey);
