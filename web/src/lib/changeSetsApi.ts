import { mutate, req } from "./apiTransport";
import type { ChangeApplication, ChangeApplyRequest, ChangeDraft, ChangeDraftRequest, ChangePlan, ChangeSet } from "./api-types.gen";

/** A248: plan a reviewed change set. It changes nothing, so it carries no Idempotency-Key. */
export const planChangeSet = (set: ChangeSet) =>
  req<ChangePlan>("/api/v1/changes/plan", { method: "POST", body: JSON.stringify(set), headers: { "Content-Type": "application/json" } });

/** A248: apply exactly the reviewed plan; a plan the tenant moved past answers 409. */
export const applyChangeSet = (request: ChangeApplyRequest, idempotencyKey?: string) =>
  mutate<ChangeApplication>("POST", "/api/v1/changes/apply", request, idempotencyKey);

/** A248: draft a change set with the configured AI model; the draft is planned, never applied. */
export const draftChangeSet = (request: ChangeDraftRequest) =>
  req<ChangeDraft>("/api/v1/changes/draft", { method: "POST", body: JSON.stringify(request), headers: { "Content-Type": "application/json" } });
