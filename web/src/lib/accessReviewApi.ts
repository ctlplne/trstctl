import { mutate } from "./apiTransport";
import type { NHIReviewGenerateRequest, NHIReviewGenerateResponse } from "./api-types.gen";

// Q1: start an access review built from what trstctl records: the credentials
// that reach a graph node, or the credentials whose owner's attestation is
// stale. A retry with the same Idempotency-Key replays the first campaign.
export const generateNHIReviewCampaign = (input: NHIReviewGenerateRequest, idempotencyKey?: string) =>
  mutate<NHIReviewGenerateResponse>("POST", "/api/v1/access/reviews/generate", input, idempotencyKey);
