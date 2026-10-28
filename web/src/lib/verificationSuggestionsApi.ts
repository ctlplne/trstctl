import { mutate, req } from "./apiTransport";
import type { DeploymentTarget, VerificationAddressConfirmation, VerificationSuggestions } from "./api-types.gen";

// Verification address suggestions: where discovery saw a certificate trstctl
// delivered to a target, for an operator to confirm as its verification address.

/** Read the addresses scans saw a target's delivered certificates at. */
export const verificationSuggestions = (targetId: string) =>
  req<VerificationSuggestions>(`/api/v1/connectors/targets/${encodeURIComponent(targetId)}/verification-suggestions`);

/** Confirm a suggested address; the target gets a new revision. */
export const confirmVerificationAddress = (targetId: string, input: VerificationAddressConfirmation, idempotencyKey?: string) =>
  mutate<DeploymentTarget>("POST", `/api/v1/connectors/targets/${encodeURIComponent(targetId)}/verification-address`, input, idempotencyKey);
