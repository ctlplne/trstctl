import { ApiError } from "@/lib/apiTransport";

export type IssuanceRequestRecovery = "retry" | "repair" | "replace";

// Act on the served recovery contract, never on a phrase in error prose.
export function issuanceRequestRecovery(error: unknown): IssuanceRequestRecovery {
  if (!(error instanceof ApiError)) return "retry";
  try {
    const problem: unknown = JSON.parse(error.body);
    if (!problem || typeof problem !== "object" || Array.isArray(problem) || !("retryable" in problem) || problem.retryable !== false) return "retry";
    if (error.status === 422 && "recovery_required" in problem && problem.recovery_required === "new_issuance_request") return "replace";
    return "repair";
  } catch {
    return "retry";
  }
}
