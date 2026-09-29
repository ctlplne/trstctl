import { describe, expect, it } from "vitest";
import { ApiError } from "@/lib/apiTransport";
import { issuanceRequestRecovery } from "@/lib/issuanceRequestRecovery";

describe("served issuance recovery contract", () => {
  it.each([
    ["temporary upstream failure", new ApiError(503, JSON.stringify({ retryable: true })), "retry"],
    ["plain validation error", new ApiError(422, JSON.stringify({ detail: "leaves no usable lifetime" })), "retry"],
    ["unknown recovery action", new ApiError(422, JSON.stringify({ retryable: false, recovery_required: "unknown" })), "repair"],
    ["missing recovery action", new ApiError(422, JSON.stringify({ retryable: false })), "repair"],
    ["different status", new ApiError(409, JSON.stringify({ retryable: false, recovery_required: "new_issuance_request" })), "repair"],
    ["incorrect boolean", new ApiError(422, JSON.stringify({ retryable: "false", recovery_required: "new_issuance_request" })), "retry"],
    ["malformed JSON", new ApiError(422, "not JSON"), "retry"],
    ["JSON null", new ApiError(422, "null"), "retry"],
    ["JSON array", new ApiError(422, "[]"), "retry"],
    ["network failure", new Error("connection lost"), "retry"],
    ["permanent pinned profile", new ApiError(422, JSON.stringify({ retryable: false, recovery_required: "new_issuance_request" })), "replace"],
  ])("handles %s without interpreting error prose", (_name, error, expected) => {
    expect(issuanceRequestRecovery(error)).toBe(expected);
  });
});
