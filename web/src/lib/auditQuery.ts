import type { AuditQuery } from "./api";

/** Search, signed evidence and every record-stream encoding share one selector.
 * Adding a filter must not quietly widen a download. */
export function auditQueryParams(options?: AuditQuery): URLSearchParams {
  const params = new URLSearchParams();
  params.set("limit", String(options?.limit ?? 50));
  if (options?.tool) params.set("tool", options.tool);
  if (options?.type) params.set("type", options.type);
  if (options?.featureID) params.set("feature_id", options.featureID);
  if (options?.action) params.set("action", options.action);
  if (options?.since) params.set("since", options.since);
  if (options?.until) params.set("until", options.until);
  if (options?.asOf != null) params.set("as_of", String(options.asOf));
  if (options?.q) params.set("q", options.q);
  return params;
}

export function auditReadSignal(signal?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(15_000);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}
