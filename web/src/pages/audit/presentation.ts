import type { AuditEvent, AuditReadableEvent } from "@/lib/api";

export interface AuditPresentation {
  state: "legacy" | "readable" | "erased" | "unavailable";
  detailsOmitted?: "key_preparing" | "tenant_offboarded";
  actor: AuditEvent["actor"];
  data: AuditEvent["data"];
}

// Keep the immutable event intact. Readable fields are a separate, exact
// identity-bound presentation and never replace the bytes its hash commits to.
export function auditPresentation(event: AuditEvent, readable: readonly AuditReadableEvent[]): AuditPresentation {
  if (event.data?.format !== "trstctl.protected-audit-source/v1") {
    const data = event.data;
    const omitted = data?.details_omitted;
    const closed =
      event.type === "authz.decision" &&
      !event.actor &&
      data &&
      Object.keys(data).length === 3 &&
      typeof data.permission === "string" &&
      (data.decision === "allow" || data.decision === "deny") &&
      (omitted === "key_preparing" || omitted === "tenant_offboarded");
    return { state: "legacy", actor: event.actor, data, detailsOmitted: closed ? omitted : undefined };
  }
  const matches = readable.filter((entry) => entry.id === event.id && entry.sequence === event.sequence);
  if (matches.length !== 1) return { state: "unavailable", actor: undefined, data: undefined };
  const details = matches[0];
  if (details.sensitive_erased) return { state: "erased", actor: undefined, data: undefined };
  return { state: "readable", actor: details.actor, data: details.data };
}
