import type { AuditEvent, AuditReadableEvent } from "@/lib/api";

export interface AuditPresentation {
  state: "legacy" | "readable" | "erased" | "unavailable";
  actor: AuditEvent["actor"];
  data: AuditEvent["data"];
}

// Keep the immutable event intact. Readable fields are a separate, exact
// identity-bound presentation and never replace the bytes its hash commits to.
export function auditPresentation(event: AuditEvent, readable: readonly AuditReadableEvent[]): AuditPresentation {
  if (event.data?.format !== "trstctl.protected-audit-source/v1") {
    return { state: "legacy", actor: event.actor, data: event.data };
  }
  const matches = readable.filter((entry) => entry.id === event.id && entry.sequence === event.sequence);
  if (matches.length !== 1) return { state: "unavailable", actor: undefined, data: undefined };
  const details = matches[0];
  if (details.sensitive_erased) return { state: "erased", actor: undefined, data: undefined };
  return { state: "readable", actor: details.actor, data: details.data };
}
