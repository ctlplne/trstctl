import type { FirstCertificatePrincipal } from "@/lib/firstCertificateAttempt";
import type { WizardCertificateAttempt } from "@/lib/wizardFirstCertificate";

// One volatile attempt, not browser storage or a cross-reload recovery contract.
// AuthProvider clears it and aborts outstanding work on a principal change.
let principal: FirstCertificatePrincipal | null = null;
let retained: WizardCertificateAttempt | null = null;
const active = new Set<AbortController>();
export function sameFirstCertificatePrincipal(a: FirstCertificatePrincipal | null, b: FirstCertificatePrincipal | null): boolean {
  return a?.tenantId === b?.tenantId && a?.subject === b?.subject;
}
export function bindFirstCertificatePrincipal(next: FirstCertificatePrincipal | null): void {
  if (sameFirstCertificatePrincipal(principal, next)) return;
  for (const controller of active) controller.abort();
  active.clear();
  retained = null;
  principal = next ? Object.freeze({ ...next }) : null;
}
export function firstCertificatePrincipalMatches(expected: FirstCertificatePrincipal): boolean {
  return Boolean(expected.tenantId && expected.subject && sameFirstCertificatePrincipal(principal, expected));
}
export function retainedFirstCertificateAttempt(expected: FirstCertificatePrincipal): WizardCertificateAttempt | null {
  return firstCertificatePrincipalMatches(expected) ? retained : null;
}
export function retainFirstCertificateAttempt(next: WizardCertificateAttempt): void {
  if (!firstCertificatePrincipalMatches(next.principal)) throw new Error("session_changed");
  retained = next;
}
export function registerFirstCertificateOperation(controller: AbortController): () => void {
  active.add(controller);
  return () => active.delete(controller);
}
