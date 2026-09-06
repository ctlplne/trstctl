// Benign first-run UI state: a single boolean — "has the operator finished
// onboarding on this browser" — persisted to localStorage so the empty-state
// wizard latches closed instead of re-prompting every visit (audit U2). This is
// never auth material: it carries no token, tenant, principal, or secret.
//
// It lives in its own module so the SURFACE-I01 storage guard
// (src/__tests__/security_sinks.test.ts) can allow exactly this benign key the
// same way it allows the theme preference and DataGrid view metadata — keeping
// raw localStorage out of page/component code.
const ONBOARDING_COMPLETE_KEY = "trstctl:onboarding-complete";

/** True once the first-run wizard has been completed on this browser. */
export function isOnboardingComplete(): boolean {
  try {
    return localStorage.getItem(ONBOARDING_COMPLETE_KEY) === "1";
  } catch {
    return false;
  }
}

/** Latch onboarding as finished so the dashboard stops showing the setup empty-state. */
export function markOnboardingComplete(): void {
  try {
    localStorage.setItem(ONBOARDING_COMPLETE_KEY, "1");
  } catch {
    /* storage unavailable — onboarding just won't latch across reloads, which is safe */
  }
}

/** Clear the latch so the wizard re-prompts on next visit (used by "start over"). */
export function resetOnboarding(): void {
  try {
    localStorage.removeItem(ONBOARDING_COMPLETE_KEY);
  } catch {
    /* storage unavailable — nothing to reset */
  }
}

// The first-run guide's certificate step issues once and then depends on React
// state; a reload (or the in-step "Open certificate inventory" link) dropped
// that state, so the guide fell back to an empty form with Next disabled and the
// only way forward was a second issuance. Remember the issued identity's id
// (a UUID, never a secret) so the guide can re-read the identity from the server
// on the next visit and treat the step as done only if the server still agrees.
const ONBOARDING_ISSUED_IDENTITY_KEY = "trstctl:onboarding-issued-identity";

/** Remember which identity the first-run guide issued so a reload can resume from the server's view of it. */
export function rememberIssuedIdentity(id: string): void {
  try {
    localStorage.setItem(ONBOARDING_ISSUED_IDENTITY_KEY, id);
  } catch {
    /* storage unavailable — the guide simply cannot resume across reloads */
  }
}

/** The remembered first-run identity id, or null. Callers must validate it against the server before trusting it. */
export function recallIssuedIdentity(): string | null {
  try {
    const value = localStorage.getItem(ONBOARDING_ISSUED_IDENTITY_KEY);
    return value && value.trim() ? value.trim() : null;
  } catch {
    return null;
  }
}

/** Forget the remembered identity (start over, or the server no longer knows it). */
export function forgetIssuedIdentity(): void {
  try {
    localStorage.removeItem(ONBOARDING_ISSUED_IDENTITY_KEY);
  } catch {
    /* storage unavailable — nothing to forget */
  }
}
