// One error renderer for the whole console (WEB-APIPROBLEM-001, AH-bc10425e).
//
// This file replaces eight page-local copies of apiProblemMessage that had
// drifted apart. Two of them - Approvals and Identities - had lost the 429
// branch entirely, so a rate-limited request rendered as a bare problem detail
// with no Retry-After guidance; of the six that kept it, four prefixed the
// message with the caller's fallback and two did not, and they disagreed on
// trailing punctuation. The same 429 therefore rendered three different ways
// depending on which page served it.
//
// Two shapes survive, because both are legitimately in use and both are pinned
// by existing tests: apiProblemMessage where the surrounding UI already names
// the failing operation, and apiProblemContext where the message stands alone.
// They share one parsing core and one 429 branch. An eslint no-restricted-syntax
// rule (web/eslint.config.js) fails the build on a ninth local copy.
import { ApiError } from "@/lib/api";

/** The RFC 7807 half of an error body the control plane returns. */
type ApiProblem = { detail?: string; title?: string };

/** apiProblemDetail extracts the human-readable half of an ApiError body: the
 * RFC 7807 detail, else its title, else the raw body, else the ApiError's own
 * summary. It never returns a blank string - a whitespace-only body falls
 * through to the summary rather than rendering an empty alert. */
function apiProblemDetail(err: ApiError): string {
  const body = err.body.trim();
  if (body) {
    try {
      const problem = JSON.parse(body) as ApiProblem;
      const message = problem.detail || problem.title;
      if (message) return message;
    } catch {
      return body;
    }
  }
  return err.message;
}

/** retryHint renders the Retry-After guidance for a shed request. It is the
 * only actionable thing a user has when the server is rate limiting them
 * (SURFACE-007), so both renderers below go through it. */
function retryHint(err: ApiError): string | undefined {
  return err.retryAfterSeconds != null ? `retry in ${err.retryAfterSeconds}s` : undefined;
}

/** apiProblemMessage renders the server's own words, using `fallback` only when
 * the throw is not an Error at all. Use it where the surrounding UI already
 * says which operation failed - an inline field error, or a banner with its own
 * title. A 429 still carries the fallback as context so "retry in 30s" is not
 * stranded without a subject. */
export function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const retry = retryHint(err);
    return retry ? `${fallback}: ${retry}` : apiProblemDetail(err);
  }
  return err instanceof Error ? err.message : fallback;
}

/** apiProblemContext renders the same message prefixed with `fallback` as the
 * context line. Use it where the message stands alone and the reader would
 * otherwise not know which request failed. */
export function apiProblemContext(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return `${fallback}: ${retryHint(err) ?? apiProblemDetail(err)}`;
  return err instanceof Error ? `${fallback}: ${err.message}` : fallback;
}
