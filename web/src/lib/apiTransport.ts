// Shared HTTP and browser authority state for startup and lazy route clients.
import { translateNow } from "@/i18n/I18nProvider";

export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

/** apiErrorMessage turns a failed response into the sentence a page shows. The
 * server answers refusals with RFC 9457 problem+json whose `detail` names the
 * exact prerequisite and remedy (for example which DNS-01 provider config or
 * custody setting an endpoint lifecycle needs). Showing only "request failed
 * (422)" threw that guidance away, so a refused preview looked like an outage.
 * The status stays in the message; a body without a usable detail keeps the
 * generic wording. */
export function apiErrorMessage(status: number, body: string, retryAfterSeconds?: number): string {
  if (status === 429) return `rate limited (429)${retryAfterSeconds != null ? ` — retry in ${retryAfterSeconds}s` : ""}`;
  const generic = `request failed (${status})`;
  const trimmed = (body ?? "").trim();
  if (!trimmed.startsWith("{")) return generic;
  try {
    const parsed = JSON.parse(trimmed) as { detail?: unknown; title?: unknown };
    const detail = typeof parsed.detail === "string" ? parsed.detail.trim() : "";
    const title = typeof parsed.title === "string" ? parsed.title.trim() : "";
    const text = detail || title;
    if (!text) return generic;
    return `${text} (HTTP ${status})`;
  } catch {
    return generic;
  }
}

export class ApiError extends Error {
  status: number;
  body: string;
  /** retryAfterSeconds is set for a 429 when the server sends Retry-After, so the UI
   * can surface a concrete "try again in N seconds" hint instead of a bare failure
   * (SURFACE-007; the server emits Retry-After on rate-limit at api.go). */
  retryAfterSeconds?: number;
  constructor(status: number, body: string, retryAfterSeconds?: number) {
    super(apiErrorMessage(status, body, retryAfterSeconds));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.retryAfterSeconds = retryAfterSeconds;
  }
  /** isRateLimited is a convenience for the UI's special-case path. */
  get isRateLimited(): boolean {
    return this.status === 429;
  }
}

/** Authorization refusals need an explicit session or permission change, not
 * automatic transport retries. Keep them visible to the query layer. */
export function isAccessDenied(error: unknown): boolean {
  return error instanceof UnauthorizedError || (error instanceof ApiError && (error.status === 401 || error.status === 403));
}

/** parseRetryAfter reads a Retry-After header (RFC 7231: either delta-seconds or an
 * HTTP-date) into seconds, or undefined when absent/unparseable. */
function parseRetryAfter(h: string | null): number | undefined {
  if (!h) return undefined;
  const secs = Number(h);
  if (Number.isFinite(secs)) return Math.max(0, Math.round(secs));
  const when = Date.parse(h);
  if (!Number.isNaN(when)) return Math.max(0, Math.round((when - Date.now()) / 1000));
  return undefined;
}

function isUnsafeMethod(method: string | undefined): boolean {
  const m = (method ?? "GET").toUpperCase();
  return m !== "GET" && m !== "HEAD" && m !== "OPTIONS" && m !== "TRACE";
}

function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length));
  }
  return undefined;
}

// Exported for the audit-export workflow, which issues a blob fetch rather
// than a JSON request and so cannot go through req<T> (epic J1).
export function csrfHeaders(method: string | undefined): Record<string, string> {
  if (!isUnsafeMethod(method)) return {};
  const token = readCookie("trstctl_csrf");
  return token ? { "X-CSRF-Token": token } : {};
}

/** Preview transport isolation (mirrors probectl's demo model): while preview
 * mode is active, the client refuses EVERY server call before fetch — the
 * showcase runs entirely in the browser, so a hosted demo bundle can never
 * leak a request. The demo host's Worker 404s /api/* as belt-and-suspenders;
 * this is the wall. Set by AuthProvider on preview start/stop. */
let previewTransportIsolated = false;
export function setPreviewTransportIsolation(isolated: boolean): void {
  previewTransportIsolated = isolated;
}

// The machine-login exchange is intentionally public because the submitted
// machine credential is what authenticates the workload. The server still
// needs an explicit tenant lookup hint before it can choose a verifier. The
// browser may use only the tenant returned by /auth/me; it never accepts this
// value from a route, query string, form field, or the machine credential.
let authenticatedBrowserTenantID = "";
export function setAuthenticatedBrowserTenantID(tenantID: string | null | undefined): void {
  authenticatedBrowserTenantID = tenantID?.trim() ?? "";
}

/** Read the preview-isolation wall. A reader rather than an exported binding,
 * so this module stays the only writer (epic J1's audit download needs to
 * honour the same wall without being able to lower it). */
export function previewTransportIsIsolated(): boolean {
  return previewTransportIsolated;
}

const previewFixturesCompiled = import.meta.env.DEV || import.meta.env.VITE_TRSTCTL_DEMO === "1";

export function previewRefusal(): ApiError {
  const refusal = new ApiError(0, translateNow("preview.transportIsolated"));
  refusal.message = refusal.body;
  return refusal;
}

async function previewResponse(method: string): Promise<unknown> {
  // This branch is a compile-time constant. Vite removes both the import and
  // its chunk from the ordinary embedded product build; dev and the explicit
  // demo build retain it.
  if (previewFixturesCompiled) {
    const { previewRead } = await import("./previewData");
    const response = previewRead(method);
    if (response.matched) return response.value;
  }
  throw previewRefusal();
}

// Exported for the estate-shape workflow module (H1/H2/H4/I1), which must go
// through this same bounded transport.
export async function req<T>(path: string, init?: RequestInit): Promise<T> {
  if (previewTransportIsolated) {
    // api methods are intercepted before reaching req. Keep this second wall
    // for direct/internal callers and future code that accidentally bypasses
    // the exported client wrapper.
    throw previewRefusal();
  }
  const method = init?.method;
  const res = await fetch(path, {
    credentials: "include",
    ...init,
    headers: { Accept: "application/json", ...csrfHeaders(method), ...(init?.headers ?? {}) },
  });
  if (res.status === 401) throw new UnauthorizedError();
  if (res.status === 429) {
    // Rate limited: surface Retry-After so the UI can show a concrete retry hint
    // (SURFACE-007). The server emits Retry-After on its per-tenant bulkhead/limit.
    throw new ApiError(429, await res.text(), parseRetryAfter(res.headers.get("Retry-After")));
  }
  if (!res.ok) throw new ApiError(res.status, await res.text());
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** newIdempotencyKey returns a fresh key so a retried mutation cannot execute
 * twice (AN-5). */
export function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `idem-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/** mutate issues a state-changing request with an optional JSON body and an
 * Idempotency-Key. */
export function mutate<T>(method: string, path: string, body?: unknown, idempotencyKey = newIdempotencyKey()): Promise<T> {
  return req<T>(path, {
    method,
    headers: { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** A public mutation whose tenant hint comes only from the authenticated
 * browser session. Refuse before serializing or sending a credential when the
 * session tenant has not been resolved. The server still authenticates the
 * credential and rejects a tenant/MAC mismatch. */
export function mutateForAuthenticatedBrowserTenant<T>(path: string, body: unknown, idempotencyKey = newIdempotencyKey()): Promise<T> {
  if (!authenticatedBrowserTenantID) {
    return Promise.reject(new ApiError(0, "The browser session has no verified tenant. Reload and sign in before testing a machine credential."));
  }
  return req<T>(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
      "X-Tenant-ID": authenticatedBrowserTenantID,
    },
    body: JSON.stringify(body),
  });
}

/** One stable wrapper per API method keeps normal query function identities
 * unchanged. In preview, only methods explicitly present in previewData can
 * resolve; mutations and unmodeled reads fail before liveApi can reach req or
 * fetch. */
export function createPreviewAwareApi<T extends object>(implementation: T): T {
  const wrapped: Record<string, (...args: unknown[]) => Promise<unknown>> = {};
  for (const [method, candidate] of Object.entries(implementation)) {
    const invoke = candidate as (...args: unknown[]) => Promise<unknown>;
    wrapped[method] = (...args: unknown[]) => (previewTransportIsolated ? previewResponse(method) : invoke(...args));
  }
  return wrapped as unknown as T;
}
