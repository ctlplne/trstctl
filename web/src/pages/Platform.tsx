import { useState } from "react";
import { useAuth } from "@/auth/AuthProvider";
import { UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { realGuiSurfaces } from "@/lib/navigation";

interface ScopeRequirement {
  feature: string;
  scope: string;
  route: string;
  denial: string;
}

interface StaticAPIRoute {
  group: string;
  path: string;
  methods: string[];
  auth: string;
}

const requiredScopes: ScopeRequirement[] = [
  {
    feature: "Certificate issuance",
    scope: "certs:issue",
    route: "/identities",
    denial: "Issuance remains denied until RA separation, dual control, and OPA allow the action.",
  },
  {
    feature: "Certificate inventory",
    scope: "certs:read",
    route: "/certificates",
    denial: "Inventory denial is shown as a generic permission message without tenant existence details.",
  },
  {
    feature: "Credential graph",
    scope: "graph:read",
    route: "/graph",
    denial: "Graph denials hide cross-tenant node details and show only the missing evidence scope.",
  },
  {
    feature: "Audit evidence",
    scope: "audit:read",
    route: "/audit",
    denial: "Audit denials suppress raw problem bodies that might mention another tenant.",
  },
  {
    feature: "Secrets",
    scope: "secrets:write",
    route: "/coverage?domain=Secrets",
    denial: "Secret workflows must never reveal or persist secret material when authorization fails.",
  },
];

const staticAPIRoutes: StaticAPIRoute[] = [
  { group: "Agents", path: "/api/v1/agents", methods: ["GET"], auth: "session or API token" },
  { group: "Agents", path: "/api/v1/agents/enrollment-tokens", methods: ["POST"], auth: "session, CSRF, Idempotency-Key" },
  { group: "AI", path: "/api/v1/ai/query", methods: ["POST"], auth: "session or API token" },
  { group: "AI", path: "/api/v1/ai/rca", methods: ["POST"], auth: "session or API token" },
  { group: "Audit", path: "/api/v1/audit/events", methods: ["GET"], auth: "session or API token" },
  { group: "Audit", path: "/api/v1/audit/export", methods: ["GET"], auth: "session or API token" },
  { group: "Certificates", path: "/api/v1/certificates", methods: ["GET", "POST"], auth: "session; POST adds CSRF + Idempotency-Key" },
  { group: "Certificates", path: "/api/v1/certificates/{id}", methods: ["GET"], auth: "session or API token" },
  { group: "Graph", path: "/api/v1/graph", methods: ["GET"], auth: "session or API token" },
  { group: "Graph", path: "/api/v1/graph/blast-radius/{id}", methods: ["GET"], auth: "session or API token" },
  { group: "Graph", path: "/api/v1/graph/query", methods: ["POST"], auth: "session, CSRF; read-only POST" },
  { group: "Graph", path: "/api/v1/graph/reachable/{id}", methods: ["GET"], auth: "session or API token" },
  { group: "Identities", path: "/api/v1/identities", methods: ["GET", "POST"], auth: "session; POST adds CSRF + Idempotency-Key" },
  { group: "Identities", path: "/api/v1/identities/{id}", methods: ["GET"], auth: "session or API token" },
  { group: "Identities", path: "/api/v1/identities/{id}/approvals", methods: ["POST"], auth: "session, CSRF, Idempotency-Key" },
  { group: "Identities", path: "/api/v1/identities/{id}/transitions", methods: ["POST"], auth: "session, CSRF, Idempotency-Key" },
  { group: "Issuers", path: "/api/v1/issuers", methods: ["GET", "POST"], auth: "session; POST adds CSRF + Idempotency-Key" },
  { group: "Issuers", path: "/api/v1/issuers/{id}", methods: ["GET"], auth: "session or API token" },
  { group: "MCP", path: "/api/v1/mcp/tools", methods: ["GET"], auth: "session or API token" },
  { group: "MCP", path: "/api/v1/mcp/tools/{tool}", methods: ["POST"], auth: "session, CSRF; read-only tool call" },
  { group: "Owners", path: "/api/v1/owners", methods: ["GET", "POST"], auth: "session; POST adds CSRF + Idempotency-Key" },
  { group: "Owners", path: "/api/v1/owners/{id}", methods: ["GET", "PUT", "DELETE"], auth: "session; mutations add CSRF + Idempotency-Key" },
  { group: "Profiles", path: "/api/v1/profiles", methods: ["GET", "POST"], auth: "session; POST adds CSRF + Idempotency-Key" },
  { group: "Profiles", path: "/api/v1/profiles/{name}/versions/{version}", methods: ["GET"], auth: "session or API token" },
  { group: "Risk", path: "/api/v1/risk/credentials", methods: ["GET"], auth: "session or API token" },
  { group: "Secrets", path: "/api/v1/secrets/login", methods: ["POST"], auth: "session, CSRF; scoped machine login" },
  { group: "Secrets", path: "/api/v1/secrets/pki", methods: ["POST"], auth: "session, CSRF, Idempotency-Key" },
  { group: "Secrets", path: "/api/v1/secrets/shares", methods: ["POST"], auth: "session, CSRF, Idempotency-Key" },
  { group: "Secrets", path: "/api/v1/secrets/shares/redeem", methods: ["POST"], auth: "session, CSRF, Idempotency-Key" },
  { group: "Secrets", path: "/api/v1/secrets/store", methods: ["GET", "POST"], auth: "session; POST adds CSRF + Idempotency-Key" },
  { group: "Secrets", path: "/api/v1/secrets/store/{name}", methods: ["GET", "PUT", "DELETE"], auth: "session; mutations add CSRF + Idempotency-Key" },
];

function browserTransport(): { label: string; detail: string; warning?: string } {
  if (typeof window === "undefined") {
    return { label: "Unknown", detail: "Browser transport is evaluated at runtime." };
  }
  if (window.location.protocol === "https:") {
    return {
      label: "HTTPS observed",
      detail: "The console is currently loaded over an encrypted browser connection.",
    };
  }
  return {
    label: "Local preview HTTP",
    detail: "The local Vite preview is HTTP. Production should be HTTPS or mTLS-terminated before operators use it.",
    warning: "Plaintext local preview. No private cert/key bytes are exposed in this browser view.",
  };
}

export function Platform() {
  const { user, preview } = useAuth();
  const transport = browserTransport();
  const nonLedgerSurfaces = realGuiSurfaces.filter((s) => s.routes.some((route) => route !== "/coverage"));
  const [copiedRoute, setCopiedRoute] = useState<string | null>(null);
  const csrfPresent = typeof document !== "undefined" && document.cookie.includes("trstctl_csrf=");

  async function copyCurl(route: StaticAPIRoute) {
    const command = curlFor(route);
    try {
      await navigator.clipboard?.writeText(command);
      setCopiedRoute(route.path);
    } catch {
      setCopiedRoute(route.path);
    }
  }

  return (
    <section aria-labelledby="platform-heading" className="grid gap-6">
      <div>
        <h1 id="platform-heading" className="text-2xl font-semibold">
          Platform
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Tenant context, access-control evidence, browser transport posture, auth status, and a static API-spec view.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="border-y border-border py-4" aria-labelledby="tenant-heading">
          <h2 id="tenant-heading" className="text-lg font-semibold">
            Tenant boundary
          </h2>
          <dl className="mt-3 grid gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Subject</dt>
              <dd>{user?.email || user?.subject || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Tenant ID from session</dt>
              <dd className="break-all font-mono text-xs">{user?.tenant_id || "-"}</dd>
            </div>
          </dl>
          <p className="mt-3 text-sm text-muted-foreground">
            The browser never chooses a tenant id through a route, query string, or form field. The backend session or API token supplies it, and PostgreSQL RLS enforces it below the API.
          </p>
        </section>

        <section className="border-y border-border py-4" aria-labelledby="transport-heading">
          <h2 id="transport-heading" className="text-lg font-semibold">
            Transport
          </h2>
          <p className="mt-3 text-sm font-medium">{transport.label}</p>
          <p className="mt-1 text-sm text-muted-foreground">{transport.detail}</p>
          {transport.warning && <p className="mt-2 text-sm font-medium text-amber-700">{transport.warning}</p>}
        </section>

        <section className="border-y border-border py-4" aria-labelledby="auth-heading">
          <h2 id="auth-heading" className="text-lg font-semibold">
            Auth session
          </h2>
          <dl className="mt-3 grid gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Mode visible to UI</dt>
              <dd>{preview ? "local preview session" : "served /auth/me session"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">CSRF cookie</dt>
              <dd>{csrfPresent ? "present for browser mutations" : "not visible in this browser context"}</dd>
            </div>
          </dl>
          <p className="mt-3 text-sm text-muted-foreground">
            OIDC enabled/disabled, issuer, audience, and API-token fallback status need `BACKEND-PLATFORM-STATUS`; this page never offers a fake token-injection login.
          </p>
        </section>
      </div>

      <section aria-labelledby="access-heading">
        <h2 id="access-heading" className="mb-3 text-lg font-semibold">
          Access control and required scopes
        </h2>
        <div className="mb-3 rounded-md border border-border p-3 text-sm">
          <p className="font-medium">Current scope inventory is not served yet.</p>
          <p className="mt-1 text-muted-foreground">
            `BACKEND-TENANT-ADMIN` must expose roles/scopes before the console can list the exact grants on this session. Until then, the UI can show the live principal and the required-scope map used by served workflows.
          </p>
        </div>
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Required permission scopes by feature</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Feature</th>
              <th scope="col" className="py-2 pr-4 font-medium">Required scope</th>
              <th scope="col" className="py-2 pr-4 font-medium">Route</th>
              <th scope="col" className="py-2 font-medium">Denied-action copy</th>
            </tr>
          </thead>
          <tbody>
            {requiredScopes.map((item) => (
              <tr key={item.scope} className="border-b border-border align-top">
                <td className="py-2 pr-4">{item.feature}</td>
                <td className="py-2 pr-4 font-mono text-xs">{item.scope}</td>
                <td className="py-2 pr-4">{item.route}</td>
                <td className="py-2">{item.denial}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section aria-labelledby="api-spec-heading">
        <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="api-spec-heading" className="text-lg font-semibold">
              Static API spec view
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {staticAPIRoutes.length} served REST paths copied from the pinned OpenAPI golden. This is a static spec view until `BACKEND-OPENAPI-SERVED` publishes a live `/api/v1/openapi.json`.
            </p>
          </div>
          <span className="rounded-md border border-border px-2 py-1 text-xs font-medium">Spec view</span>
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[60rem] text-left text-sm">
            <caption className="sr-only">Static served REST API paths</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Group</th>
                <th scope="col" className="py-2 pr-4 font-medium">Methods</th>
                <th scope="col" className="py-2 pr-4 font-medium">Path</th>
                <th scope="col" className="py-2 pr-4 font-medium">Auth mode</th>
                <th scope="col" className="py-2 pr-3 font-medium">Curl</th>
              </tr>
            </thead>
            <tbody>
              {staticAPIRoutes.map((route) => (
                <tr key={route.path} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4">{route.group}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{route.methods.join(", ")}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{route.path}</td>
                  <td className="py-2 pr-4">{route.auth}</td>
                  <td className="py-2 pr-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <code className="max-w-md break-all rounded bg-muted px-2 py-1 text-xs">{curlFor(route)}</code>
                      <Button type="button" size="sm" variant="outline" onClick={() => void copyCurl(route)}>
                        Copy curl
                      </Button>
                    </div>
                    {copiedRoute === route.path && <p className="mt-1 text-xs text-muted-foreground">Copied without token material.</p>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="surfaces-heading">
        <h2 id="surfaces-heading" className="mb-3 text-lg font-semibold">
          Registered real surfaces
        </h2>
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Real GUI route registry</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Feature</th>
              <th scope="col" className="py-2 pr-4 font-medium">Routes</th>
              <th scope="col" className="py-2 pr-4 font-medium">Kind</th>
              <th scope="col" className="py-2 font-medium">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {nonLedgerSurfaces.map((surface) => (
              <tr key={surface.featureId} className="border-b border-border align-top">
                <td className="py-2 pr-4 font-mono text-xs">{surface.featureId}</td>
                <td className="py-2 pr-4">{surface.routes.join(", ")}</td>
                <td className="py-2 pr-4">{surface.kind}</td>
                <td className="py-2">{surface.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <div className="grid gap-3 lg:grid-cols-3">
        <UnavailableState title="Tenant admin endpoint not served yet">
          Tenant list, tenant switching, per-tenant limits, and exact role/scope inventory are blocked on `BACKEND-TENANT-ADMIN`. The session tenant remains fixed by the backend.
        </UnavailableState>
        <UnavailableState title="Platform status endpoint not served yet">
          Build info, datastore mode, signer-child state, OIDC config, and feature flags are blocked on `BACKEND-PLATFORM-STATUS`.
        </UnavailableState>
        <UnavailableState title="Live OpenAPI endpoint not served yet">
          Runtime OpenAPI publication is blocked on `BACKEND-OPENAPI-SERVED`; the table above is a static spec view from the pinned golden.
        </UnavailableState>
      </div>
    </section>
  );
}

function curlFor(route: StaticAPIRoute): string {
  const method = route.methods[0];
  const header = method === "GET" ? "" : " -H 'Content-Type: application/json'";
  return `curl -X ${method}${header} https://trstctl.example.test${route.path}`;
}
