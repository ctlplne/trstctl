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

const cliCommands = [
  {
    context: "Certificate inventory",
    command: "trstctl-cli certificates list --limit 50 --format json",
    parity: "same list contract as GET /api/v1/certificates",
  },
  {
    context: "Audit evidence",
    command: "trstctl-cli audit export --limit 500 --output audit-evidence.jws",
    parity: "same signed bundle as GET /api/v1/audit/export",
  },
  {
    context: "Graph blast radius",
    command: "trstctl-cli graph blast-radius cert:payments-api --format json",
    parity: "same graph result as /api/v1/graph/blast-radius/{id}",
  },
  {
    context: "Agent enrollment",
    command: "trstctl-cli agents enroll-token --format json",
    parity: "same one-time token endpoint as the Agents page",
  },
];

const runtimeRows = [
  {
    field: "Binary version",
    visible: "blocked on BACKEND-PLATFORM-STATUS",
    meaning: "Build info exists in the binary, but no console status JSON is served.",
  },
  {
    field: "Embedded UI asset",
    visible: "current bundle is served statically",
    meaning: "The browser receives a hashed Vite bundle, but the backend does not expose an asset-version field.",
  },
  {
    field: "Run mode",
    visible: "child signer mode documented, not observed",
    meaning: "Single-binary mode still supervises a separate signer child process; UI status needs a served read.",
  },
  {
    field: "Datastore mode",
    visible: "PostgreSQL required",
    meaning: "Bundled eval versus external production mode is not readable from the console yet.",
  },
  {
    field: "Signer supervision",
    visible: "not served",
    meaning: "The page must not guess whether the signer child is alive; /readyz is not enough detail for operators.",
  },
];

const federationRows = [
  {
    topic: "Cluster topology",
    state: "roadmap only",
    caveat: "no cross-cluster peer list or region status is served",
  },
  {
    topic: "Event-log replication",
    state: "not shipped",
    caveat: "conflict handling and replay checkpoints need BACKEND-FEDERATION",
  },
  {
    topic: "Tenant placement",
    state: "not shipped",
    caveat: "the console must not claim multi-region tenancy is available",
  },
];

const pluginAdminRows = [
  {
    plugin: "connector-f5.wasm",
    provenance: "Ed25519 signature required; digest pin sha256:4cf2...ab91",
    grants: "net.dial:f5.example.test",
    conformance: "fixture: OK before admission",
    runtime: "served introspection read missing",
  },
  {
    plugin: "dns-route53.wasm",
    provenance: "unsigned plugin would fail closed before instantiation",
    grants: "net.dial:route53.amazonaws.com",
    conformance: "fixture: denied CapFSWrite request",
    runtime: "activation blocked in console",
  },
  {
    plugin: "connector-nginx.wasm",
    provenance: "trusted-key set required",
    grants: "fs.write:/etc/nginx/certs, process.exec:nginx",
    conformance: "fixture: grant-limited",
    runtime: "denial reasons need BACKEND-PLUGINHOST",
  },
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

      <section aria-labelledby="cli-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="cli-heading" className="text-lg font-semibold">
            CLI companion
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            These commands mirror served API paths and assume `TRSTCTL_TOKEN` is already set in the shell. The browser never renders bearer token values, and the examples avoid inline Authorization headers.
          </p>
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[66rem] text-left text-sm">
            <caption className="sr-only">CLI companion commands</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Context</th>
                <th scope="col" className="py-2 pr-4 font-medium">Token-safe command</th>
                <th scope="col" className="py-2 pr-3 font-medium">Parity note</th>
              </tr>
            </thead>
            <tbody>
              {cliCommands.map((row) => (
                <tr key={row.context} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.context}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{row.command}</td>
                  <td className="py-2 pr-3">{row.parity}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="runtime-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="runtime-heading" className="text-lg font-semibold">
            Single-binary runtime
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Single-binary evaluation mode still keeps private-key operations in a separate signer child process. A real system page needs version, build info, embedded-UI asset, run mode, datastore mode, and signer supervision from a served status read.
          </p>
        </div>
        <UnavailableState title="Runtime status JSON not served yet">
          `BACKEND-PLATFORM-STATUS` must serve binary version, build metadata, embedded UI asset version, datastore mode, run mode, and signer child supervision before this page can show live runtime state.
        </UnavailableState>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[58rem] text-left text-sm">
            <caption className="sr-only">Single-binary runtime status fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Field</th>
                <th scope="col" className="py-2 pr-4 font-medium">Console visibility</th>
                <th scope="col" className="py-2 pr-3 font-medium">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {runtimeRows.map((row) => (
                <tr key={row.field} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.field}</td>
                  <td className="py-2 pr-4">{row.visible}</td>
                  <td className="py-2 pr-3">{row.meaning}</td>
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

      <section aria-labelledby="plugin-admin-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="plugin-admin-heading" className="text-lg font-semibold">
            Plugin SDK and capability sandbox
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Plugin administration needs loaded-plugin inventory, Ed25519 provenance, digest pins, capability grants, conformance results, runtime status, and denial reasons. The plugin host exists, but the console has no served read API for those records yet.
          </p>
        </div>
        <UnavailableState title="Plugin admin read API not served yet">
          `BACKEND-PLUGINHOST` must expose tenant-scoped plugin inventory, verification receipts, grants, conformance results, runtime state, and denial reasons before this page can inspect or activate plugins.
        </UnavailableState>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[72rem] text-left text-sm">
            <caption className="sr-only">Plugin SDK capability sandbox fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Plugin</th>
                <th scope="col" className="py-2 pr-4 font-medium">Provenance</th>
                <th scope="col" className="py-2 pr-4 font-medium">Capability grants</th>
                <th scope="col" className="py-2 pr-4 font-medium">Conformance</th>
                <th scope="col" className="py-2 pr-3 font-medium">Runtime status</th>
              </tr>
            </thead>
            <tbody>
              {pluginAdminRows.map((row) => (
                <tr key={row.plugin} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-mono text-xs">{row.plugin}</td>
                  <td className="py-2 pr-4">{row.provenance}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{row.grants}</td>
                  <td className="py-2 pr-4">{row.conformance}</td>
                  <td className="py-2 pr-3">{row.runtime}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="federation-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="federation-heading" className="text-lg font-semibold">
            Cross-cluster federation roadmap
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Cross-cluster and multi-region federation is roadmap-only. The console must not claim topology, replication, conflict handling, or tenant placement is available until a backend exists.
          </p>
        </div>
        <UnavailableState title="Federation is roadmap-only">
          `BACKEND-FEDERATION` has no served endpoint today. This page is a non-interactive roadmap disclosure, not an availability or replication status panel.
        </UnavailableState>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[52rem] text-left text-sm">
            <caption className="sr-only">Federation roadmap fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Topic</th>
                <th scope="col" className="py-2 pr-4 font-medium">State</th>
                <th scope="col" className="py-2 pr-3 font-medium">Caveat</th>
              </tr>
            </thead>
            <tbody>
              {federationRows.map((row) => (
                <tr key={row.topic} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.topic}</td>
                  <td className="py-2 pr-4">{row.state}</td>
                  <td className="py-2 pr-3">{row.caveat}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
