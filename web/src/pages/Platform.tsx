import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Copy, KeyRound, Loader2, Plus, RefreshCw, ShieldCheck, UserMinus } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { PageHeader } from "@/components/PageHeader";
import { UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { api, type APIToken, type Member, type OIDCMappingStatus, type RoleList } from "@/lib/api";
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
    feature: "Access administration",
    scope: "access:write",
    route: "/platform",
    denial: "Member and API-token administration stays denied unless the principal has the access-admin write scope.",
  },
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
  { group: "Access", path: "/api/v1/access/roles", methods: ["GET"], auth: "session or API token" },
  { group: "Access", path: "/api/v1/access/oidc-mapping", methods: ["GET"], auth: "session or API token" },
  { group: "Access", path: "/api/v1/access/members", methods: ["GET"], auth: "session or API token" },
  { group: "Access", path: "/api/v1/access/members/{subject}", methods: ["PUT"], auth: "session, CSRF, Idempotency-Key" },
  { group: "Access", path: "/api/v1/access/members/{subject}/offboard", methods: ["POST"], auth: "session, CSRF, Idempotency-Key" },
  { group: "Access", path: "/api/v1/access/api-tokens", methods: ["GET", "POST"], auth: "session; POST adds CSRF + Idempotency-Key" },
  { group: "Access", path: "/api/v1/access/api-tokens/{id}", methods: ["DELETE"], auth: "session, CSRF, Idempotency-Key" },
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
  {
    context: "Access administration",
    command: "trstctl-cli access members list --include_offboarded true --format json",
    parity: "same member/offboarding contract as GET /api/v1/access/members",
  },
  {
    context: "Approver token mint",
    command: "trstctl-cli access tokens create -f approver-token.json --format json",
    parity: "same reveal-once token contract as POST /api/v1/access/api-tokens",
  },
];

const runtimeRows = [
  {
    field: "Binary version",
    visible: "not shown in the console yet",
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
    caveat: "conflict handling and replay checkpoints are on the roadmap",
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
    runtime: "console management is coming soon",
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
  const [roles, setRoles] = useState<RoleList | null>(null);
  const [oidc, setOIDC] = useState<OIDCMappingStatus | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [accessLoading, setAccessLoading] = useState(true);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [accessNotice, setAccessNotice] = useState<string | null>(null);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [memberSubject, setMemberSubject] = useState("");
  const [memberDisplayName, setMemberDisplayName] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRoles, setMemberRoles] = useState("operator");
  const [tokenSubject, setTokenSubject] = useState("");
  const [tokenScopes, setTokenScopes] = useState("certs:issue");
  const [offboardSubject, setOffboardSubject] = useState("");
  const [offboardReason, setOffboardReason] = useState("");
  const roleRows = useMemo(() => roles?.items ?? [], [roles]);

  async function loadAccessAdmin() {
    setAccessLoading(true);
    setAccessError(null);
    try {
      const [roleCatalog, oidcStatus, memberPage, tokenPage] = await Promise.all([
        api.accessRoles(),
        api.oidcMappingStatus(),
        api.members({ includeOffboarded: true, limit: 50 }),
        api.apiTokens({ includeRevoked: true, limit: 50 }),
      ]);
      setRoles(roleCatalog);
      setOIDC(oidcStatus);
      setMembers(memberPage.items ?? []);
      setTokens(tokenPage.items ?? []);
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessLoading(false);
    }
  }

  useEffect(() => {
    void loadAccessAdmin();
  }, []);

  async function onboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    try {
      await api.upsertMember(memberSubject.trim(), {
        display_name: memberDisplayName.trim(),
        email: memberEmail.trim(),
        roles: csvList(memberRoles),
        source: "manual",
      });
      setAccessNotice(`Onboarded ${memberSubject.trim()}`);
      setMemberSubject("");
      setMemberDisplayName("");
      setMemberEmail("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  async function mintToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
    try {
      const created = await api.createAPIToken({ subject: tokenSubject.trim(), scopes: csvList(tokenScopes) });
      setRevealedToken(created.token);
      setAccessNotice(`Minted API token for ${created.subject}`);
      setTokenSubject("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  async function offboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
    try {
      const result = await api.offboardMember(offboardSubject.trim(), { reason: offboardReason.trim() });
      setAccessNotice(`Offboarded ${result.member.subject}; revoked ${result.revoked_token_count} token(s)`);
      setOffboardSubject("");
      setOffboardReason("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

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
      <PageHeader
        titleId="platform-heading"
        title="Platform"
        description="Tenant context, access-control evidence, browser transport posture, auth status, and a static API-spec view."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="ui-panel p-comfortable" aria-labelledby="tenant-heading">
          <h2 id="tenant-heading" className="text-title font-semibold">
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

        <section className="ui-panel p-comfortable" aria-labelledby="transport-heading">
          <h2 id="transport-heading" className="text-title font-semibold">
            Transport
          </h2>
          <p className="mt-3 text-sm font-medium">{transport.label}</p>
          <p className="mt-1 text-sm text-muted-foreground">{transport.detail}</p>
          {transport.warning && <p className="mt-2 text-sm font-medium text-status-warning">{transport.warning}</p>}
        </section>

        <section className="ui-panel p-comfortable" aria-labelledby="auth-heading">
          <h2 id="auth-heading" className="text-title font-semibold">
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
            OIDC mapping status and API-token administration are shown in Access administration below. This card only reflects the browser session and CSRF posture.
          </p>
        </section>
      </div>

      <section aria-labelledby="access-heading">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h2 id="access-heading" className="text-title font-semibold">
            Access administration
          </h2>
          <Button type="button" size="sm" variant="outline" onClick={() => void loadAccessAdmin()} disabled={accessLoading}>
            {accessLoading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
            Refresh
          </Button>
        </div>
        {accessError && <p role="alert" className="mb-3 rounded-control border border-status-danger/30 bg-status-danger/10 px-3 py-2 text-sm text-status-danger">{accessError}</p>}
        {accessNotice && <p role="status" className="mb-3 rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">{accessNotice}</p>}
        {revealedToken && (
          <div className="mb-3 rounded-panel border border-status-warning/40 bg-status-warning/10 p-3 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-medium">Reveal-once API token</p>
              <Button type="button" size="sm" variant="ghost" onClick={() => setRevealedToken(null)}>
                Dismiss
              </Button>
            </div>
            <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{revealedToken}</code>
          </div>
        )}
        <div className="mb-4 grid gap-3 xl:grid-cols-3">
          <form onSubmit={(event) => void onboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-status-success" aria-hidden="true" />
              <h3 className="text-body font-semibold">Onboard member</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={memberSubject} onChange={(event) => setMemberSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Display name</span>
              <input className="ui-input" value={memberDisplayName} onChange={(event) => setMemberDisplayName(event.target.value)} />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Email</span>
              <input className="ui-input" value={memberEmail} onChange={(event) => setMemberEmail(event.target.value)} />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Roles</span>
              <input className="ui-input" value={memberRoles} onChange={(event) => setMemberRoles(event.target.value)} required />
            </label>
            <Button type="submit" disabled={accessBusy || !memberSubject.trim()}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              Save
            </Button>
          </form>
          <form onSubmit={(event) => void mintToken(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-status-warning" aria-hidden="true" />
              <h3 className="text-body font-semibold">Mint API token</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={tokenSubject} onChange={(event) => setTokenSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Scopes</span>
              <input className="ui-input" value={tokenScopes} onChange={(event) => setTokenScopes(event.target.value)} required />
            </label>
            <Button type="submit" disabled={accessBusy || !tokenSubject.trim()}>
              <KeyRound className="h-4 w-4" aria-hidden="true" />
              Mint
            </Button>
          </form>
          <form onSubmit={(event) => void offboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <UserMinus className="h-4 w-4 text-status-danger" aria-hidden="true" />
              <h3 className="text-body font-semibold">Offboard member</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={offboardSubject} onChange={(event) => setOffboardSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Reason</span>
              <input className="ui-input" value={offboardReason} onChange={(event) => setOffboardReason(event.target.value)} />
            </label>
            <Button type="submit" variant="outline" className="text-status-danger" disabled={accessBusy || !offboardSubject.trim()}>
              <UserMinus className="h-4 w-4" aria-hidden="true" />
              Offboard
            </Button>
          </form>
        </div>
        <div className="mb-4 grid gap-4 xl:grid-cols-2">
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[34rem]">
              <caption className="sr-only">Served role catalog</caption>
              <thead>
                <tr>
                  <th scope="col">Role</th>
                  <th scope="col">Permissions</th>
                </tr>
              </thead>
              <tbody>
                {roleRows.map((role) => (
                  <tr key={role.name} className="align-top">
                    <td className="font-medium">{role.name}</td>
                    <td className="font-mono text-xs">{role.permissions.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="ui-panel p-comfortable text-sm">
            <h3 className="font-semibold">OIDC mapping status</h3>
            <dl className="mt-3 grid gap-2">
              <div>
                <dt className="font-medium text-muted-foreground">Enabled</dt>
                <dd>{oidc?.enabled ? "yes" : "no"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Claims</dt>
                <dd>{[oidc?.tenant_claim || "no tenant claim", oidc?.groups_claim || "no groups claim"].join(" · ")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Mappings</dt>
                <dd>{oidc?.tenant_mappings?.length ? oidc.tenant_mappings.map((m) => m.group || m.subject || m.claim).join(", ") : "none served"}</dd>
              </div>
            </dl>
          </div>
        </div>
        <div className="mb-4 grid gap-4 xl:grid-cols-2">
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[44rem]">
              <caption className="sr-only">Tenant members</caption>
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Roles</th>
                  <th scope="col">Status</th>
                  <th scope="col">Updated</th>
                </tr>
              </thead>
              <tbody>
                {members.map((member) => (
                  <tr key={member.subject} className="align-top">
                    <td className="font-medium">{member.subject}</td>
                    <td className="font-mono text-xs">{member.roles.join(", ")}</td>
                    <td>{member.status}</td>
                    <td>{formatDate(member.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[48rem]">
              <caption className="sr-only">API token metadata</caption>
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Scopes</th>
                  <th scope="col">Status</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((token) => (
                  <tr key={token.id} className="align-top">
                    <td className="font-medium">{token.subject}</td>
                    <td className="font-mono text-xs">{token.scopes.join(", ")}</td>
                    <td>{token.revoked_at ? "revoked" : "active"}</td>
                    <td>{formatDate(token.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <table className="ui-table">
          <caption className="sr-only">Required permission scopes by feature</caption>
          <thead>
            <tr>
              <th scope="col">Feature</th>
              <th scope="col">Required scope</th>
              <th scope="col">Route</th>
              <th scope="col">Denied-action copy</th>
            </tr>
          </thead>
          <tbody>
            {requiredScopes.map((item) => (
              <tr key={item.scope} className="align-top">
                <td>{item.feature}</td>
                <td className="font-mono text-xs">{item.scope}</td>
                <td>{item.route}</td>
                <td>{item.denial}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section aria-labelledby="api-spec-heading">
        <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="api-spec-heading" className="text-title font-semibold">
              Static API spec view
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {staticAPIRoutes.length} served REST paths copied from the pinned OpenAPI golden. This is a static spec view until a live `/api/v1/openapi.json` is published.
            </p>
          </div>
          <span className="rounded-control border border-border bg-muted px-2 py-1 text-caption font-medium text-muted-foreground">Spec view</span>
        </div>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[60rem]">
            <caption className="sr-only">Static served REST API paths</caption>
            <thead>
              <tr>
                <th scope="col">Group</th>
                <th scope="col">Methods</th>
                <th scope="col">Path</th>
                <th scope="col">Auth mode</th>
                <th scope="col">Curl</th>
              </tr>
            </thead>
            <tbody>
              {staticAPIRoutes.map((route) => (
                <tr key={route.path} className="align-top">
                  <td>{route.group}</td>
                  <td className="font-mono text-xs">{route.methods.join(", ")}</td>
                  <td className="font-mono text-xs">{route.path}</td>
                  <td>{route.auth}</td>
                  <td>
                    <div className="flex flex-wrap items-center gap-2">
                      <code className="max-w-md break-all rounded bg-muted px-2 py-1 text-xs">{curlFor(route)}</code>
                      <Button type="button" size="sm" variant="outline" onClick={() => void copyCurl(route)}>
                        <Copy className="h-4 w-4" aria-hidden="true" />
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
          <h2 id="cli-heading" className="text-title font-semibold">
            CLI companion
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            These commands mirror served API paths and assume `TRSTCTL_TOKEN` is already set in the shell. The browser never renders bearer token values, and the examples avoid inline Authorization headers.
          </p>
        </div>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[66rem]">
            <caption className="sr-only">CLI companion commands</caption>
            <thead>
              <tr>
                <th scope="col">Context</th>
                <th scope="col">Token-safe command</th>
                <th scope="col">Parity note</th>
              </tr>
            </thead>
            <tbody>
              {cliCommands.map((row) => (
                <tr key={row.context} className="align-top">
                  <td className="font-medium">{row.context}</td>
                  <td className="font-mono text-xs">{row.command}</td>
                  <td>{row.parity}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="runtime-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="runtime-heading" className="text-title font-semibold">
            Single-binary runtime
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Single-binary evaluation mode still keeps private-key operations in a separate signer child process. A real system page needs version, build info, embedded-UI asset, run mode, datastore mode, and signer supervision from a served status read.
          </p>
        </div>
        <UnavailableState title="Runtime status JSON not served yet">
          Binary version, build metadata, embedded UI asset version, datastore mode, run mode, and signer child supervision aren't shown in the console yet, so this page can't show live runtime state.
        </UnavailableState>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[58rem]">
            <caption className="sr-only">Single-binary runtime status fixtures</caption>
            <thead>
              <tr>
                <th scope="col">Field</th>
                <th scope="col">Console visibility</th>
                <th scope="col">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {runtimeRows.map((row) => (
                <tr key={row.field} className="align-top">
                  <td className="font-medium">{row.field}</td>
                  <td>{row.visible}</td>
                  <td>{row.meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="surfaces-heading">
        <h2 id="surfaces-heading" className="mb-3 text-title font-semibold">
          Registered real surfaces
        </h2>
        <table className="ui-table">
          <caption className="sr-only">Real GUI route registry</caption>
          <thead>
            <tr>
              <th scope="col">Feature</th>
              <th scope="col">Routes</th>
              <th scope="col">Kind</th>
              <th scope="col">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {nonLedgerSurfaces.map((surface) => (
              <tr key={surface.featureId} className="align-top">
                <td className="font-mono text-xs">{surface.featureId}</td>
                <td>{surface.routes.join(", ")}</td>
                <td>{surface.kind}</td>
                <td>{surface.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section aria-labelledby="plugin-admin-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="plugin-admin-heading" className="text-title font-semibold">
            Plugin SDK and capability sandbox
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Plugin administration needs loaded-plugin inventory, Ed25519 provenance, digest pins, capability grants, conformance results, runtime status, and denial reasons. The plugin host exists, but the console has no served read API for those records yet.
          </p>
        </div>
        <UnavailableState title="Plugin admin read API not served yet">
          The plugin runtime is served, but plugin administration is not. Tenant-scoped plugin inventory, verification receipts, grants, conformance results, runtime state, and denial reasons have no served API or CLI management surface yet.
        </UnavailableState>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[72rem]">
            <caption className="sr-only">Plugin SDK capability sandbox fixtures</caption>
            <thead>
              <tr>
                <th scope="col">Plugin</th>
                <th scope="col">Provenance</th>
                <th scope="col">Capability grants</th>
                <th scope="col">Conformance</th>
                <th scope="col">Runtime status</th>
              </tr>
            </thead>
            <tbody>
              {pluginAdminRows.map((row) => (
                <tr key={row.plugin} className="align-top">
                  <td className="font-mono text-xs">{row.plugin}</td>
                  <td>{row.provenance}</td>
                  <td className="font-mono text-xs">{row.grants}</td>
                  <td>{row.conformance}</td>
                  <td>{row.runtime}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="federation-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="federation-heading" className="text-title font-semibold">
            Cross-cluster federation roadmap
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Cross-cluster and multi-region federation is roadmap-only. The console must not claim topology, replication, conflict handling, or tenant placement is available until a backend exists.
          </p>
        </div>
        <UnavailableState title="Federation is roadmap-only">
          Cross-cluster federation is on the roadmap and has no served endpoint today. This page is a non-interactive roadmap disclosure, not an availability or replication status panel.
        </UnavailableState>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[52rem]">
            <caption className="sr-only">Federation roadmap fixtures</caption>
            <thead>
              <tr>
                <th scope="col">Topic</th>
                <th scope="col">State</th>
                <th scope="col">Caveat</th>
              </tr>
            </thead>
            <tbody>
              {federationRows.map((row) => (
                <tr key={row.topic} className="align-top">
                  <td className="font-medium">{row.topic}</td>
                  <td>{row.state}</td>
                  <td>{row.caveat}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="grid gap-3 lg:grid-cols-3">
        <UnavailableState title="Tenant switching not served yet">
          Member, role, OIDC mapping, and API-token administration are served above. Tenant list, tenant switching, and per-tenant limits are still fixed by the backend session tenant.
        </UnavailableState>
        <UnavailableState title="Platform status endpoint not served yet">
          Build info, datastore mode, signer-child state, OIDC config, and feature flags aren't shown in the console yet.
        </UnavailableState>
        <UnavailableState title="Live OpenAPI endpoint not served yet">
          Runtime OpenAPI publication isn't available yet; the table above is a static spec view from the pinned golden.
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

function csvList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatDate(value?: string): string {
  if (!value) return "-";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return value;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}
