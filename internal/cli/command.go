package cli

import "strings"

// bodyMode says where a command's request body comes from.
type bodyMode int

const (
	bodyNone   bodyMode = iota // no request body
	bodyFile                   // JSON body from -f <file> (or -f - for stdin)
	bodyCypher                 // positional argument(s) wrapped as {"query": ...}
)

// Command maps a CLI invocation to one API operation, so the command set is
// data-driven and provably at parity with the API route table.
type Command struct {
	Name    []string // command words, e.g. ["certificates","list"]
	Method  string   // HTTP method
	Path    string   // API path template, with {param} placeholders
	Query   []string // accepted query-parameter flag names
	Body    bodyMode
	Summary string
}

// Destructive reports whether the command can remove, revoke, erase, zeroize,
// offboard, or otherwise run irreversible/destructive work and therefore needs
// an explicit --force acknowledgement in the CLI.
func (c Command) Destructive() bool {
	if c.Method == "DELETE" {
		return true
	}
	name := strings.Join(c.Name, " ")
	for _, marker := range []string{
		"bulk-revoke",
		"delete",
		"erase",
		"managed-keys rotate",
		"offboard",
		"recover",
		"retention run",
		"revoke",
		"zeroize",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// commandTable is one command per core API operation (S3.3 surface).
var commandTable = []Command{
	{Name: []string{"owners", "create"}, Method: "POST", Path: "/api/v1/owners", Body: bodyFile, Summary: "Create an owner"},
	{Name: []string{"owners", "list"}, Method: "GET", Path: "/api/v1/owners", Query: []string{"limit", "cursor"}, Summary: "List owners"},
	{Name: []string{"owners", "get"}, Method: "GET", Path: "/api/v1/owners/{id}", Summary: "Get an owner"},
	{Name: []string{"owners", "update"}, Method: "PUT", Path: "/api/v1/owners/{id}", Body: bodyFile, Summary: "Replace an owner"},
	{Name: []string{"owners", "delete"}, Method: "DELETE", Path: "/api/v1/owners/{id}", Summary: "Delete an owner"},

	{Name: []string{"issuers", "create"}, Method: "POST", Path: "/api/v1/issuers", Body: bodyFile, Summary: "Create an issuer"},
	{Name: []string{"issuers", "list"}, Method: "GET", Path: "/api/v1/issuers", Query: []string{"limit", "cursor"}, Summary: "List issuers"},
	{Name: []string{"issuers", "get"}, Method: "GET", Path: "/api/v1/issuers/{id}", Summary: "Get an issuer"},

	{Name: []string{"ca", "ceremonies", "start"}, Method: "POST", Path: "/api/v1/ca/ceremonies", Body: bodyFile, Summary: "Start an m-of-n CA key ceremony"},
	{Name: []string{"ca", "ceremonies", "get"}, Method: "GET", Path: "/api/v1/ca/ceremonies/{id}", Summary: "Get a CA key ceremony"},
	{Name: []string{"ca", "ceremonies", "approve"}, Method: "POST", Path: "/api/v1/ca/ceremonies/{id}/approvals", Body: bodyNone, Summary: "Approve a CA key ceremony"},
	{Name: []string{"ca", "authorities", "list"}, Method: "GET", Path: "/api/v1/ca/authorities", Summary: "List private CA authorities"},
	{Name: []string{"ca", "authorities", "create-root"}, Method: "POST", Path: "/api/v1/ca/authorities/roots", Body: bodyFile, Summary: "Create a signer-backed root CA after ceremony quorum"},
	{Name: []string{"ca", "authorities", "create-intermediate"}, Method: "POST", Path: "/api/v1/ca/authorities/intermediates", Body: bodyFile, Summary: "Create a signer-backed intermediate CA after ceremony quorum"},
	{Name: []string{"ca", "authorities", "issue-intermediate-csr"}, Method: "POST", Path: "/api/v1/ca/authorities/{id}/intermediates/csr", Body: bodyFile, Summary: "Sign an external intermediate CA CSR from a private CA authority"},
	{Name: []string{"ca", "authorities", "issue"}, Method: "POST", Path: "/api/v1/ca/authorities/{id}/issue", Body: bodyFile, Summary: "Issue a leaf certificate from a private CA authority"},
	{Name: []string{"external-cas", "list"}, Method: "GET", Path: "/api/v1/external-cas", Summary: "List configured upstream CA integrations"},
	{Name: []string{"external-cas", "issue"}, Method: "POST", Path: "/api/v1/external-cas/{id}/issue", Body: bodyFile, Summary: "Issue a certificate through an upstream CA integration"},

	{Name: []string{"identities", "create"}, Method: "POST", Path: "/api/v1/identities", Body: bodyFile, Summary: "Create an identity"},
	{Name: []string{"identities", "list"}, Method: "GET", Path: "/api/v1/identities", Query: []string{"limit", "cursor"}, Summary: "List identities"},
	{Name: []string{"identities", "get"}, Method: "GET", Path: "/api/v1/identities/{id}", Summary: "Get an identity"},
	{Name: []string{"identities", "transition"}, Method: "POST", Path: "/api/v1/identities/{id}/transitions", Body: bodyFile, Summary: "Apply a lifecycle transition"},
	{Name: []string{"identities", "approve"}, Method: "POST", Path: "/api/v1/identities/{id}/approvals", Body: bodyFile, Summary: "Approve a dual-control issuance transition (distinct approver)"},
	{Name: []string{"identities", "bulk-revoke"}, Method: "POST", Path: "/api/v1/identities/bulk-revoke", Body: bodyFile, Summary: "Bulk revoke identities by id or criteria"},

	{Name: []string{"certificates", "ingest"}, Method: "POST", Path: "/api/v1/certificates", Body: bodyFile, Summary: "Ingest a certificate"},
	{Name: []string{"certificates", "list"}, Method: "GET", Path: "/api/v1/certificates", Query: []string{"limit", "cursor", "expiring_before"}, Summary: "Query the certificate inventory"},
	{Name: []string{"certificates", "get"}, Method: "GET", Path: "/api/v1/certificates/{id}", Summary: "Get an inventoried certificate"},
	{Name: []string{"certificates", "bulk-revoke"}, Method: "POST", Path: "/api/v1/certificates/bulk-revoke", Body: bodyFile, Summary: "Bulk revoke certificate identities by id or criteria"},

	{Name: []string{"workloads", "attested-issuance"}, Method: "POST", Path: "/api/v1/workloads/attested-issuance", Body: bodyFile, Summary: "Issue an attested X.509-SVID"},
	{Name: []string{"broker", "agent-identities", "issue"}, Method: "POST", Path: "/api/v1/broker/agent-identities", Body: bodyFile, Summary: "Issue a policy-gated AI/MCP agent identity"},
	{Name: []string{"ephemeral", "issue"}, Method: "POST", Path: "/api/v1/ephemeral", Body: bodyFile, Summary: "Open or complete an approval-gated JIT credential request"},
	{Name: []string{"ephemeral", "api-keys", "issue"}, Method: "POST", Path: "/api/v1/ephemeral/api-keys", Body: bodyFile, Summary: "Mint a short-TTL API key"},
	{Name: []string{"ephemeral", "approve"}, Method: "POST", Path: "/api/v1/ephemeral/{id}/approvals", Body: bodyFile, Summary: "Approve an ephemeral JIT credential request"},

	{Name: []string{"discovery", "sources", "create"}, Method: "POST", Path: "/api/v1/discovery/sources", Body: bodyFile, Summary: "Create a discovery source"},
	{Name: []string{"discovery", "sources", "list"}, Method: "GET", Path: "/api/v1/discovery/sources", Query: []string{"limit", "cursor"}, Summary: "List discovery sources"},
	{Name: []string{"discovery", "schedules", "create"}, Method: "POST", Path: "/api/v1/discovery/schedules", Body: bodyFile, Summary: "Create a discovery schedule"},
	{Name: []string{"discovery", "schedules", "list"}, Method: "GET", Path: "/api/v1/discovery/schedules", Query: []string{"limit", "cursor"}, Summary: "List discovery schedules"},
	{Name: []string{"discovery", "runs", "start"}, Method: "POST", Path: "/api/v1/discovery/runs", Body: bodyFile, Summary: "Start a discovery run"},
	{Name: []string{"discovery", "runs", "list"}, Method: "GET", Path: "/api/v1/discovery/runs", Query: []string{"limit", "cursor"}, Summary: "List discovery runs"},
	{Name: []string{"discovery", "runs", "get"}, Method: "GET", Path: "/api/v1/discovery/runs/{id}", Summary: "Get a discovery run"},
	{Name: []string{"discovery", "findings", "list"}, Method: "GET", Path: "/api/v1/discovery/findings", Query: []string{"limit", "cursor", "run_id"}, Summary: "List discovery findings"},
	{Name: []string{"discovery", "findings", "claim"}, Method: "POST", Path: "/api/v1/discovery/findings/{id}/claim", Body: bodyFile, Summary: "Claim a discovery finding as managed"},
	{Name: []string{"discovery", "findings", "dismiss"}, Method: "POST", Path: "/api/v1/discovery/findings/{id}/dismiss", Body: bodyFile, Summary: "Dismiss a discovery finding"},

	{Name: []string{"connectors", "catalog"}, Method: "GET", Path: "/api/v1/connectors/catalog", Summary: "List connector kinds"},
	{Name: []string{"connectors", "outbox-circuits"}, Method: "GET", Path: "/api/v1/connectors/outbox-circuits", Summary: "List outbox destination circuit breaker state"},
	{Name: []string{"notifications", "list"}, Method: "GET", Path: "/api/v1/notifications", Query: []string{"limit", "cursor", "status"}, Summary: "List notification inbox and dead-letter rows"},
	{Name: []string{"notifications", "get"}, Method: "GET", Path: "/api/v1/notifications/{id}", Summary: "Get a notification inbox row"},
	{Name: []string{"notifications", "read"}, Method: "POST", Path: "/api/v1/notifications/{id}/read", Summary: "Mark a notification as read"},
	{Name: []string{"notifications", "requeue"}, Method: "POST", Path: "/api/v1/notifications/{id}/requeue", Summary: "Requeue a dead-lettered notification dispatch"},
	{Name: []string{"connectors", "deliveries", "list"}, Method: "GET", Path: "/api/v1/connectors/deliveries", Query: []string{"limit", "cursor", "identity_id"}, Summary: "List connector delivery receipts"},
	{Name: []string{"connectors", "deliveries", "get"}, Method: "GET", Path: "/api/v1/connectors/deliveries/{id}", Summary: "Get a connector delivery receipt"},
	{Name: []string{"lifecycle", "rotation-runs", "list"}, Method: "GET", Path: "/api/v1/lifecycle/rotation-runs", Query: []string{"limit", "cursor", "identity_id"}, Summary: "List lifecycle rotation runs"},
	{Name: []string{"lifecycle", "rotation-runs", "get"}, Method: "GET", Path: "/api/v1/lifecycle/rotation-runs/{id}", Summary: "Get a lifecycle rotation run"},

	{Name: []string{"incidents", "executions", "execute"}, Method: "POST", Path: "/api/v1/incidents/executions", Body: bodyFile, Summary: "Execute credential-compromise remediation"},
	{Name: []string{"incidents", "executions", "list"}, Method: "GET", Path: "/api/v1/incidents/executions", Query: []string{"limit", "cursor", "identity_id"}, Summary: "List incident execution evidence packs"},
	{Name: []string{"incidents", "executions", "get"}, Method: "GET", Path: "/api/v1/incidents/executions/{id}", Summary: "Get an incident execution evidence pack"},
	{Name: []string{"itsm", "servicenow", "tickets", "create"}, Method: "POST", Path: "/api/v1/itsm/servicenow/tickets", Body: bodyFile, Summary: "Queue a ServiceNow ITSM ticket through the outbox"},
	{Name: []string{"breakglass", "reconcile"}, Method: "POST", Path: "/api/v1/breakglass/reconcile", Body: bodyFile, Summary: "Reconcile signed offline break-glass bundles into audit"},

	{Name: []string{"editions", "status"}, Method: "GET", Path: "/api/v1/editions", Summary: "Show edition, license, and FIPS posture"},
	{Name: []string{"support", "enterprise"}, Method: "GET", Path: "/api/v1/support/enterprise", Summary: "Show enterprise support, SLA, and services posture"},
	{Name: []string{"managed-offering", "status"}, Method: "GET", Path: "/api/v1/managed-offering/status", Summary: "Show managed offering and provider-plane posture"},
	{Name: []string{"managed-offering", "tenants", "provision"}, Method: "POST", Path: "/api/v1/managed-offering/tenants", Body: bodyFile, Summary: "Provision a hosted tenant in the managed offering"},

	{Name: []string{"access", "roles"}, Method: "GET", Path: "/api/v1/access/roles", Summary: "List access roles and scopes"},
	{Name: []string{"access", "oidc-mapping"}, Method: "GET", Path: "/api/v1/access/oidc-mapping", Summary: "Show OIDC tenant and group mapping status"},
	{Name: []string{"access", "members", "list"}, Method: "GET", Path: "/api/v1/access/members", Query: []string{"limit", "cursor", "include_offboarded"}, Summary: "List tenant members"},
	{Name: []string{"access", "members", "upsert"}, Method: "PUT", Path: "/api/v1/access/members/{subject}", Body: bodyFile, Summary: "Onboard or update a tenant member"},
	{Name: []string{"access", "members", "offboard"}, Method: "POST", Path: "/api/v1/access/members/{subject}/offboard", Body: bodyFile, Summary: "Offboard a tenant member and revoke their API tokens"},
	{Name: []string{"access", "tokens", "list"}, Method: "GET", Path: "/api/v1/access/api-tokens", Query: []string{"limit", "cursor", "subject", "include_revoked"}, Summary: "List API token metadata"},
	{Name: []string{"access", "tokens", "create"}, Method: "POST", Path: "/api/v1/access/api-tokens", Body: bodyFile, Summary: "Mint a member API token"},
	{Name: []string{"access", "tokens", "revoke"}, Method: "DELETE", Path: "/api/v1/access/api-tokens/{id}", Summary: "Revoke an API token"},
	{Name: []string{"access", "sessions", "list"}, Method: "GET", Path: "/api/v1/access/sessions", Query: []string{"limit", "cursor"}, Summary: "List just-in-time privileged access sessions"},
	{Name: []string{"access", "sessions", "open"}, Method: "POST", Path: "/api/v1/access/sessions", Body: bodyFile, Summary: "Open a just-in-time privileged access session"},
	{Name: []string{"access", "sessions", "get"}, Method: "GET", Path: "/api/v1/access/sessions/{id}", Summary: "Get a privileged access session"},
	{Name: []string{"access", "reviews", "start"}, Method: "POST", Path: "/api/v1/access/reviews", Body: bodyFile, Summary: "Start an NHI access certification campaign"},
	{Name: []string{"access", "reviews", "list"}, Method: "GET", Path: "/api/v1/access/reviews", Query: []string{"limit", "cursor"}, Summary: "List NHI access certification campaigns"},
	{Name: []string{"access", "reviews", "get"}, Method: "GET", Path: "/api/v1/access/reviews/{id}", Summary: "Get an NHI access certification campaign"},
	{Name: []string{"access", "reviews", "decide"}, Method: "POST", Path: "/api/v1/access/reviews/{id}/items/{item_id}/decision", Body: bodyFile, Summary: "Record an NHI access-review item decision"},

	{Name: []string{"profiles", "create"}, Method: "POST", Path: "/api/v1/profiles", Body: bodyFile, Summary: "Create a certificate profile version"},
	{Name: []string{"profiles", "list"}, Method: "GET", Path: "/api/v1/profiles", Summary: "List active certificate profiles"},
	{Name: []string{"profiles", "get-version"}, Method: "GET", Path: "/api/v1/profiles/{name}/versions/{version}", Summary: "Get a certificate-profile version"},

	{Name: []string{"audit", "events"}, Method: "GET", Path: "/api/v1/audit/events", Query: []string{"type", "since", "until", "as_of", "q", "limit"}, Summary: "Query the audit log"},
	{Name: []string{"audit", "export"}, Method: "GET", Path: "/api/v1/audit/export", Query: []string{"type", "since", "until", "as_of", "q", "limit"}, Summary: "Export a signed audit bundle"},
	{Name: []string{"compliance", "evidence-pack"}, Method: "GET", Path: "/api/v1/compliance/evidence-packs/{framework}", Summary: "Export a signed compliance evidence pack"},

	{Name: []string{"privacy", "erasures", "erase"}, Method: "POST", Path: "/api/v1/privacy/subject-erasures", Body: bodyFile, Summary: "Erase direct subject personal data"},
	{Name: []string{"privacy", "erasures", "list"}, Method: "GET", Path: "/api/v1/privacy/subject-erasures", Query: []string{"limit", "cursor"}, Summary: "List subject-erasure evidence"},
	{Name: []string{"privacy", "retention", "run"}, Method: "POST", Path: "/api/v1/privacy/retention-runs", Body: bodyNone, Summary: "Run non-audit personal-data retention"},
	{Name: []string{"privacy", "retention", "list"}, Method: "GET", Path: "/api/v1/privacy/retention-runs", Query: []string{"limit", "cursor"}, Summary: "List retention evidence"},
	{Name: []string{"privacy", "export"}, Method: "POST", Path: "/api/v1/privacy/subject-exports", Body: bodyFile, Summary: "Export all records tied to a data subject"},
	{Name: []string{"privacy", "catalog"}, Method: "GET", Path: "/api/v1/privacy/catalog", Summary: "Get the personal-data catalog"},

	{Name: []string{"graph", "nodes"}, Method: "GET", Path: "/api/v1/graph", Summary: "Get the credential graph"},
	{Name: []string{"graph", "reachable"}, Method: "GET", Path: "/api/v1/graph/reachable/{id}", Summary: "Nodes reachable from a node"},
	{Name: []string{"graph", "blast-radius"}, Method: "GET", Path: "/api/v1/graph/blast-radius/{id}", Summary: "Blast radius of a node"},
	{Name: []string{"graph", "query"}, Method: "POST", Path: "/api/v1/graph/query", Body: bodyCypher, Summary: "Run a Cypher-style query"},

	{Name: []string{"risk", "credentials"}, Method: "GET", Path: "/api/v1/risk/credentials", Query: []string{"sort", "min_score", "privilege", "owner"}, Summary: "Rank credentials by risk score"},
	{Name: []string{"cbom", "scan"}, Method: "POST", Path: "/api/v1/cbom/scans", Body: bodyFile, Summary: "Scan TLS endpoints and host configs into the CBOM"},
	{Name: []string{"cbom", "assets"}, Method: "GET", Path: "/api/v1/cbom/assets", Summary: "List CBOM assets and PQC migration progress"},
	{Name: []string{"pqc", "migrations", "start"}, Method: "POST", Path: "/api/v1/pqc/migrations", Body: bodyFile, Summary: "Queue PQC re-issuance for CBOM assets"},
	{Name: []string{"pqc", "migrations", "rollback"}, Method: "POST", Path: "/api/v1/pqc/migrations/{run_id}/rollback", Body: bodyFile, Summary: "Queue rollback for a PQC migration run"},

	{Name: []string{"agents", "list"}, Method: "GET", Path: "/api/v1/agents", Summary: "List in-network agents"},
	{Name: []string{"agents", "enroll-token"}, Method: "POST", Path: "/api/v1/agents/enrollment-tokens", Body: bodyNone, Summary: "Mint a one-time agent bootstrap token"},
	{Name: []string{"agents", "revoke-cert"}, Method: "POST", Path: "/api/v1/agents/{id}/cert-revocations", Body: bodyFile, Summary: "Revoke an agent mTLS certificate"},

	// AI assistant + root-cause analysis (SURFACE-003).
	{Name: []string{"ai", "status"}, Method: "GET", Path: "/api/v1/ai/status", Summary: "Show AI runtime and model status"},
	{Name: []string{"ai", "query"}, Method: "POST", Path: "/api/v1/ai/query", Body: bodyFile, Summary: "Ask the AI assistant a question"},
	{Name: []string{"ai", "rca"}, Method: "POST", Path: "/api/v1/ai/rca", Body: bodyFile, Summary: "Run an AI root-cause analysis"},

	// MCP tool surface (SURFACE-003).
	{Name: []string{"mcp", "tools"}, Method: "GET", Path: "/api/v1/mcp/tools", Summary: "List the MCP tools the server exposes"},
	{Name: []string{"mcp", "call"}, Method: "POST", Path: "/api/v1/mcp/tools/{tool}", Body: bodyFile, Summary: "Invoke an MCP tool"},

	// Secret store, dynamic leases, secret sharing, and dynamic PKI secret (GAP-006).
	{Name: []string{"secrets", "login"}, Method: "POST", Path: "/api/v1/secrets/login", Body: bodyFile, Summary: "Exchange a machine credential for a workload session"},
	{Name: []string{"secrets", "store", "put"}, Method: "POST", Path: "/api/v1/secrets/store", Body: bodyFile, Summary: "Store a secret"},
	{Name: []string{"secrets", "store", "list"}, Method: "GET", Path: "/api/v1/secrets/store", Query: []string{"limit", "cursor"}, Summary: "List stored secrets"},
	{Name: []string{"secrets", "store", "import"}, Method: "POST", Path: "/api/v1/secrets/store/import", Body: bodyFile, Summary: "Import a tree of stored secrets"},
	{Name: []string{"secrets", "store", "get"}, Method: "GET", Path: "/api/v1/secrets/store/{name}", Query: []string{"resolve"}, Summary: "Get a stored secret"},
	{Name: []string{"secrets", "store", "history"}, Method: "GET", Path: "/api/v1/secrets/store/history/{name}", Query: []string{"version"}, Summary: "Get a historical stored-secret version"},
	{Name: []string{"secrets", "store", "recover"}, Method: "POST", Path: "/api/v1/secrets/store/recover/{name}", Body: bodyFile, Summary: "Recover a stored secret to a point in time"},
	{Name: []string{"secrets", "store", "update"}, Method: "PUT", Path: "/api/v1/secrets/store/{name}", Body: bodyFile, Summary: "Replace a stored secret"},
	{Name: []string{"secrets", "store", "delete"}, Method: "DELETE", Path: "/api/v1/secrets/store/{name}", Summary: "Delete a stored secret"},
	{Name: []string{"secrets", "approvals", "approve"}, Method: "POST", Path: "/api/v1/secrets/store/approvals/{name}", Body: bodyFile, Summary: "Approve a pending secret-store change"},
	{Name: []string{"secrets", "leases", "issue"}, Method: "POST", Path: "/api/v1/secrets/leases", Body: bodyFile, Summary: "Issue a dynamic secret lease"},
	{Name: []string{"secrets", "leases", "get"}, Method: "GET", Path: "/api/v1/secrets/leases/{lease_id}", Summary: "Get dynamic secret lease metadata"},
	{Name: []string{"secrets", "leases", "renew"}, Method: "POST", Path: "/api/v1/secrets/leases/{lease_id}/renew", Body: bodyFile, Summary: "Renew a dynamic secret lease"},
	{Name: []string{"secrets", "leases", "revoke"}, Method: "POST", Path: "/api/v1/secrets/leases/{lease_id}/revoke", Summary: "Revoke a dynamic secret lease"},
	{Name: []string{"secrets", "rotations", "run"}, Method: "POST", Path: "/api/v1/secrets/rotations", Body: bodyFile, Summary: "Run a rollback-safe static secret rotation"},
	{Name: []string{"secrets", "syncs", "run"}, Method: "POST", Path: "/api/v1/secrets/syncs", Body: bodyFile, Summary: "Push a stored secret to a configured external sync target"},
	{Name: []string{"secrets", "scans", "run"}, Method: "POST", Path: "/api/v1/secrets/scans", Body: bodyFile, Summary: "Run Gitleaks and record redacted scan findings"},
	{Name: []string{"secrets", "shares", "create"}, Method: "POST", Path: "/api/v1/secrets/shares", Body: bodyFile, Summary: "Create a secret share"},
	{Name: []string{"secrets", "shares", "redeem"}, Method: "POST", Path: "/api/v1/secrets/shares/redeem", Body: bodyFile, Summary: "Redeem a secret share"},
	{Name: []string{"secrets", "pki"}, Method: "POST", Path: "/api/v1/secrets/pki", Body: bodyFile, Summary: "Issue a dynamic PKI secret"},

	// Transit/EaaS served key operations (KMS-01/F66). These commands call fixed
	// compile-time Go handlers behind internal/crypto, matching prior-art adapter
	// shapes such as crypto.Signer / JCA / OpenSSL ENGINE without runtime provider
	// registration or policy-fed crypto-provider behavior.
	{Name: []string{"transit", "keys", "create"}, Method: "POST", Path: "/api/v1/transit/keys", Body: bodyFile, Summary: "Create a tenant-scoped transit key"},
	{Name: []string{"transit", "keys", "rotate"}, Method: "POST", Path: "/api/v1/transit/keys/rotate", Body: bodyFile, Summary: "Rotate a tenant-scoped transit key"},
	{Name: []string{"transit", "encrypt"}, Method: "POST", Path: "/api/v1/transit/encrypt", Body: bodyFile, Summary: "Encrypt plaintext with a transit key"},
	{Name: []string{"transit", "decrypt"}, Method: "POST", Path: "/api/v1/transit/decrypt", Body: bodyFile, Summary: "Decrypt transit ciphertext"},
	{Name: []string{"transit", "rewrap"}, Method: "POST", Path: "/api/v1/transit/rewrap", Body: bodyFile, Summary: "Re-encrypt transit ciphertext under the current key version"},
	{Name: []string{"transit", "hmac"}, Method: "POST", Path: "/api/v1/transit/hmac", Body: bodyFile, Summary: "Compute an HMAC with a transit key"},
	{Name: []string{"transit", "sign"}, Method: "POST", Path: "/api/v1/transit/sign", Body: bodyFile, Summary: "Sign a message with a transit signing key"},
	{Name: []string{"transit", "verify"}, Method: "POST", Path: "/api/v1/transit/verify", Body: bodyFile, Summary: "Verify a transit signature"},

	// Code-signing (CLM-06/F50). The served API signs artifact digests with a
	// managed key or a verified keyless identity, then queues Rekor transparency-log
	// publication through outbox.
	{Name: []string{"code-signing", "sign"}, Method: "POST", Path: "/api/v1/code-signing/sign", Body: bodyFile, Summary: "Sign an artifact digest with a managed code-signing key"},
	{Name: []string{"code-signing", "keyless"}, Method: "POST", Path: "/api/v1/code-signing/keyless", Body: bodyFile, Summary: "Sign an artifact digest with a verified Sigstore/Fulcio identity"},

	// BYOK/HSM managed-key lifecycle (CRYPTO-005). Generate mints provider-resident
	// material; rotate/revoke/zeroize are destructive and require a distinct-approver
	// approval (dual control) recorded out of band before the command succeeds.
	{Name: []string{"managed-keys", "generate"}, Method: "POST", Path: "/api/v1/managed-keys", Body: bodyFile, Summary: "Generate a BYOK/HSM-resident managed key"},
	{Name: []string{"managed-keys", "rotate"}, Method: "POST", Path: "/api/v1/managed-keys/rotate", Body: bodyFile, Summary: "Rotate a managed key (requires dual-control approval)"},
	{Name: []string{"managed-keys", "revoke"}, Method: "POST", Path: "/api/v1/managed-keys/revoke", Body: bodyFile, Summary: "Revoke a managed key at the provider (requires dual-control approval)"},
	{Name: []string{"managed-keys", "zeroize"}, Method: "POST", Path: "/api/v1/managed-keys/zeroize", Body: bodyFile, Summary: "Zeroize a managed key's material at the provider (requires dual-control approval)"},
}

var specialCommandTable = []Command{
	{Name: []string{"run"}, Summary: "Run a child process with fetched secrets injected into its environment"},
}

// Commands returns the CLI's command set.
func Commands() []Command {
	out := make([]Command, 0, len(commandTable)+len(specialCommandTable))
	out = append(out, commandTable...)
	out = append(out, specialCommandTable...)
	return out
}

// pathParams returns the {placeholder} names in the command's path, in order.
func (c Command) pathParams() []string {
	var out []string
	rest := c.Path
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			return out
		}
		closeIdx := strings.IndexByte(rest[open:], '}')
		if closeIdx < 0 {
			return out
		}
		out = append(out, rest[open+1:open+closeIdx])
		rest = rest[open+closeIdx+1:]
	}
}

// matchCommand finds the command whose name is the longest prefix of words, and
// returns the remaining (non-name) arguments.
func matchCommand(words []string) (Command, []string, bool) {
	best := -1
	var match Command
	for _, c := range commandTable {
		if len(c.Name) <= len(words) && hasPrefix(words, c.Name) && len(c.Name) > best {
			best = len(c.Name)
			match = c
		}
	}
	if best < 0 {
		return Command{}, nil, false
	}
	return match, words[best:], true
}

func hasPrefix(words, prefix []string) bool {
	for i, p := range prefix {
		if words[i] != p {
			return false
		}
	}
	return true
}
