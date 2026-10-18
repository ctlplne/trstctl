// SPDX-License-Identifier: BUSL-1.1

package cli

// Commands for API routes attached outside the static route table.
//
// Why this is a separate file. These routes are mounted by attach seams rather
// than the static route table (PQC migration attaches in every build since
// 2026-09-20; the others still by license), and the per-file rule that keeps
// command.go feature-neutral is worth keeping. The CLI is a thin HTTP client — these entries
// are route strings and help text, not an implementation, and the same request
// can be made with curl against the same server. But the rule is enforced
// per-file, so naming these routes inside command.go would have exempted that
// whole 400-line table from the check and let real PQC code slip in later
// unnoticed. Isolating them here keeps the exemption to a file that holds
// nothing but a route list, and leaves command.go fully covered.
//
// The PQC migration routes attach in Core. A commercial-only route returns 404
// when its edition is unavailable; the CLI uses the served contract rather than
// guessing the server's edition ahead of the call.
var licensedRouteCommands = []Command{
	{Name: []string{"agent-delegation", "roots", "register"}, Method: "POST", Path: "/api/v1/agent-delegation/root-anchors", Body: bodyFile, Summary: "Register an immutable tenant delegation root anchor; use a new key ID to rotate"},
	{Name: []string{"agent-delegation", "roots", "list"}, Method: "GET", Path: "/api/v1/agent-delegation/root-anchors", Summary: "List tenant delegation root anchors"},
	{Name: []string{"agent-delegation", "issue"}, Method: "POST", Path: "/api/v1/agent-delegation/issuances", Body: bodyFile, Summary: "Queue signer-gated issuance of a chain-bound agent credential"},
	{Name: []string{"agent-delegation", "issuance", "get"}, Method: "GET", Path: "/api/v1/agent-delegation/issuance", Query: []string{"issuance_id"}, RequiredQuery: []string{"issuance_id"}, Summary: "Follow an issuance receipt to the public credential ID"},
	{Name: []string{"agent-delegation", "revoke"}, Method: "POST", Path: "/api/v1/agent-delegation/revocations", Body: bodyFile, Summary: "Queue a cascaded delegation revocation; review the subject and use --force"},
	{Name: []string{"agent-delegation", "chain", "get"}, Method: "GET", Path: "/api/v1/agent-delegation/chain", Query: []string{"credential_id"}, RequiredQuery: []string{"credential_id"}, Summary: "Read the exact issued credential's delegation chain"},
	{Name: []string{"agent-delegation", "credential", "get"}, Method: "GET", Path: "/api/v1/agent-delegation/credential", Query: []string{"credential_id"}, RequiredQuery: []string{"credential_id"}, Summary: "Read an issued credential's public material"},
	{Name: []string{"agent-delegation", "revocations", "incomplete-jobs"}, Method: "GET", Path: "/api/v1/agent-delegation/revocations/incomplete-jobs", Query: []string{"directive_id"}, RequiredQuery: []string{"directive_id"}, Summary: "Read an exact directive's unfinished descendant jobs"},
	{Name: []string{"agent-delegation", "revocations", "evidence"}, Method: "GET", Path: "/api/v1/agent-delegation/revocations/evidence", Query: []string{"directive_id"}, RequiredQuery: []string{"directive_id"}, Summary: "Read an exact directive's aggregate revocation evidence"},
	{Name: []string{"pcas", "genesis", "register"}, Method: "POST", Path: "/api/v1/pcas/genesis", Body: bodyFile, Summary: "Register a tenant-scoped signer-held PCAS genesis key"},
	{Name: []string{"pcas", "requests", "status"}, Method: "GET", Path: "/api/v1/pcas/requests/{request_id}", Summary: "Show durable PCAS request and breadth-worker progress"},
	{Name: []string{"pcas", "recovery", "policy", "set"}, Method: "POST", Path: "/api/v1/pcas/recovery/policies", Body: bodyFile, Summary: "Set a tenant identity's public threshold-recovery policy"},
	{Name: []string{"pcas", "recovery", "policy", "get"}, Method: "GET", Path: "/api/v1/pcas/recovery/policies", Query: []string{"identity_id"}, RequiredQuery: []string{"identity_id"}, Summary: "Read the exact public recovery quorum enforced for an identity"},
	{Name: []string{"pcas", "recovery", "successor", "prepare"}, Method: "POST", Path: "/api/v1/pcas/recovery/successors/prepare", Body: bodyFile, Summary: "Prepare the exact signer-held public key before custodian approval"},
	{Name: []string{"pcas", "recovery", "successor", "get"}, Method: "GET", Path: "/api/v1/pcas/recovery/successors", Query: []string{"identity_id", "epoch"}, RequiredQuery: []string{"identity_id", "epoch"}, Summary: "Read the signed public successor receipt from isolated signer custody"},
	{Name: []string{"pcas", "recovery", "request"}, Method: "POST", Path: "/api/v1/pcas/recovery/requests", Body: bodyFile, Summary: "Queue signed threshold recovery under the configured policy"},
	{Name: []string{"pcas", "federation", "bridges", "list"}, Method: "GET", Path: "/api/v1/pcas/federation/bridges", Summary: "List only verified, signed foreign trust bridges"},
	{Name: []string{"pcas", "federation", "imports", "request"}, Method: "POST", Path: "/api/v1/pcas/federation/imports", Body: bodyFile, Summary: "Queue verification and signing of a foreign PCAS bridge"},
	{Name: []string{"pcas", "kem", "rewrap", "request"}, Method: "POST", Path: "/api/v1/pcas/kem/rewraps", Body: bodyFile, Summary: "Queue a tenant-bound signer-held KEM successor with named stages"},
	{Name: []string{"pcas", "rewrap", "status"}, Method: "GET", Path: "/api/v1/pcas/rewrap", Query: []string{"identity_id", "predecessor_epoch"}, RequiredQuery: []string{"identity_id"}, Summary: "Read KEM rewrap stage completion for an identity"},
	{Name: []string{"pcas", "issuers", "register"}, Method: "POST", Path: "/api/v1/pcas/issuers", Body: bodyFile, Summary: "Bind an active tenant-managed CA to its current PCAS epoch"},
	{Name: []string{"pcas", "issuers", "leaf", "issue"}, Method: "POST", Path: "/api/v1/pcas/issuers/leaf", Body: bodyFile, Summary: "Issue an issuer-epoch-bound X.509 leaf"},
	{Name: []string{"pcas", "staple", "leaf", "issue"}, Method: "POST", Path: "/api/v1/pcas/staple/leaf", Body: bodyFile, Summary: "Issue an X.509 leaf with a signed succession checkpoint attachment"},
	{Name: []string{"pcas", "delegation", "scopes", "list"}, Method: "GET", Path: "/api/v1/pcas/delegation/scopes", Summary: "Read tenant scopes with signer-signed applied receipts"},
	{Name: []string{"pcas", "delegation", "scopes", "set"}, Method: "POST", Path: "/api/v1/pcas/delegation/scopes", Body: bodyFile, Summary: "Queue a tenant scope with immutable parent and monotonic epoch floor"},
	{Name: []string{"pcas", "delegation", "floors", "raise"}, Method: "POST", Path: "/api/v1/pcas/delegation/floors", Body: bodyFile, Summary: "Queue a signer-enforced epoch-floor increase"},
	{Name: []string{"pcas", "succession", "request"}, Method: "POST", Path: "/api/v1/pcas/successions", Body: bodyFile, Summary: "Queue an algorithm succession after genesis is delivered"},
	{Name: []string{"pcas", "chain", "get"}, Method: "GET", Path: "/api/v1/pcas/chain", Query: []string{"identity_id"}, Summary: "Read the signed genesis and successor chain"},
	{Name: []string{"pcas", "checkpoints", "get"}, Method: "GET", Path: "/api/v1/pcas/checkpoints", Query: []string{"identity_id"}, Summary: "Read the latest signed epoch checkpoint and its historical signer public key"},
	{Name: []string{"pcas", "retirement", "show"}, Method: "GET", Path: "/api/v1/pcas/retirement", Query: []string{"identity_id", "predecessor_epoch"}, RequiredQuery: []string{"identity_id"}, Summary: "Read the predecessor epoch's relying-party acknowledgment policy and rewrap status"},
	{Name: []string{"pcas", "retirement", "policy", "set"}, Method: "POST", Path: "/api/v1/pcas/retirement/policies", Body: bodyFile, Summary: "Set the relying-party acknowledgment quorum for predecessor-key retirement"},
	{Name: []string{"ca", "keys", "retire"}, Method: "POST", Path: "/api/v1/ca/keys/{id}/retirement", Body: bodyFile, Summary: "Irreversibly retire a superseded CA key through the isolated signer and retain its signed destruction record"},
	{Name: []string{"migration", "plan"}, Method: "POST", Path: "/api/v1/pqc/migrations/plan", Body: bodyFile, Summary: "Preview a crypto-migration plan without queueing it"},
	{Name: []string{"migration", "start"}, Method: "POST", Path: "/api/v1/pqc/migrations", Body: bodyFile, Summary: "Start a Core PQC migration run over selected CBOM assets"},
	{Name: []string{"migration", "status"}, Method: "GET", Path: "/api/v1/pqc/migrations/{run_id}", Summary: "Show migration run progress"},
	{Name: []string{"migration", "rollback"}, Method: "POST", Path: "/api/v1/pqc/migrations/{run_id}/rollback", Body: bodyFile, Summary: "Roll back selected assets in a PQC migration run"},
}
