// SPDX-License-Identifier: BUSL-1.1

package cli

// Commands for API routes that only a licensed server serves.
//
// Why this is a separate file. PACKAGING-007 keeps PQC out of the MPL core so
// the open-core boundary is real: a Community build must not carry the
// proprietary migration engine. The CLI is a thin HTTP client — these entries
// are route strings and help text, not an implementation, and the same request
// can be made with curl against the same server. But the rule is enforced
// per-file, so naming these routes inside command.go would have exempted that
// whole 400-line table from the check and let real PQC code slip in later
// unnoticed. Isolating them here keeps the exemption to a file that holds
// nothing but a route list, and leaves command.go fully covered.
//
// Against an unlicensed server these routes return 404, which is the honest
// answer for a feature the edition does not serve — the CLI does not pretend to
// know the server's edition ahead of the call.
var licensedRouteCommands = []Command{
	{Name: []string{"ca", "keys", "retire"}, Method: "POST", Path: "/api/v1/ca/keys/{id}/retirement", Body: bodyFile, Summary: "Irreversibly retire a superseded CA key through the isolated signer and retain its signed destruction record"},
	{Name: []string{"migration", "plan"}, Method: "POST", Path: "/api/v1/pqc/migrations/plan", Body: bodyFile, Summary: "Preview a crypto-migration plan without queueing it"},
	{Name: []string{"migration", "start"}, Method: "POST", Path: "/api/v1/pqc/migrations", Body: bodyFile, Summary: "Start a licensed crypto-migration run over CBOM findings"},
	{Name: []string{"migration", "status"}, Method: "GET", Path: "/api/v1/pqc/migrations/{run_id}", Summary: "Show migration run progress"},
	{Name: []string{"migration", "rollback"}, Method: "POST", Path: "/api/v1/pqc/migrations/{run_id}/rollback", Body: bodyOptionalFile, Summary: "Roll back a migration run"},
}
