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
	{Name: []string{"ca", "keys", "retire"}, Method: "POST", Path: "/api/v1/ca/keys/{id}/retirement", Body: bodyFile, Summary: "Irreversibly retire a superseded CA key through the isolated signer and retain its signed destruction record"},
	{Name: []string{"migration", "plan"}, Method: "POST", Path: "/api/v1/pqc/migrations/plan", Body: bodyFile, Summary: "Preview a crypto-migration plan without queueing it"},
	{Name: []string{"migration", "start"}, Method: "POST", Path: "/api/v1/pqc/migrations", Body: bodyFile, Summary: "Start a Core PQC migration run over selected CBOM assets"},
	{Name: []string{"migration", "status"}, Method: "GET", Path: "/api/v1/pqc/migrations/{run_id}", Summary: "Show migration run progress"},
	{Name: []string{"migration", "rollback"}, Method: "POST", Path: "/api/v1/pqc/migrations/{run_id}/rollback", Body: bodyFile, Summary: "Roll back selected assets in a PQC migration run"},
}
