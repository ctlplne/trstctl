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

	{Name: []string{"identities", "create"}, Method: "POST", Path: "/api/v1/identities", Body: bodyFile, Summary: "Create an identity"},
	{Name: []string{"identities", "list"}, Method: "GET", Path: "/api/v1/identities", Query: []string{"limit", "cursor"}, Summary: "List identities"},
	{Name: []string{"identities", "get"}, Method: "GET", Path: "/api/v1/identities/{id}", Summary: "Get an identity"},
	{Name: []string{"identities", "transition"}, Method: "POST", Path: "/api/v1/identities/{id}/transitions", Body: bodyFile, Summary: "Apply a lifecycle transition"},
	{Name: []string{"identities", "approve"}, Method: "POST", Path: "/api/v1/identities/{id}/approvals", Body: bodyFile, Summary: "Approve a dual-control issuance transition (distinct approver)"},

	{Name: []string{"certificates", "ingest"}, Method: "POST", Path: "/api/v1/certificates", Body: bodyFile, Summary: "Ingest a certificate"},
	{Name: []string{"certificates", "list"}, Method: "GET", Path: "/api/v1/certificates", Query: []string{"limit", "cursor", "expiring_before"}, Summary: "Query the certificate inventory"},
	{Name: []string{"certificates", "get"}, Method: "GET", Path: "/api/v1/certificates/{id}", Summary: "Get an inventoried certificate"},

	{Name: []string{"profiles", "create"}, Method: "POST", Path: "/api/v1/profiles", Body: bodyFile, Summary: "Create a certificate profile version"},
	{Name: []string{"profiles", "list"}, Method: "GET", Path: "/api/v1/profiles", Summary: "List active certificate profiles"},
	{Name: []string{"profiles", "get-version"}, Method: "GET", Path: "/api/v1/profiles/{name}/versions/{version}", Summary: "Get a certificate-profile version"},

	{Name: []string{"audit", "events"}, Method: "GET", Path: "/api/v1/audit/events", Query: []string{"type", "since", "until", "as_of", "q", "limit"}, Summary: "Query the audit log"},
	{Name: []string{"audit", "export"}, Method: "GET", Path: "/api/v1/audit/export", Query: []string{"type", "since", "until", "as_of", "q", "limit"}, Summary: "Export a signed audit bundle"},

	{Name: []string{"graph", "nodes"}, Method: "GET", Path: "/api/v1/graph", Summary: "Get the credential graph"},
	{Name: []string{"graph", "reachable"}, Method: "GET", Path: "/api/v1/graph/reachable/{id}", Summary: "Nodes reachable from a node"},
	{Name: []string{"graph", "blast-radius"}, Method: "GET", Path: "/api/v1/graph/blast-radius/{id}", Summary: "Blast radius of a node"},
	{Name: []string{"graph", "query"}, Method: "POST", Path: "/api/v1/graph/query", Body: bodyCypher, Summary: "Run a Cypher-style query"},

	{Name: []string{"risk", "credentials"}, Method: "GET", Path: "/api/v1/risk/credentials", Query: []string{"sort", "min_score", "privilege", "owner"}, Summary: "Rank credentials by risk score"},

	{Name: []string{"agents", "list"}, Method: "GET", Path: "/api/v1/agents", Summary: "List in-network agents"},
	{Name: []string{"agents", "enroll-token"}, Method: "POST", Path: "/api/v1/agents/enrollment-tokens", Body: bodyNone, Summary: "Mint a one-time agent bootstrap token"},

	// AI assistant + root-cause analysis (SURFACE-003).
	{Name: []string{"ai", "query"}, Method: "POST", Path: "/api/v1/ai/query", Body: bodyFile, Summary: "Ask the AI assistant a question"},
	{Name: []string{"ai", "rca"}, Method: "POST", Path: "/api/v1/ai/rca", Body: bodyFile, Summary: "Run an AI root-cause analysis"},

	// MCP tool surface (SURFACE-003).
	{Name: []string{"mcp", "tools"}, Method: "GET", Path: "/api/v1/mcp/tools", Summary: "List the MCP tools the server exposes"},
	{Name: []string{"mcp", "call"}, Method: "POST", Path: "/api/v1/mcp/tools/{tool}", Body: bodyFile, Summary: "Invoke an MCP tool"},

	// Secret store, secret sharing, and dynamic PKI secret (GAP-006).
	{Name: []string{"secrets", "store", "put"}, Method: "POST", Path: "/api/v1/secrets/store", Body: bodyFile, Summary: "Store a secret"},
	{Name: []string{"secrets", "store", "list"}, Method: "GET", Path: "/api/v1/secrets/store", Query: []string{"limit", "cursor"}, Summary: "List stored secrets"},
	{Name: []string{"secrets", "store", "get"}, Method: "GET", Path: "/api/v1/secrets/store/{name}", Summary: "Get a stored secret"},
	{Name: []string{"secrets", "store", "update"}, Method: "PUT", Path: "/api/v1/secrets/store/{name}", Body: bodyFile, Summary: "Replace a stored secret"},
	{Name: []string{"secrets", "store", "delete"}, Method: "DELETE", Path: "/api/v1/secrets/store/{name}", Summary: "Delete a stored secret"},
	{Name: []string{"secrets", "shares", "create"}, Method: "POST", Path: "/api/v1/secrets/shares", Body: bodyFile, Summary: "Create a secret share"},
	{Name: []string{"secrets", "shares", "redeem"}, Method: "POST", Path: "/api/v1/secrets/shares/redeem", Body: bodyFile, Summary: "Redeem a secret share"},
	{Name: []string{"secrets", "pki"}, Method: "POST", Path: "/api/v1/secrets/pki", Body: bodyFile, Summary: "Issue a dynamic PKI secret"},
}

// Commands returns the CLI's command set.
func Commands() []Command { return commandTable }

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
