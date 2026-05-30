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

	{Name: []string{"certificates", "ingest"}, Method: "POST", Path: "/api/v1/certificates", Body: bodyFile, Summary: "Ingest a certificate"},
	{Name: []string{"certificates", "list"}, Method: "GET", Path: "/api/v1/certificates", Query: []string{"limit", "cursor", "expiring_before"}, Summary: "Query the certificate inventory"},
	{Name: []string{"certificates", "get"}, Method: "GET", Path: "/api/v1/certificates/{id}", Summary: "Get an inventoried certificate"},

	{Name: []string{"audit", "events"}, Method: "GET", Path: "/api/v1/audit/events", Query: []string{"type", "since", "until", "as_of", "q", "limit"}, Summary: "Query the audit log"},
	{Name: []string{"audit", "export"}, Method: "GET", Path: "/api/v1/audit/export", Query: []string{"type", "since", "until", "as_of", "q", "limit"}, Summary: "Export a signed audit bundle"},

	{Name: []string{"graph", "nodes"}, Method: "GET", Path: "/api/v1/graph", Summary: "Get the credential graph"},
	{Name: []string{"graph", "reachable"}, Method: "GET", Path: "/api/v1/graph/reachable/{id}", Summary: "Nodes reachable from a node"},
	{Name: []string{"graph", "blast-radius"}, Method: "GET", Path: "/api/v1/graph/blast-radius/{id}", Summary: "Blast radius of a node"},
	{Name: []string{"graph", "query"}, Method: "POST", Path: "/api/v1/graph/query", Body: bodyCypher, Summary: "Run a Cypher-style query"},

	{Name: []string{"risk", "credentials"}, Method: "GET", Path: "/api/v1/risk/credentials", Query: []string{"sort", "min_score", "privilege", "owner"}, Summary: "Rank credentials by risk score"},
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
