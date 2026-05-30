package graph_test

import (
	"reflect"
	"sort"
	"testing"

	"certctl.io/certctl/internal/graph"
)

// column extracts the values of a single RETURN column across all rows, sorted.
func column(rows []graph.Row, col string) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r[col])
	}
	sort.Strings(out)
	return out
}

func TestCypherSingleHop(t *testing.T) {
	g := fixture()
	// Every credential issued directly by an issuer. The root→intermediate edge
	// is excluded because the intermediate is an issuer, not a credential.
	rows, err := g.Query(`MATCH (i:issuer)-[:ISSUED]->(c:credential) RETURN c`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	got := column(rows, "c")
	want := []string{"cred:cert-payments", "cred:cert-web"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RETURN c = %v, want %v", got, want)
	}
}

func TestCypherMultiHopReturnsField(t *testing.T) {
	g := fixture()
	// Two hops: a workload's credential and where that credential is deployed,
	// returning the resource's human name rather than its node ID.
	rows, err := g.Query(`MATCH (w:workload)-[:OWNS]->(c)-[:DEPLOYED_TO]->(r) RETURN r.name`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	got := column(rows, "r.name")
	want := []string{"lb-edge", "payments-db"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RETURN r.name = %v, want %v", got, want)
	}
}

func TestCypherWhereFilter(t *testing.T) {
	g := fixture()
	rows, err := g.Query(`MATCH (w:workload)-[:OWNS]->(c)-[:DEPLOYED_TO]->(r) WHERE w.name = "payments-svc" RETURN r`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	got := column(rows, "r")
	if want := []string{"res:payments-db"}; !reflect.DeepEqual(got, want) {
		t.Errorf("filtered RETURN r = %v, want %v", got, want)
	}
}

func TestCypherMultipleReturnColumns(t *testing.T) {
	g := fixture()
	rows, err := g.Query(`MATCH (w:workload)-[:OWNS]->(c) RETURN w.name, c`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// Each row pairs a workload name with the credential ID it owns.
	pairs := map[string]string{}
	for _, r := range rows {
		pairs[r["w.name"]] = r["c"]
	}
	want := map[string]string{
		"payments-svc": "cred:cert-payments",
		"web-frontend": "cred:cert-web",
	}
	if !reflect.DeepEqual(pairs, want) {
		t.Errorf("pairs = %v, want %v", pairs, want)
	}
}

func TestCypherWhereOnKind(t *testing.T) {
	g := fixture()
	// The un-owned standing-access grant: a credential that grants access to a
	// resource. Only the deploy key matches.
	rows, err := g.Query(`MATCH (c)-[:GRANTS_ACCESS]->(r) RETURN c`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := column(rows, "c"); !reflect.DeepEqual(got, []string{"cred:ssh-deploy"}) {
		t.Errorf("RETURN c = %v, want [cred:ssh-deploy]", got)
	}
}

func TestCypherParseErrors(t *testing.T) {
	g := fixture()
	for _, q := range []string{
		`RETURN c`,                                    // no MATCH
		`MATCH (a:issuer)`,                            // no RETURN
		`MATCH (a)-[:ISSUED]->(b) RETURN z`,           // RETURN references unbound var
		`MATCH (a)=[:ISSUED]=>(b) RETURN a`,           // malformed edge
		`MATCH (a)-[:ISSUED]->(b) WHERE a = RETURN a`, // malformed WHERE
	} {
		if _, err := g.Query(q); err == nil {
			t.Errorf("Query(%q) = nil error, want a parse error", q)
		}
	}
}
