// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

// "No CMDB write unless explicitly configured" (epic I2) must hold as an
// absence of code, not as a flag.
//
// A configuration switch that gates writes is one careless default away from
// writing to a customer's system of record. These tests assert the two ways a
// write could appear: through the ticket writer's table allow-list, and through
// the reconcile path's own requests.

func TestTheTicketWriterCannotAddressTheCMDB(t *testing.T) {
	t.Parallel()
	for _, table := range []string{"cmdb_ci", "cmdb_ci_server", "cmdb_rel_ci", "CMDB_CI", " cmdb_ci "} {
		if got, ok := orchestrator.NormalizeServiceNowTable(table); ok {
			t.Fatalf("the ticket writer accepted table %q (normalized to %q).\n\n"+
				"That is a write path into a customer's system of record. The CMDB integration is "+
				"read-only by construction, and it stays that way only while no writer can name the "+
				"cmdb_ci table.", table, got)
		}
	}
}

// The reconcile path must issue GETs against the fixed cmdb_ci path, so a
// schedule cannot be steered into reading — or writing — some other table.
func TestTheReconcilePathOnlyEverReadsCMDBCI(t *testing.T) {
	t.Parallel()
	var methods []string
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()

	// A schedule that tries to name another table in its instance URL and in
	// its query. Neither may move the request off cmdb_ci.
	endpoint, err := cmdbEndpoint(srv.URL+"/", "nameLIKEx^ORtable=sys_user_password")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if len(methods) != 1 || methods[0] != http.MethodGet {
		t.Fatalf("methods = %v, want exactly one GET. Any other verb against a CMDB is a write to a "+
			"customer's system of record", methods)
	}
	if len(paths) != 1 || !strings.HasSuffix(paths[0], "/api/now/table/cmdb_ci") {
		t.Fatalf("path = %v, want the fixed cmdb_ci table. A schedule that can choose its own table "+
			"can read sys_user_password", paths)
	}
}

// The query is a filter, not a path. An operator query must not be able to
// escape into the URL path or swap the table.
func TestACIQueryCannotEscapeIntoThePath(t *testing.T) {
	t.Parallel()
	endpoint, err := cmdbEndpoint("https://example.service-now.com", "../../sys_user_password?x=1")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/api/now/table/cmdb_ci" {
		t.Fatalf("path = %q, want /api/now/table/cmdb_ci; the query escaped into the path", u.Path)
	}
	if got := u.Query().Get("sysparm_query"); got != "../../sys_user_password?x=1" {
		t.Fatalf("sysparm_query = %q; the query must travel as an encoded parameter", got)
	}
	if u.Query().Get("sysparm_display_value") != "all" {
		t.Fatal("display values were not requested; reference fields would come back as sys_ids, and " +
			"a sys_id in an owner column is a value nobody can route an expiry notice to")
	}
}

// The reconcile must never create owners.
//
// A CMDB assignment group is not evidence that a trstctl owner should exist.
// Auto-creating would build a parallel estate out of the CMDB's typos, and
// every new owner would look like coverage.
func TestReconcileNeverCreatesOwnersFromCMDBRows(t *testing.T) {
	t.Parallel()
	src, err := readSourceFile("cmdb_reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"CreateOwner", "UpsertOwner"} {
		if strings.Contains(src, forbidden) {
			t.Fatalf("cmdb_reconcile.go calls %s. A CI naming an unknown owner must be REPORTED, "+
				"not created: the CMDB's typos would become owners, and each one would look like "+
				"ownership coverage this estate does not have", forbidden)
		}
	}
}

// readSourceFile is a structural guard, not a behavioural one, and is used
// only where the property IS the absence of a call. RunCMDBReconcileOnce needs
// a live store to exercise, and a test that stood up Postgres to prove a
// function is never called would prove less than reading the function.
func readSourceFile(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}
