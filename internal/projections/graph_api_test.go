package projections_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"certctl.io/certctl/internal/api"
	"certctl.io/certctl/internal/graph"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/sshinv"
	"certctl.io/certctl/internal/store"
)

// newGraphAPI builds an API server over a fresh store and returns both, so the
// test can seed the inventory the graph is built from.
func newGraphAPI(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)))
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv, s
}

// nodeID finds the single node of the given kind and name and returns its ID.
func nodeID(t *testing.T, nodes []graph.Node, kind graph.NodeKind, name string) string {
	t.Helper()
	for _, n := range nodes {
		if n.Kind == kind && n.Name == name {
			return n.ID
		}
	}
	t.Fatalf("no %s node named %q among %d nodes", kind, name, len(nodes))
	return ""
}

// seedGraphInventory plants two workloads, an issuer, the two certificates they
// own (each deployed to a resource and signed by the issuer), and one orphaned
// standing-access SSH grant.
func seedGraphInventory(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	exp := time.Now().Add(720 * time.Hour)

	payments, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerWorkload, Name: "payments-svc"})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	web, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerWorkload, Name: "web-frontend"})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	issuer, err := s.CreateIssuer(ctx, store.Issuer{
		TenantID: tenantA, Kind: store.IssuerX509CA, Name: "Acme Intermediate",
		Chain: []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
	})
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}

	mkCert := func(owner string, subject, fp, loc string) {
		_, err := s.UpsertCertificate(ctx, store.Certificate{
			TenantID: tenantA, OwnerID: &owner, Subject: subject, SANs: []string{subject},
			Issuer: "Acme Intermediate", Serial: fp, Fingerprint: fp, KeyAlgorithm: "ECDSA",
			NotBefore: tptr(exp.Add(-24 * time.Hour)), NotAfter: tptr(exp),
			DeploymentLocation: loc, Source: "import", Status: "active",
		})
		if err != nil {
			t.Fatalf("upsert cert: %v", err)
		}
	}
	mkCert(payments.ID, "payments.example.com", "fp-payments", "payments-db")
	mkCert(web.ID, "web.example.com", "fp-web", "lb-edge")

	if _, err := s.UpsertSSHKey(ctx, store.SSHKey{
		TenantID: tenantA, Fingerprint: "SHA256:orphan", KeyType: "ssh-ed25519",
		Source: sshinv.SourceAuthorizedKeys, Location: "bastion:22",
		StandingAccess: true, Orphaned: true,
	}); err != nil {
		t.Fatalf("upsert ssh key: %v", err)
	}
	_ = issuer
}

// TestGraphRESTReachabilityAndBlastRadius is the S6.4 acceptance over the REST
// surface: the credential graph, built from real inventory in embedded
// PostgreSQL, answers reachability and blast-radius queries correctly.
func TestGraphRESTReachabilityAndBlastRadius(t *testing.T) {
	srv, s := newGraphAPI(t)
	seedGraphInventory(t, s)

	// Discover node IDs from the graph snapshot, the way a real client would.
	var snap struct {
		Nodes []graph.Node `json:"nodes"`
		Edges []graph.Edge `json:"edges"`
	}
	status, _, body := do(t, srv, http.MethodGet, "/api/v1/graph", reqOpts{tenant: tenantA})
	if status != http.StatusOK {
		t.Fatalf("GET /graph = %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	paymentsWL := nodeID(t, snap.Nodes, graph.KindWorkload, "payments-svc")
	issuerID := nodeID(t, snap.Nodes, graph.KindIssuer, "Acme Intermediate")
	paymentsCert := nodeID(t, snap.Nodes, graph.KindCredential, "payments.example.com")

	// Reachability: payments-svc reaches only its own certificate and the
	// resource that certificate is deployed to.
	var reach struct {
		From  string       `json:"from"`
		Nodes []graph.Node `json:"nodes"`
	}
	status, _, body = do(t, srv, http.MethodGet, "/api/v1/graph/reachable/"+paymentsWL, reqOpts{tenant: tenantA})
	if status != http.StatusOK {
		t.Fatalf("GET reachable = %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &reach); err != nil {
		t.Fatalf("decode reachable: %v", err)
	}
	if got := names(reach.Nodes); !equalStrings(got, []string{"payments-db", "payments.example.com"}) {
		t.Errorf("reachable(payments-svc) = %v, want [payments-db payments.example.com]", got)
	}

	// Blast radius: compromising the issuer affects both certificates and both
	// resources they protect.
	var imp graph.Impact
	status, _, body = do(t, srv, http.MethodGet, "/api/v1/graph/blast-radius/"+issuerID, reqOpts{tenant: tenantA})
	if status != http.StatusOK {
		t.Fatalf("GET blast-radius = %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &imp); err != nil {
		t.Fatalf("decode impact: %v", err)
	}
	if got := names(imp.ByKind[graph.KindCredential]); !equalStrings(got, []string{"payments.example.com", "web.example.com"}) {
		t.Errorf("blast-radius credentials = %v", got)
	}
	if got := names(imp.ByKind[graph.KindResource]); !equalStrings(got, []string{"lb-edge", "payments-db"}) {
		t.Errorf("blast-radius resources = %v", got)
	}

	// A certificate's blast radius is just where it is deployed.
	status, _, body = do(t, srv, http.MethodGet, "/api/v1/graph/blast-radius/"+paymentsCert, reqOpts{tenant: tenantA})
	if status != http.StatusOK {
		t.Fatalf("GET blast-radius(cert) = %d: %s", status, body)
	}
	var impCert graph.Impact
	if err := json.Unmarshal(body, &impCert); err != nil {
		t.Fatalf("decode impact: %v", err)
	}
	if got := names(impCert.Affected); !equalStrings(got, []string{"payments-db"}) {
		t.Errorf("blast-radius(payments cert) = %v, want [payments-db]", got)
	}

	// Unknown node → 404.
	status, _, _ = do(t, srv, http.MethodGet, "/api/v1/graph/reachable/wl:does-not-exist", reqOpts{tenant: tenantA})
	if status != http.StatusNotFound {
		t.Errorf("reachable(unknown) = %d, want 404", status)
	}
}

// TestGraphRESTCypherQuery is the S6.4 acceptance for the Cypher-style query
// over the REST surface.
func TestGraphRESTCypherQuery(t *testing.T) {
	srv, s := newGraphAPI(t)
	seedGraphInventory(t, s)

	query := func(q string) []graph.Row {
		t.Helper()
		status, _, body := do(t, srv, http.MethodPost, "/api/v1/graph/query", reqOpts{tenant: tenantA, body: map[string]string{"query": q}})
		if status != http.StatusOK {
			t.Fatalf("POST query %q = %d: %s", q, status, body)
		}
		var res struct {
			Rows []graph.Row `json:"rows"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("decode rows: %v", err)
		}
		return res.Rows
	}

	// Where each workload's certificate is deployed.
	rows := query(`MATCH (w:workload)-[:OWNS]->(c)-[:DEPLOYED_TO]->(r) RETURN r.name`)
	var got []string
	for _, r := range rows {
		got = append(got, r["r.name"])
	}
	sort.Strings(got)
	if !equalStrings(got, []string{"lb-edge", "payments-db"}) {
		t.Errorf("cypher deploy targets = %v", got)
	}

	// The orphaned standing-access grant, surfaced by a WHERE on a node
	// attribute the builder populated from the SSH inventory.
	rows = query(`MATCH (c)-[:GRANTS_ACCESS]->(r) WHERE c.orphaned = "true" RETURN r.name`)
	if len(rows) != 1 || rows[0]["r.name"] != "bastion:22" {
		t.Errorf("cypher orphaned grant = %v, want one row to bastion:22", rows)
	}

	// A malformed query is a 400, not a 500.
	status, _, _ := do(t, srv, http.MethodPost, "/api/v1/graph/query", reqOpts{tenant: tenantA, body: map[string]string{"query": "RETURN nonsense"}})
	if status != http.StatusBadRequest {
		t.Errorf("malformed query status = %d, want 400", status)
	}
}

// TestGraphRESTRequiresPermission proves the graph endpoints are guarded: a
// viewer (read-only) is allowed, but a role without graph:read is denied.
func TestGraphRESTRequiresPermission(t *testing.T) {
	srv, s := newGraphAPI(t)
	seedGraphInventory(t, s)

	// viewer carries graph:read.
	if status, _, _ := do(t, srv, http.MethodGet, "/api/v1/graph", reqOpts{tenant: tenantA, roles: "viewer"}); status != http.StatusOK {
		t.Errorf("viewer GET /graph = %d, want 200", status)
	}
	// auditor carries only audit:read.
	if status, _, _ := do(t, srv, http.MethodGet, "/api/v1/graph", reqOpts{tenant: tenantA, roles: "auditor"}); status != http.StatusForbidden {
		t.Errorf("auditor GET /graph = %d, want 403", status)
	}
}

func names(nodes []graph.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
