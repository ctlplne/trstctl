package projections_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"certctl.io/certctl/internal/api"
	"certctl.io/certctl/internal/orchestrator"
)

func newAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)))
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv
}

type reqOpts struct {
	tenant string
	idem   string
	body   any
}

func do(t *testing.T, srv *httptest.Server, method, path string, o reqOpts) (int, http.Header, []byte) {
	t.Helper()
	var r io.Reader
	if o.body != nil {
		b, _ := json.Marshal(o.body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if o.tenant != "" {
		req.Header.Set("X-Tenant-ID", o.tenant)
	}
	if o.idem != "" {
		req.Header.Set("Idempotency-Key", o.idem)
	}
	if o.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, body
}

func decode(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return m
}

func assertProblem(t *testing.T, hdr http.Header, body []byte, wantStatus int) {
	t.Helper()
	if ct := hdr.Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		t.Errorf("content-type = %q, want application/problem+json", ct)
	}
	p := decode(t, body)
	if int(p["status"].(float64)) != wantStatus {
		t.Errorf("problem status = %v, want %d", p["status"], wantStatus)
	}
	if p["title"] == nil || p["title"] == "" {
		t.Error("problem missing title")
	}
}

// TestAPIOwnerCRUD covers create/read/update/delete and problem+json on 404.
func TestAPIOwnerCRUD(t *testing.T) {
	srv := newAPIServer(t)

	st, _, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, idem: "k1", body: map[string]any{"kind": "service", "name": "billing"}})
	if st != http.StatusCreated {
		t.Fatalf("create owner status = %d (%s), want 201", st, body)
	}
	id, _ := decode(t, body)["id"].(string)
	if id == "" {
		t.Fatal("create owner returned no id")
	}

	st, _, body = do(t, srv, "GET", "/api/v1/owners/"+id, reqOpts{tenant: tenantA})
	if st != http.StatusOK || decode(t, body)["name"] != "billing" {
		t.Fatalf("get owner = %d %s", st, body)
	}

	st, _, _ = do(t, srv, "PUT", "/api/v1/owners/"+id, reqOpts{tenant: tenantA, idem: "k2", body: map[string]any{"kind": "service", "name": "billing-2", "email": "b@acme.test"}})
	if st != http.StatusOK {
		t.Fatalf("update owner status = %d, want 200", st)
	}
	_, _, body = do(t, srv, "GET", "/api/v1/owners/"+id, reqOpts{tenant: tenantA})
	if decode(t, body)["name"] != "billing-2" {
		t.Fatalf("owner not updated: %s", body)
	}

	st, _, _ = do(t, srv, "DELETE", "/api/v1/owners/"+id, reqOpts{tenant: tenantA, idem: "k3"})
	if st != http.StatusNoContent {
		t.Fatalf("delete owner status = %d, want 204", st)
	}
	st, hdr, body := do(t, srv, "GET", "/api/v1/owners/"+id, reqOpts{tenant: tenantA})
	if st != http.StatusNotFound {
		t.Fatalf("get deleted owner status = %d, want 404", st)
	}
	assertProblem(t, hdr, body, http.StatusNotFound)
}

// TestAPIMutationGuards covers the idempotency-key and tenant requirements.
func TestAPIMutationGuards(t *testing.T) {
	srv := newAPIServer(t)

	// Missing Idempotency-Key on a mutation.
	st, hdr, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, body: map[string]any{"kind": "service", "name": "x"}})
	if st != http.StatusBadRequest {
		t.Fatalf("missing idem key status = %d, want 400", st)
	}
	assertProblem(t, hdr, body, http.StatusBadRequest)

	// Missing tenant.
	st, hdr, body = do(t, srv, "POST", "/api/v1/owners", reqOpts{idem: "k1", body: map[string]any{"kind": "service", "name": "x"}})
	if st != http.StatusUnauthorized {
		t.Fatalf("missing tenant status = %d, want 401", st)
	}
	assertProblem(t, hdr, body, http.StatusUnauthorized)
}

// TestAPIMutationsAreIdempotent: replaying a key returns the original result and
// produces a single effect.
func TestAPIMutationsAreIdempotent(t *testing.T) {
	srv := newAPIServer(t)

	st1, _, b1 := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, idem: "dup", body: map[string]any{"kind": "service", "name": "once"}})
	st2, _, b2 := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, idem: "dup", body: map[string]any{"kind": "service", "name": "once"}})
	if st1 != http.StatusCreated || st2 != http.StatusCreated {
		t.Fatalf("statuses = %d, %d, want 201, 201 (replay returns original)", st1, st2)
	}
	if decode(t, b1)["id"] != decode(t, b2)["id"] {
		t.Errorf("replay returned a different id: %s vs %s", b1, b2)
	}

	// Exactly one owner was created despite the duplicate request.
	_, _, lb := do(t, srv, "GET", "/api/v1/owners?limit=100", reqOpts{tenant: tenantA})
	items, _ := decode(t, lb)["items"].([]any)
	if len(items) != 1 {
		t.Errorf("idempotent replay produced %d owners, want 1", len(items))
	}
}

// TestAPIOwnerListPagination walks the cursor to completion.
func TestAPIOwnerListPagination(t *testing.T) {
	srv := newAPIServer(t)
	for i := 0; i < 5; i++ {
		st, _, body := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, idem: string(rune('a' + i)), body: map[string]any{"kind": "service", "name": "o"}})
		if st != http.StatusCreated {
			t.Fatalf("seed owner %d: %d %s", i, st, body)
		}
	}

	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		path := "/api/v1/owners?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		st, _, body := do(t, srv, "GET", path, reqOpts{tenant: tenantA})
		if st != http.StatusOK {
			t.Fatalf("list status = %d: %s", st, body)
		}
		page := decode(t, body)
		items, _ := page["items"].([]any)
		for _, it := range items {
			seen[it.(map[string]any)["id"].(string)] = true
		}
		next, _ := page["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 5 {
		t.Errorf("pagination yielded %d distinct owners, want 5", len(seen))
	}
}

// TestAPIIssuerValidation covers the X.509/SSH distinction and 422 on an invalid
// issuer.
func TestAPIIssuerValidation(t *testing.T) {
	srv := newAPIServer(t)

	st, _, _ := do(t, srv, "POST", "/api/v1/issuers", reqOpts{tenant: tenantA, idem: "i1", body: map[string]any{"kind": "x509_ca", "name": "root", "chain": []string{"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----"}}})
	if st != http.StatusCreated {
		t.Fatalf("create x509 issuer status = %d, want 201", st)
	}
	st, _, _ = do(t, srv, "POST", "/api/v1/issuers", reqOpts{tenant: tenantA, idem: "i2", body: map[string]any{"kind": "ssh_ca", "name": "fleet", "public_key": "ssh-ed25519 AAAA"}})
	if st != http.StatusCreated {
		t.Fatalf("create ssh issuer status = %d, want 201", st)
	}
	// An SSH CA carrying a chain is invalid.
	st, hdr, body := do(t, srv, "POST", "/api/v1/issuers", reqOpts{tenant: tenantA, idem: "i3", body: map[string]any{"kind": "ssh_ca", "name": "bad", "chain": []string{"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----"}}})
	if st != http.StatusUnprocessableEntity {
		t.Fatalf("invalid issuer status = %d, want 422", st)
	}
	assertProblem(t, hdr, body, http.StatusUnprocessableEntity)
}

// TestAPIIdentityLifecycle covers create + lifecycle transition + invalid
// transition (409).
func TestAPIIdentityLifecycle(t *testing.T) {
	srv := newAPIServer(t)

	_, _, ob := do(t, srv, "POST", "/api/v1/owners", reqOpts{tenant: tenantA, idem: "o", body: map[string]any{"kind": "service", "name": "svc"}})
	ownerID := decode(t, ob)["id"].(string)

	st, _, body := do(t, srv, "POST", "/api/v1/identities", reqOpts{tenant: tenantA, idem: "id1", body: map[string]any{"kind": "x509_certificate", "name": "svc.acme.test", "owner_id": ownerID}})
	if st != http.StatusCreated {
		t.Fatalf("create identity status = %d: %s", st, body)
	}
	identID := decode(t, body)["id"].(string)
	if decode(t, body)["status"] != "requested" {
		t.Fatalf("new identity status = %v, want requested", decode(t, body)["status"])
	}

	st, _, body = do(t, srv, "POST", "/api/v1/identities/"+identID+"/transitions", reqOpts{tenant: tenantA, idem: "t1", body: map[string]any{"to": "issued"}})
	if st != http.StatusOK || decode(t, body)["status"] != "issued" {
		t.Fatalf("transition to issued = %d %s", st, body)
	}

	// issued -> retired is not a valid transition.
	st, hdr, body := do(t, srv, "POST", "/api/v1/identities/"+identID+"/transitions", reqOpts{tenant: tenantA, idem: "t2", body: map[string]any{"to": "retired"}})
	if st != http.StatusConflict {
		t.Fatalf("invalid transition status = %d, want 409: %s", st, body)
	}
	assertProblem(t, hdr, body, http.StatusConflict)
}
