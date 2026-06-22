package trstctl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI is an in-process stand-in for the trstctl control plane that responds
// per the served OpenAPI contract: Bearer auth, Idempotency-Key on mutations,
// 201 on create, cursor pages with { items, next_cursor }, and
// application/problem+json on errors. The acceptance test drives the real SDK
// against it so every code path (transport, auth, idempotency, retry, paging,
// problem decoding) is exercised — no string-only assertions.
type fakeAPI struct {
	mu sync.Mutex

	// captured request facts for assertions
	gotAuth          string
	gotTenant        string
	createIdemKeys   []string // Idempotency-Key seen on each create-style mutation
	transitionIdem   string
	ownerCreateCalls int
	identCreateCalls int

	// retry simulation: fail the first N transition attempts with the given
	// status before succeeding.
	transitionFailsLeft  int
	transitionFailStatus int
	transitionAttempts   int

	// the issued identity + a synthesized certificate list for paging
	issuedIdentity Identity
	certPages      map[string]Page[Certificate] // cursor -> page ("" = first)
}

func newFakeAPI() *fakeAPI {
	f := &fakeAPI{certPages: map[string]Page[Certificate]{}}
	return f
}

func (f *fakeAPI) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/owners", func(w http.ResponseWriter, r *http.Request) {
		f.capture(r)
		if r.Method != http.MethodPost {
			f.problem(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		f.mu.Lock()
		f.ownerCreateCalls++
		f.createIdemKeys = append(f.createIdemKeys, r.Header.Get("Idempotency-Key"))
		f.mu.Unlock()
		var req OwnerRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Kind == "" || req.Name == "" {
			f.problem(w, http.StatusBadRequest, "kind and name are required")
			return
		}
		writeJSON(w, http.StatusCreated, Owner{
			ID: "11111111-1111-1111-1111-111111111111", TenantID: "t", Kind: req.Kind, Name: req.Name,
		})
	})

	mux.HandleFunc("/api/v1/identities", func(w http.ResponseWriter, r *http.Request) {
		f.capture(r)
		if r.Method != http.MethodPost {
			f.problem(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		f.mu.Lock()
		f.identCreateCalls++
		f.createIdemKeys = append(f.createIdemKeys, r.Header.Get("Idempotency-Key"))
		f.mu.Unlock()
		var req IdentityRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.OwnerID == "" {
			f.problem(w, http.StatusBadRequest, "owner_id is required")
			return
		}
		f.mu.Lock()
		f.issuedIdentity = Identity{
			ID: "22222222-2222-2222-2222-222222222222", Kind: req.Kind, Name: req.Name,
			OwnerID: req.OwnerID, Status: "requested",
		}
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, f.issuedIdentity)
	})

	mux.HandleFunc("/api/v1/identities/22222222-2222-2222-2222-222222222222/transitions", func(w http.ResponseWriter, r *http.Request) {
		f.capture(r)
		f.mu.Lock()
		f.transitionAttempts++
		f.transitionIdem = r.Header.Get("Idempotency-Key")
		failLeft := f.transitionFailsLeft
		if failLeft > 0 {
			f.transitionFailsLeft--
		}
		failStatus := f.transitionFailStatus
		f.mu.Unlock()

		if failLeft > 0 {
			// Simulate a transient failure (429 or 503). Send Retry-After so the
			// SDK's backoff honors it.
			w.Header().Set("Retry-After", "0")
			f.problem(w, failStatus, "temporarily unavailable, retry")
			return
		}
		var req TransitionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		id := f.issuedIdentity
		id.Status = req.To
		f.issuedIdentity = id
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, id)
	})

	mux.HandleFunc("/api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		f.capture(r)
		cursor := r.URL.Query().Get("cursor")
		f.mu.Lock()
		pg, ok := f.certPages[cursor]
		f.mu.Unlock()
		if !ok {
			f.problem(w, http.StatusBadRequest, "unknown cursor")
			return
		}
		writeJSON(w, http.StatusOK, pg)
	})

	// A deliberately error-only endpoint to assert problem+json decoding into a
	// typed *Problem with a useful detail.
	mux.HandleFunc("/api/v1/identities/does-not-exist", func(w http.ResponseWriter, r *http.Request) {
		f.capture(r)
		f.problemWithType(w, http.StatusNotFound, "https://trstctl.com/problems/not-found", "Not Found", "identity does-not-exist was not found")
	})

	return mux
}

func (f *fakeAPI) capture(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a := r.Header.Get("Authorization"); a != "" {
		f.gotAuth = a
	}
	if t := r.Header.Get("X-Tenant-ID"); t != "" {
		f.gotTenant = t
	}
}

func (f *fakeAPI) problem(w http.ResponseWriter, status int, detail string) {
	f.problemWithType(w, status, "", http.StatusText(status), detail)
}

func (f *fakeAPI) problemWithType(w http.ResponseWriter, status int, typ, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{"title": title, "status": status, "detail": detail}
	if typ != "" {
		body["type"] = typ
	}
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// TestGettingStartedFlow is the PRODUCT-007 acceptance test: it spins up an
// in-process server speaking the OpenAPI contract and drives the SDK through the
// documented getting-started create -> list flow, asserting the load-bearing DX
// guarantees (auth header, Idempotency-Key on create, problem+json typed error,
// retry on transient failure, and cursor paging across multiple pages).
func TestGettingStartedFlow(t *testing.T) {
	fake := newFakeAPI()
	// One transient 429 on the first transition attempt, then success: proves
	// retry-with-backoff honoring Retry-After kicks in for a mutation.
	fake.transitionFailsLeft = 1
	fake.transitionFailStatus = http.StatusTooManyRequests
	// Three certificates spread across two pages, proving the cursor iterator
	// follows next_cursor.
	fake.certPages[""] = Page[Certificate]{
		Items:      []Certificate{{ID: "c1", Subject: "a"}, {ID: "c2", Subject: "b"}},
		NextCursor: "page2",
	}
	fake.certPages["page2"] = Page[Certificate]{
		Items: []Certificate{{ID: "c3", Subject: "c"}},
	}

	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	client := New(srv.URL, "trst_test-token",
		WithTenant("11111111-1111-1111-1111-111111111111"),
		// Tight, fast backoff so the retry path runs quickly under test.
		WithRetry(RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}),
	)
	ctx := context.Background()

	// --- create flow (owner -> identity -> transition issued) ---------------
	ident, err := client.IssueFirstCertificate(ctx, "payments")
	if err != nil {
		t.Fatalf("IssueFirstCertificate: %v", err)
	}
	if ident.Status != "issued" {
		t.Fatalf("issued identity status = %q, want issued", ident.Status)
	}
	if ident.OwnerID == "" {
		t.Fatalf("issued identity has no owner_id; owner creation did not feed identity create")
	}

	// --- auth header was sent on every call ---------------------------------
	if fake.gotAuth != "Bearer trst_test-token" {
		t.Fatalf("Authorization header = %q, want Bearer trst_test-token", fake.gotAuth)
	}
	if fake.gotTenant != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("X-Tenant-ID = %q, want the configured tenant", fake.gotTenant)
	}

	// --- Idempotency-Key was sent on each create mutation -------------------
	if fake.ownerCreateCalls != 1 || fake.identCreateCalls != 1 {
		t.Fatalf("expected exactly one owner and one identity create, got owner=%d identity=%d",
			fake.ownerCreateCalls, fake.identCreateCalls)
	}
	if len(fake.createIdemKeys) != 2 {
		t.Fatalf("expected 2 captured create idempotency keys, got %d", len(fake.createIdemKeys))
	}
	for i, k := range fake.createIdemKeys {
		if strings.TrimSpace(k) == "" {
			t.Fatalf("create mutation #%d sent no Idempotency-Key (AN-5 violation)", i)
		}
	}
	if fake.createIdemKeys[0] == fake.createIdemKeys[1] {
		t.Fatalf("owner and identity creates reused the same Idempotency-Key %q; each logical mutation must get its own", fake.createIdemKeys[0])
	}
	if strings.TrimSpace(fake.transitionIdem) == "" {
		t.Fatalf("transition mutation sent no Idempotency-Key")
	}

	// --- retry triggered on 429 then succeeded ------------------------------
	if fake.transitionAttempts != 2 {
		t.Fatalf("transition attempts = %d, want 2 (one 429 retry then success)", fake.transitionAttempts)
	}

	// --- cursor iterator pages through multiple pages -----------------------
	var ids []string
	it := client.Certificates(CertificateListOptions{ListOptions: ListOptions{Limit: 2}})
	for it.Next(ctx) {
		ids = append(ids, it.Value().ID)
	}
	if err := it.Err(); err != nil {
		t.Fatalf("certificate iterator error: %v", err)
	}
	want := []string{"c1", "c2", "c3"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("iterator yielded %v across pages, want %v", ids, want)
	}

	// Collect should produce the same set in one call.
	collected, err := client.Certificates(CertificateListOptions{}).Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(collected) != 3 {
		t.Fatalf("Collect returned %d certificates, want 3", len(collected))
	}
}

// TestProblemJSONSurfacedAsTypedError asserts a non-2xx problem+json body is
// parsed into a typed *Problem with status, title, type, and detail intact, and
// is reachable via errors.As / AsProblem.
func TestProblemJSONSurfacedAsTypedError(t *testing.T) {
	fake := newFakeAPI()
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	client := New(srv.URL, "trst_test-token",
		WithRetry(RetryPolicy{MaxAttempts: 1}), // a 404 is not retryable anyway
	)
	_, err := client.GetIdentity(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected an error for a missing identity, got nil")
	}

	prob, ok := AsProblem(err)
	if !ok {
		t.Fatalf("error %v is not a *Problem; problem+json was not surfaced as a typed error", err)
	}
	if prob.HTTPStatus != http.StatusNotFound {
		t.Errorf("Problem.HTTPStatus = %d, want 404", prob.HTTPStatus)
	}
	if prob.Status != http.StatusNotFound {
		t.Errorf("Problem.Status (body) = %d, want 404", prob.Status)
	}
	if prob.Title != "Not Found" {
		t.Errorf("Problem.Title = %q, want Not Found", prob.Title)
	}
	if prob.Type != "https://trstctl.com/problems/not-found" {
		t.Errorf("Problem.Type = %q, want the served type URI", prob.Type)
	}
	if !strings.Contains(prob.Detail, "does-not-exist") {
		t.Errorf("Problem.Detail = %q, want it to mention the missing id", prob.Detail)
	}
	// Also reachable via errors.As directly.
	var p2 *Problem
	if !errors.As(err, &p2) {
		t.Fatal("errors.As(*Problem) failed; the SDK error chain does not expose the typed problem")
	}
}

// TestRetryOn503ThenSuccess exercises the retry path on a 503 (a different
// retryable status than 429) for an idempotent GET, proving backoff applies and
// the call ultimately succeeds.
func TestRetryOn503ThenSuccess(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n <= 2 {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"title": "Service Unavailable", "status": 503, "detail": "shedding load"})
			return
		}
		writeJSON(w, http.StatusOK, Page[Owner]{Items: []Owner{{ID: "o1", Kind: "workload", Name: "x"}}})
	}))
	defer srv.Close()

	client := New(srv.URL, "trst_test-token",
		WithRetry(RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}))

	page, err := client.ListOwners(context.Background(), ListOptions{})
	if err != nil {
		t.Fatalf("ListOwners after retries: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "o1" {
		t.Fatalf("unexpected page after retry: %+v", page)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3 (two 503s then success)", attempts)
	}
}

// TestNonRetryableClientErrorNotRetried asserts a 400 is returned immediately,
// not retried, so we don't hammer the server on a deterministic client error.
func TestNonRetryableClientErrorNotRetried(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"title": "Bad Request", "status": 400, "detail": "kind is invalid"})
	}))
	defer srv.Close()

	client := New(srv.URL, "trst_test-token",
		WithRetry(RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond}))
	_, err := client.CreateOwner(context.Background(), OwnerRequest{Kind: "bogus", Name: "x"})
	if err == nil {
		t.Fatal("expected a 400 error, got nil")
	}
	if prob, ok := AsProblem(err); !ok || prob.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("want a 400 *Problem, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Fatalf("a 400 must not be retried; attempts = %d, want 1", attempts)
	}
}

// TestIdempotencyKeyStableAcrossRetries asserts that when a mutation is retried,
// the SAME Idempotency-Key is sent each time, so the server's replay protection
// makes the retried create exactly-once (AN-5).
func TestIdempotencyKeyStableAcrossRetries(t *testing.T) {
	var keys []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		n := len(keys)
		mu.Unlock()
		if n <= 2 {
			w.Header().Set("Retry-After", "0")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"title": "Service Unavailable", "status": 503})
			return
		}
		writeJSON(w, http.StatusCreated, Owner{ID: "o1", Kind: "workload", Name: "x"})
	}))
	defer srv.Close()

	client := New(srv.URL, "trst_test-token",
		WithRetry(RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}))
	if _, err := client.CreateOwner(context.Background(), OwnerRequest{Kind: "workload", Name: "x"}); err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keys) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(keys))
	}
	for i, k := range keys {
		if k == "" {
			t.Fatalf("attempt %d had no Idempotency-Key", i)
		}
		if k != keys[0] {
			t.Fatalf("Idempotency-Key changed across retries: attempt 0 = %q, attempt %d = %q (a retry must reuse the key)", keys[0], i, k)
		}
	}
}

// TestExplicitIdempotencyKeyHonored asserts a caller-supplied key is used
// verbatim rather than auto-generated.
func TestExplicitIdempotencyKeyHonored(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Idempotency-Key")
		writeJSON(w, http.StatusCreated, Owner{ID: "o1", Kind: "workload", Name: "x"})
	}))
	defer srv.Close()

	client := New(srv.URL, "trst_test-token")
	_, err := client.CreateOwnerKeyed(context.Background(), OwnerRequest{Kind: "workload", Name: "x"}, "my-stable-key-123")
	if err != nil {
		t.Fatalf("CreateOwnerKeyed: %v", err)
	}
	if gotKey != "my-stable-key-123" {
		t.Fatalf("Idempotency-Key = %q, want the caller-supplied key", gotKey)
	}
}

// TestEmptyListNoCursorTerminates guards the iterator against an infinite loop
// on an empty terminal page.
func TestEmptyListNoCursorTerminates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Page[Owner]{Items: []Owner{}})
	}))
	defer srv.Close()
	client := New(srv.URL, "trst_test-token")
	all, err := client.Owners(ListOptions{}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect on empty list: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected 0 owners, got %d", len(all))
	}
}
