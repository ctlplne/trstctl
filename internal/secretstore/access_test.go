package secretstore

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
)

type allowFn func(ctx context.Context, t, p, path, action string) (bool, string)

func (f allowFn) Allow(ctx context.Context, t, p, path, action string) (bool, string) {
	return f(ctx, t, p, path, action)
}

func apiFixture(t *testing.T, rec auditsink.Auditor, authz Authorizer) *APIServer {
	t.Helper()
	kek, _ := crypto.NewKEK()
	store, err := New(Config{TenantID: "t1", KEK: kek})
	if err != nil {
		t.Fatal(err)
	}
	return NewAPIServer(store, "t1", authz, rec)
}

func do(t *testing.T, api *APIServer, method, path, body, tenant, principal, query string) (int, string) {
	t.Helper()
	r, _ := http.NewRequest(method, "http://x/secrets/"+path+query, strings.NewReader(body))
	r.Header.Set("X-Tenant", tenant)
	r.Header.Set("X-Principal", principal)
	rw := newRecorder()
	api.ServeHTTP(rw, r)
	return rw.code, rw.body.String()
}

func TestAPIReadWriteRollback(t *testing.T) {
	authz := allowFn(func(_ context.Context, _, p, _, _ string) (bool, string) {
		if p == "bad" {
			return false, "rbac"
		}
		return true, ""
	})
	api := apiFixture(t, &auditsink.Recorder{}, authz)
	if code, _ := do(t, api, "PUT", "app/db", "v1", "t1", "alice", ""); code != http.StatusOK {
		t.Fatalf("put v1 = %d", code)
	}
	if code, body := do(t, api, "GET", "app/db", "", "t1", "alice", ""); code != http.StatusOK || body != "v1" {
		t.Fatalf("get = %d %q", code, body)
	}
	do(t, api, "PUT", "app/db", "v2", "t1", "alice", "")
	if code, _ := do(t, api, "POST", "app/db", "", "t1", "alice", "?rollback=1"); code != http.StatusOK {
		t.Fatalf("rollback = %d", code)
	}
	if _, body := do(t, api, "GET", "app/db", "", "t1", "alice", ""); body != "v1" {
		t.Errorf("after rollback = %q, want v1", body)
	}
}

func TestAPICrossTenantDenied(t *testing.T) {
	rec := &auditsink.Recorder{}
	api := apiFixture(t, rec, allowFn(func(context.Context, string, string, string, string) (bool, string) { return true, "" }))
	if code, _ := do(t, api, "GET", "app/db", "", "t2", "alice", ""); code != http.StatusForbidden {
		t.Errorf("cross-tenant read = %d, want 403", code)
	}
	if rec.Count("secret.access.denied") == 0 {
		t.Error("cross-tenant denial not audited")
	}
}

func TestAPIRBACDenied(t *testing.T) {
	authz := allowFn(func(_ context.Context, _, p, _, _ string) (bool, string) {
		return p != "bad", "rbac out of scope"
	})
	api := apiFixture(t, &auditsink.Recorder{}, authz)
	if code, _ := do(t, api, "GET", "app/db", "", "t1", "bad", ""); code != http.StatusForbidden {
		t.Errorf("RBAC-denied read = %d, want 403", code)
	}
}

// minimal ResponseWriter recorder (avoids importing httptest just for this).
type recorder struct {
	code   int
	body   strings.Builder
	header http.Header
}

func newRecorder() *recorder            { return &recorder{code: 200, header: http.Header{}} }
func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(code int) { r.code = code }

var _ io.Writer = (*recorder)(nil)
