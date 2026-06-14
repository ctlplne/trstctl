package secretstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"trustctl.io/trustctl/internal/auditsink"
)

// Authorizer decides per-secret RBAC + policy (F28) for a principal acting on a
// path. action is "read" or "write". It returns a reason on denial.
type Authorizer interface {
	Allow(ctx context.Context, tenantID, principal, path, action string) (allowed bool, reason string)
}

// APIServer is the external read/write/version/rollback surface over the store
// core (S16.3a): per-secret RBAC + policy gating, cross-tenant denial, and audited
// access decisions. It serves one tenant; a request for any other tenant is denied
// (AN-1).
type APIServer struct {
	store    *Store
	tenantID string
	authz    Authorizer
	audit    auditsink.Auditor
}

// NewAPIServer constructs an APIServer over a single-tenant store.
func NewAPIServer(store *Store, tenantID string, authz Authorizer, audit auditsink.Auditor) *APIServer {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &APIServer{store: store, tenantID: tenantID, authz: authz, audit: audit}
}

// ServeHTTP routes /secrets/<path> requests. The caller's tenant and principal are
// taken from the X-Tenant and X-Principal headers (set by the auth layer).
func (a *APIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Tenant") != a.tenantID { // cross-tenant denial (AN-1)
		a.deny(r, "cross-tenant")
		http.Error(w, "cross-tenant access denied", http.StatusForbidden)
		return
	}
	principal := r.Header.Get("X-Principal")
	path := strings.TrimPrefix(r.URL.Path, "/secrets/")
	if path == "" {
		http.Error(w, "missing secret path", http.StatusBadRequest)
		return
	}
	action := "read"
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		action = "write"
	}
	if a.authz != nil {
		if ok, reason := a.authz.Allow(r.Context(), a.tenantID, principal, path, action); !ok {
			a.deny(r, reason)
			http.Error(w, "access denied: "+reason, http.StatusForbidden)
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Has("versions") {
			fmt.Fprintf(w, "%v", a.store.Versions(path))
			return
		}
		val, ver, err := a.store.Get(r.Context(), path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("X-Version", strconv.Itoa(ver))
		w.Write(val)
	case http.MethodPut:
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		ver, err := a.store.Put(r.Context(), path, body, r.Header.Get("Idempotency-Key"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"version":%d}`, ver)
	case http.MethodPost:
		if v := r.URL.Query().Get("rollback"); v != "" {
			to, err := strconv.Atoi(v)
			if err != nil {
				http.Error(w, "bad rollback version", http.StatusBadRequest)
				return
			}
			ver, err := a.store.Rollback(r.Context(), path, to)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, `{"version":%d}`, ver)
			return
		}
		http.Error(w, "unsupported", http.StatusBadRequest)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
	_ = a.audit.Audit(r.Context(), "secret.access", a.tenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"path":%q,"action":%q,"decision":"allow"}`, principal, path, action)))
}

func (a *APIServer) deny(r *http.Request, reason string) {
	_ = a.audit.Audit(r.Context(), "secret.access.denied", a.tenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"path":%q,"reason":%q}`, r.Header.Get("X-Principal"), r.URL.Path, reason)))
}
