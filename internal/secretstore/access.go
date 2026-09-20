// SPDX-License-Identifier: BUSL-1.1

package secretstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/auditsink"
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
	// Secret material and version metadata are never an HTML context: an
	// explicit content type plus nosniff stops a browser from sniffing secret
	// bytes into a renderable type (CWE-79 / CWE-116).
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Has("versions") {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if _, err := fmt.Fprintf(w, "%v", a.store.Versions(path)); err != nil {
				return
			}
			return
		}
		val, ver, err := a.store.Get(r.Context(), path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("X-Version", strconv.Itoa(ver))
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := w.Write(val); err != nil { // #nosec G705 -- the secret read API returns the secret by contract; served as octet-stream with nosniff, never an HTML context (CWE-79)
			return
		}
	case http.MethodPut:
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		ver, err := a.store.Put(r.Context(), path, body, r.Header.Get("Idempotency-Key"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprintf(w, `{"version":%d}`, ver); err != nil { // #nosec G705 -- fixed-shape JSON carrying only an integer version, served as application/json with nosniff (CWE-79)
			return
		}
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
			w.Header().Set("Content-Type", "application/json")
			if _, err := fmt.Fprintf(w, `{"version":%d}`, ver); err != nil { // #nosec G705 -- fixed-shape JSON carrying only an integer version, served as application/json with nosniff (CWE-79)
				return
			}
			return
		}
		http.Error(w, "unsupported", http.StatusBadRequest)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
	_ = auditsink.Emit(r.Context(), a.audit, nil, "secret.access", a.tenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"path":%q,"action":%q,"decision":"allow"}`, principal, path, action)))
}

func (a *APIServer) deny(r *http.Request, reason string) {
	_ = auditsink.Emit(r.Context(), a.audit, nil, "secret.access.denied", a.tenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"path":%q,"reason":%q}`, r.Header.Get("X-Principal"), r.URL.Path, reason)))
}
