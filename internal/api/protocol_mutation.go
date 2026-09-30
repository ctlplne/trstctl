// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
)

// ProtocolMutationFunc performs one mutation on a protocol surface that lives
// outside the /api/v1 route table. ctx carries the authenticated principal and
// event actor; r is the original request with its body unread.
type ProtocolMutationFunc func(ctx context.Context, tenantID string, r *http.Request) (status int, body any, err error)

// ProtocolMutation serves a mutating protocol route (the raw /ssh/ issuance and
// revocation routes) under exactly the guard an API mutation gets: bearer or
// session authentication, RBAC for perm, the ABAC deny overlay, the per-tenant
// rate limit, the event actor, and Idempotency-Key replay (AN-5). A protocol
// surface that re-implemented only authentication silently skipped the rest.
func (a *API) ProtocolMutation(perm authz.Permission, fn ProtocolMutationFunc) http.HandlerFunc {
	if perm == "" || fn == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			a.writeProblem(w, problem.New(http.StatusInternalServerError, "protocol mutation is missing its permission or handler"))
		}
	}
	guarded := a.guard(perm, nil, func(w http.ResponseWriter, r *http.Request) {
		a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
			return fn(ctx, tenantID, r.WithContext(ctx))
		})
	})
	// Raw protocol routes bypass API.ServeHTTP. They still need the tenant
	// service lease for the entire request, including idempotency recording.
	return func(w http.ResponseWriter, r *http.Request) {
		serveTenantServiceRequest(w, r, guarded)
	}
}

// ProtocolRequestError reports a malformed protocol request with a 4xx status
// and a caller-facing detail. Any other status is reported as 400.
func ProtocolRequestError(status int, detail string) error {
	if status < 400 || status > 499 {
		status = http.StatusBadRequest
	}
	return errStatus(status, detail)
}
