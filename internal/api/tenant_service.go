// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/tenancy"
)

type tenantServiceRequestKey struct{}
type tenantServiceRequest struct {
	tenantID string
	release  func()
}

// Each served HTTP entry point owns the lease through its complete response,
// including narrow listeners that do not pass through API.ServeHTTP.
func serveTenantServiceRequest(w http.ResponseWriter, r *http.Request, next http.Handler) {
	work := &tenantServiceRequest{}
	r = r.WithContext(context.WithValue(r.Context(), tenantServiceRequestKey{}, work))
	defer func() {
		if work.release != nil {
			work.release()
		}
	}()
	next.ServeHTTP(w, r)
}

// Reads retain request-time admission. Mutations hold the shared fence through
// response/idempotency recording, including requests paused after admission.
// A long-lived read stream must not occupy the mutation lock pool indefinitely.
func (a *API) fenceTenantMutation(r *http.Request, tenantID string) error {
	if a.store == nil || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return nil
	}
	work, _ := r.Context().Value(tenantServiceRequestKey{}).(*tenantServiceRequest)
	if work == nil {
		return errors.New("tenant mutation request lifetime is unavailable")
	}
	if work.release != nil {
		if work.tenantID != tenantID {
			return errors.New("tenant mutation cannot change customer")
		}
		return nil
	}
	ctx, release, err := a.store.BeginTenantService(r.Context(), tenantID)
	if err != nil {
		return err
	}
	work.tenantID, work.release = tenantID, release
	*r = *r.WithContext(ctx)
	return nil
}

// WithTenantServiceCheck applies current tenant admission to authenticated
// requests and tenant-attributed public credential exchanges. It is independent
// of the caller's role: an administrator credential cannot undo a suspension.
func WithTenantServiceCheck(check tenancy.ServiceCheck) Option {
	return func(c *config) { c.tenantServiceCheck = check }
}

func (a *API) checkTenantService(r *http.Request, tenantID string) error {
	err := a.fenceTenantMutation(r, tenantID)
	if err == nil {
		err = a.tenantServiceCheck.Check(r.Context(), tenantID)
	}
	return err
}

func (a *API) allowTenantService(w http.ResponseWriter, r *http.Request, tenantID string) bool {
	err := a.checkTenantService(r, tenantID)
	if err == nil {
		return true
	}
	if errors.Is(err, tenancy.ErrServiceUnavailable) {
		a.writeProblem(w, problem.New(http.StatusForbidden, "tenant service is suspended or offboarded"))
	} else {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "tenant service authority is unavailable; retry later"))
	}
	return false
}
