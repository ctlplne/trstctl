// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/tenancy"
)

// WithTenantServiceCheck applies current tenant admission to authenticated
// requests and tenant-attributed public credential exchanges. It is independent
// of the caller's role: an administrator credential cannot undo a suspension.
func WithTenantServiceCheck(check tenancy.ServiceCheck) Option {
	return func(c *config) { c.tenantServiceCheck = check }
}

func (a *API) allowTenantService(w http.ResponseWriter, r *http.Request, tenantID string) bool {
	err := a.tenantServiceCheck.Check(r.Context(), tenantID)
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
