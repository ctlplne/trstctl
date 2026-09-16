// SPDX-License-Identifier: MPL-2.0

package server

import (
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/tenancy"
)

// tenantProtocolAdmission is for a protocol with one configured tenant and no
// per-user principal, such as the timestamp authority. Authentication and tenant
// attribution for the other protocols remain in their normal adapters.
func tenantProtocolAdmission(check tenancy.ServiceCheck, tenantID string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := check.Check(r.Context(), tenantID); err != nil {
			code := http.StatusServiceUnavailable
			if errors.Is(err, tenancy.ErrServiceUnavailable) {
				code = http.StatusForbidden
			}
			http.Error(w, "tenant service is unavailable", code)
			return
		}
		next.ServeHTTP(w, r)
	})
}
