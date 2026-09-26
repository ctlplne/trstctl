// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/tenancy"
)

// tenantProtocolAdmission protects the full request of a protocol with one
// configured tenant, including non-signing mutations such as ACME account/order
// creation. Protocol authentication remains in the normal handler; its service
// fence also keeps an admitted request ahead of suspension or erasure.
func tenantProtocolAdmission(work tenancy.ServiceWork, check tenancy.ServiceCheck, tenantID string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, release, err := work.Begin(r.Context(), tenantID)
		if err == nil {
			defer release()
			r = r.WithContext(ctx)
			err = check.Check(ctx, tenantID)
		}
		if err != nil {
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
