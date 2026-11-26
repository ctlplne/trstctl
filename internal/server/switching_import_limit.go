// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
)

// switchingImportAdmission lets one large export occupy the shared server at
// a time. The permit is taken before the API bulkhead reads and copies its body.
func switchingImportAdmission(next http.Handler) http.Handler {
	slot := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			_ = problem.New(http.StatusServiceUnavailable, "a switching import is already being processed; retry shortly").Write(w)
		}
	})
}
