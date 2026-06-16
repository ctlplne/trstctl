package server

import (
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/bulkhead"
)

// bulkheadHandler runs next on the named subsystem's bounded worker pool (AN-7 in
// the live path). When the pool is saturated it sheds fast — 503 with a
// Retry-After for a transient full queue — so a flood on one subsystem can never
// exhaust the capacity another (liveness, readiness, metrics, the signer) depends
// on. The pools are isolated, so saturating the API never starves them.
func bulkheadHandler(set *bulkhead.Set, subsystem string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := make(chan struct{})
		err := set.Submit(subsystem, func() {
			defer close(done)
			next.ServeHTTP(w, r)
		})
		if err != nil {
			var rej *bulkhead.Rejected
			if errors.As(err, &rej) && rej.Retryable() {
				w.Header().Set("Retry-After", "1")
			}
			_ = problem.New(http.StatusServiceUnavailable, "server overloaded: the "+subsystem+" subsystem is saturated").Write(w)
			return
		}
		<-done
	})
}
