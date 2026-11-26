// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"net/http"
	"sync"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/netsec"
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

// clientConcurrencyLimit keeps one peer from holding every worker while it
// dribbles a POST body. The trusted-proxy middleware resolves the client before
// this wrapper runs; an untrusted X-Forwarded-For cannot choose a new bucket.
type clientConcurrencyLimit struct {
	mu        sync.Mutex
	active    map[string]int
	perClient int
}

func newClientConcurrencyLimit(perClient int) *clientConcurrencyLimit {
	if perClient < 1 {
		perClient = 1
	}
	return &clientConcurrencyLimit{active: make(map[string]int), perClient: perClient}
}

func (l *clientConcurrencyLimit) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}
		client := netsec.ClientIP(r)
		l.mu.Lock()
		if l.active[client] >= l.perClient {
			l.mu.Unlock()
			w.Header().Set("Retry-After", "1")
			_ = problem.New(http.StatusTooManyRequests, "too many in-flight requests from this client").Write(w)
			return
		}
		l.active[client]++
		l.mu.Unlock()
		defer func() {
			l.mu.Lock()
			l.active[client]--
			if l.active[client] == 0 {
				delete(l.active, client)
			}
			l.mu.Unlock()
		}()
		next.ServeHTTP(w, r)
	})
}

func clientLimitForPool(set *bulkhead.Set, subsystem string) *clientConcurrencyLimit {
	if pool := set.Pool(subsystem); pool != nil {
		return newClientConcurrencyLimit(max(1, pool.Stats().Workers/2))
	}
	return newClientConcurrencyLimit(1)
}
