// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/netsec"
)

const (
	timestampRequestsPerClientMinute = 30
	timestampRequestsGlobalMinute    = 120
	timestampTrackedClients          = 4096
)

// timestampAdmission bounds signer work before a public request enters the
// protocol worker pool. The global budget also holds when client addresses vary.
type timestampAdmission struct {
	clients *clientRateLimiter
	global  *clientRateLimiter
}

func newTimestampAdmission(perClientMinute, globalMinute, maxClients int) *timestampAdmission {
	return &timestampAdmission{
		clients: newClientRateLimiter(perClientMinute, maxClients),
		global:  newClientRateLimiter(globalMinute, 1),
	}
}

func (a *timestampAdmission) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		if wait, ok := a.clients.allow(netsec.ClientIP(r), now); !ok {
			writeTimestampLimit(w, wait)
			return
		}
		if wait, ok := a.global.allow("all", now); !ok {
			writeTimestampLimit(w, wait)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeTimestampLimit(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
	_ = problem.New(http.StatusTooManyRequests, "timestamp request rate exceeded").Write(w)
}
