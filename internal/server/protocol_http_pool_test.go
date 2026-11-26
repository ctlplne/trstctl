// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
)

func occupyProtocolTestPool(t *testing.T, pool *bulkhead.Pool) func() {
	t.Helper()
	release := make(chan struct{})
	started := make(chan struct{})
	deadline := time.Now().Add(time.Second)
	for {
		if err := pool.Submit(func() { close(started); <-release }); err == nil {
			<-started
			return func() { close(release) }
		}
		if time.Now().After(deadline) {
			t.Fatal("could not occupy worker")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestServedProtocolHTTPDoesNotConsumeAPIWorkers(t *testing.T) {
	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 1, Queue: 0},
		bulkhead.Config{Name: bulkhead.SubsystemProtocolHTTP, Workers: 1, Queue: 0},
	)
	defer set.Close()
	release := occupyProtocolTestPool(t, set.Pool(bulkhead.SubsystemAPI))
	defer release()
	mux := http.NewServeMux()
	(&servedProtocols{est: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}).routes(mux, set)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/est/cacerts", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("protocol request consumed a saturated API worker: %d", response.Code)
	}
}
