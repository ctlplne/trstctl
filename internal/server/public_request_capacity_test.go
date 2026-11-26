// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
)

func TestOneClientCannotOccupyEveryAPIWorker(t *testing.T) {
	set := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 3, Queue: 0})
	defer set.Close()
	limit := newClientConcurrencyLimit(2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorkers := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWorkers()
	entered := make(chan struct{}, 2)
	h := limit.wrap(bulkheadHandler(set, bulkhead.SubsystemAPI, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			entered <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	finished := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			r := httptest.NewRequest(http.MethodPost, "/slow", nil)
			r.RemoteAddr = "192.0.2.10:1234"
			h.ServeHTTP(httptest.NewRecorder(), r)
			finished <- struct{}{}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("slow request did not occupy the expected worker")
		}
	}
	blocked := httptest.NewRequest(http.MethodPost, "/slow", nil)
	blocked.RemoteAddr = "192.0.2.10:5678"
	response := httptest.NewRecorder()
	h.ServeHTTP(response, blocked)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("third request from one client = %d, Retry-After %q", response.Code, response.Header().Get("Retry-After"))
	}
	other := httptest.NewRequest(http.MethodPost, "/fast", nil)
	other.RemoteAddr = "192.0.2.11:1234"
	response = httptest.NewRecorder()
	h.ServeHTTP(response, other)
	if response.Code != http.StatusNoContent {
		t.Fatalf("unrelated client lost the remaining worker: %d", response.Code)
	}
	releaseWorkers()
	<-finished
	<-finished
}

func TestMainHTTPServerHasFiniteBodyAndResponseDeadlines(t *testing.T) {
	srv := mainHTTPServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if srv.ReadTimeout <= srv.ReadHeaderTimeout || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("main HTTP deadlines are unbounded or do not allow a body: read=%s header=%s write=%s idle=%s", srv.ReadTimeout, srv.ReadHeaderTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}

func TestMainHTTPBodyDeadlineReleasesAStalledRead(t *testing.T) {
	finished := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		finished <- err
		w.WriteHeader(http.StatusBadRequest)
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.Config = mainHTTPServer(handler)
	srv.Config.ReadTimeout = 100 * time.Millisecond
	srv.Start()
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprint(conn, "POST /slow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\na"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("incomplete body did not hit the read deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("slow body kept the handler blocked past the deadline")
	}
}

func TestPublicAndRevocationRoutesDoNotQueueBehindAPIWorkers(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	if h.srv.revoc == nil {
		t.Fatal("served CA did not mount revocation routes")
	}
	apiPool := h.srv.bulk.Pool(bulkhead.SubsystemAPI)
	workers := apiPool.Stats().Workers
	release := make(chan struct{})
	defer close(release)
	started := make(chan struct{}, workers)
	for i := 0; i < workers; i++ {
		if err := apiPool.Submit(func() { started <- struct{}{}; <-release }); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < workers; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("API worker did not start")
		}
	}
	for _, path := range []string{"/auth/methods", "/crl/" + servedTestTenant} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.ts.URL+path, nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			cancel()
			t.Fatalf("%s queued behind the API pool: %v", path, err)
		}
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatalf("%s shed with the API pool saturated", path)
		}
	}
}
