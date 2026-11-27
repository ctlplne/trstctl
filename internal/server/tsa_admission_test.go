// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTimestampAdmissionBoundsEachClientAndAllClients(t *testing.T) {
	called := 0
	h := newTimestampAdmission(2, 3, 8).wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func(addr string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/tsa", nil)
		r.RemoteAddr = addr
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for range 2 {
		if got := request("192.0.2.1:5000").Code; got != http.StatusNoContent {
			t.Fatalf("first client status = %d", got)
		}
	}
	if got := request("192.0.2.1:5000"); got.Code != http.StatusTooManyRequests || got.Header().Get("Retry-After") == "" {
		t.Fatalf("client limit status = %d, retry-after = %q", got.Code, got.Header().Get("Retry-After"))
	}
	if got := request("192.0.2.2:5000").Code; got != http.StatusNoContent {
		t.Fatalf("second client status = %d", got)
	}
	if got := request("192.0.2.3:5000"); got.Code != http.StatusTooManyRequests || got.Header().Get("Retry-After") == "" {
		t.Fatalf("global limit status = %d, retry-after = %q", got.Code, got.Header().Get("Retry-After"))
	}
	if called != 3 {
		t.Fatalf("upstream called %d times, want 3", called)
	}
}
