// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSwitchingImportAdmissionRejectsConcurrentBodies(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	h := switchingImportAdmission(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/switching/imports/preview", nil))
	}()
	<-entered
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/switching/imports", nil))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("concurrent import = %d, retry-after %q", response.Code, response.Header().Get("Retry-After"))
	}
	close(release)
	<-done
	response = httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/switching/imports", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("import after release = %d, want 200", response.Code)
	}
}
