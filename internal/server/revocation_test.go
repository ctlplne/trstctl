package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOCSPHandlerMalformedDERIsBadRequest(t *testing.T) {
	svc := &revocationService{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ocsp/{tenant}", svc.ocspHandler())

	req := httptest.NewRequest(http.MethodPost, "/ocsp/11111111-1111-1111-1111-111111111111", strings.NewReader("\x30\x03\x02\x01\x00"))
	req.Header.Set("Content-Type", "application/ocsp-request")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed OCSP DER status = %d, want 400", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "malformed request") {
		t.Fatalf("malformed OCSP response body = %q, want a sanitized malformed-request error", body)
	}
}
