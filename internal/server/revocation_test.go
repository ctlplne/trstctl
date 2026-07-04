// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/base64"
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

func TestOCSPHandlerRejectsOverLimitBody(t *testing.T) {
	svc := &revocationService{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ocsp/{tenant}", svc.ocspHandler())

	req := httptest.NewRequest(http.MethodPost, "/ocsp/11111111-1111-1111-1111-111111111111", bytes.NewReader(bytes.Repeat([]byte("x"), (1<<16)+1)))
	req.Header.Set("Content-Type", "application/ocsp-request")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit OCSP status = %d, want 413", rec.Code)
	}
}

// TestOCSPGETRequestTooLarge proves FUZZ-005: the base64-in-path GET form is
// capped like the POST body. Before the fix the GET path base64-decoded the
// {b64request} segment directly (no cap), so a hostile client could force an
// unbounded decode-buffer allocation that the POST path already rejects. An
// over-cap encoded value is now rejected with 413 BEFORE base64 decode runs.
func TestOCSPGETRequestTooLarge(t *testing.T) {
	svc := &revocationService{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ocsp/{tenant}/{b64request}", svc.ocspHandler())

	// base64.StdEncoding.EncodedLen(64 KiB) is the largest legitimate encoded
	// length; one full base64 quantum (4 chars) past it must be rejected. 'A' is a
	// valid base64 symbol, so the value would decode fine if it were not capped —
	// this proves the cap, not a base64 parse error.
	const maxOCSPRequest = 1 << 16
	over := base64.StdEncoding.EncodedLen(maxOCSPRequest) + 4
	enc := strings.Repeat("A", over)

	req := httptest.NewRequest(http.MethodGet, "/ocsp/11111111-1111-1111-1111-111111111111/"+enc, nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap GET OCSP status = %d, want 413", rec.Code)
	}
}
