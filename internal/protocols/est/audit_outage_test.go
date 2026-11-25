// SPDX-License-Identifier: BUSL-1.1

package est_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/protocols/est"
)

func TestESTReturnsRetryableErrorWhenDecisionCannotBeRecorded(t *testing.T) {
	ca, leaf, _, envelope := serverKeygenFixture(t)
	log := openESTEventLog(t)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	s := est.New(est.Config{
		Enroller: realEnroller{ca: ca}, Auth: allowAuth{}, ProfileName: "fleet", Log: log,
		ServerKeygenEnabled: true, ServerKeygen: &recordingServerKeygen{
			result: est.ServerKeygenResult{CertificateDER: leaf, EnvelopedKeyDER: envelope},
		},
	})
	csr := deviceCSR(t)
	for _, tc := range []struct {
		path string
		name string
		body []byte
	}{
		{"simpleenroll", "enrollment", csr}, {"simplereenroll", "renewal", csr},
		{"serverkeygen", "key generation", csr}, {"simpleenroll", "invalid request", []byte("invalid PKCS10")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/.well-known/est/"+tc.path, b64Body(tc.body))
			req = req.WithContext(est.WithTenant(req.Context(), "tenant-est"))
			req.Header.Set("Content-Type", "application/pkcs10")
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
				t.Fatalf("response status %d, content type %q; want retryable text error", rec.Code, rec.Header().Get("Content-Type"))
			}
			if body := strings.TrimSpace(rec.Body.String()); body != "est: audit unavailable" {
				t.Errorf("unexpected audit failure response (%d bytes)", len(body))
			}
		})
	}
}
