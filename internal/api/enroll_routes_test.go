package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

// enrollOnlyEnroller is a minimal BootstrapEnroller so api.New mounts the bootstrap
// route without the full enrollment authority.
type enrollOnlyEnroller struct{}

func (enrollOnlyEnroller) EnrollBootstrap(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"), nil
}
func (enrollOnlyEnroller) CABundlePEM() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")
}

// TestEnrollRoutesServed pins the EXACT served /enroll/* route set of the running
// binary (DOCS-001). The composition mounts ONLY POST /enroll/bootstrap; renewal is
// library-complete (internal/agent/enroll has EnrollRenewal + a POST /enroll/renewal
// handler) but is NOT wired into the served API, so /enroll/renewal must 404 against
// the running binary. enrollment-protocols.md was corrected to this reality, and this
// test guards it: if renewal is ever mounted (EXC-WIRE-02 closes), this test must be
// updated alongside the doc — and if someone re-claims renewal is served without
// mounting it, the doc reality-test (docs/enroll_routes_test.go) fails.
func TestEnrollRoutesServed(t *testing.T) {
	a := api.New(nil, nil, nil, api.WithAgentEnroller(enrollOnlyEnroller{}))
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]string{
		"token": "tok",
		"csr":   base64.StdEncoding.EncodeToString([]byte("csr-der")),
	})

	post := func(path string) int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Bootstrap IS served: it must not 404 (the stub enroller returns a chain → 200).
	if code := post("/enroll/bootstrap"); code == http.StatusNotFound {
		t.Errorf("POST /enroll/bootstrap should be served, got 404")
	}

	// Renewal is NOT served by the running binary: it must 404 (DOCS-001). A non-404
	// here means renewal was mounted — update enrollment-protocols.md and this test.
	if code := post("/enroll/renewal"); code != http.StatusNotFound {
		t.Errorf("POST /enroll/renewal is documented as not-yet-mounted (DOCS-001) but returned %d, not 404 — if it was wired (EXC-WIRE-02), update the docs and this test", code)
	}

	// And there is no served reenroll alias either.
	if code := post("/enroll/reenroll"); code != http.StatusNotFound {
		t.Errorf("POST /enroll/reenroll should not be served, got %d", code)
	}
}
