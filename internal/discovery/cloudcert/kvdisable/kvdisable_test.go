// SPDX-License-Identifier: BUSL-1.1

package kvdisable

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
)

// vaultDouble answers the Key Vault certificate version get and update calls
// with the shapes the REST reference documents: a certificate bundle with its
// id and attributes. ignore makes the update a no-op.
type vaultDouble struct {
	mu      sync.Mutex
	enabled map[string]bool
	ignore  bool
	calls   []string
}

func (v *vaultDouble) serve(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls = append(v.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	if r.Header.Get("Authorization") != "Bearer write-token" || r.URL.Query().Get("api-version") != "7.4" {
		http.Error(w, `{"error":{"code":"Unauthorized"}}`, http.StatusUnauthorized)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/certificates/")
	enabled, ok := v.enabled[key]
	if !ok {
		http.Error(w, `{"error":{"code":"CertificateNotFound"}}`, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPatch {
		var body struct {
			Attributes struct {
				Enabled *bool `json:"enabled"`
			} `json:"attributes"`
		}
		raw, _ := io.ReadAll(r.Body)
		if json.Unmarshal(raw, &body) != nil || body.Attributes.Enabled == nil {
			http.Error(w, `{"error":{"code":"BadParameter"}}`, http.StatusBadRequest)
			return
		}
		if !v.ignore {
			enabled = *body.Attributes.Enabled
			v.enabled[key] = enabled
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": "https://" + r.Host + "/certificates/" + key,
		"attributes": map[string]any{"enabled": enabled, "updated": 1762250000}})
}

func newVault(t *testing.T) (*vaultDouble, *httptest.Server) {
	t.Helper()
	v := &vaultDouble{enabled: map[string]bool{"web-cert/0123abcd": true}}
	srv := httptest.NewTLSServer(http.HandlerFunc(v.serve))
	t.Cleanup(srv.Close)
	return v, srv
}

func TestDisableDisablesTheExactVersionAndReadsItBack(t *testing.T) {
	v, srv := newVault(t)
	target, err := ParseCertificateID(srv.URL + "/certificates/web-cert/0123abcd")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Disable(context.Background(), Config{Token: cloudcert.StaticToken("write-token"), HTTPClient: srv.Client()}, target)
	if err != nil || res.Enabled || !res.Updated.Equal(time.Unix(1762250000, 0).UTC()) {
		t.Fatalf("disable = %+v %v", res, err)
	}
	if v.enabled["web-cert/0123abcd"] || len(v.calls) != 2 || !strings.HasPrefix(v.calls[0], "PATCH /certificates/web-cert/0123abcd?") ||
		!strings.HasPrefix(v.calls[1], "GET /certificates/web-cert/0123abcd?") {
		t.Fatalf("vault calls = %v, state %v", v.calls, v.enabled)
	}
}

func TestDisableRefusesWhatItCannotProve(t *testing.T) {
	v, srv := newVault(t)
	target, _ := ParseCertificateID(srv.URL + "/certificates/web-cert/0123abcd")
	v.ignore = true
	if _, err := Disable(context.Background(), Config{Token: cloudcert.StaticToken("write-token"), HTTPClient: srv.Client()}, target); err == nil ||
		!strings.Contains(err.Error(), "does not read the certificate version back as disabled") {
		t.Fatalf("an update the vault ignored = %v", err)
	}
	v.ignore = false
	if _, err := Disable(context.Background(), Config{Token: cloudcert.StaticToken("read-only"), HTTPClient: srv.Client()}, target); err == nil ||
		!strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("a refused credential = %v", err)
	}
	missing, _ := ParseCertificateID(srv.URL + "/certificates/web-cert/ffff")
	if _, err := Disable(context.Background(), Config{Token: cloudcert.StaticToken("write-token"), HTTPClient: srv.Client()}, missing); err == nil {
		t.Fatal("a missing version was reported disabled")
	}
	for _, bad := range []string{"http://vault.example/certificates/a/b", "https://vault.example/certificates/a",
		"https://vault.example/keys/a/b", "https://u:p@vault.example/certificates/a/b", "https://vault.example/certificates/a/b?x=1",
		"https://vault.example/certificates/a b/c"} {
		if _, err := ParseCertificateID(bad); err == nil {
			t.Fatalf("%q parsed as a certificate version", bad)
		}
	}
}
