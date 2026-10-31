// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
)

// A158: an AD CS issuer configured with a Kerberos keytab authenticates only
// with Negotiate. The keytab is loaded byte-exact (a trailing 0x0a is part of
// the binary file, not a newline to trim), and with no reachable KDC the issue
// fails before any request reaches certsrv: there is no Basic fallback.
func TestExternalADCSWithKerberosNegotiatesAndNeverFallsBackToBasic(t *testing.T) {
	kt := keytab.New()
	// kvno 10 ends the marshaled keytab with byte 0x0a, which a text loader
	// would strip.
	if err := kt.AddEntry("svc-trstctl", "CORP.EXAMPLE", "keytab-derivation-input", time.Now().Add(-time.Hour), 10, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if raw[len(raw)-1] != '\n' {
		t.Fatalf("fixture keytab ends with %#x; the byte-exact load check needs a trailing 0x0a", raw[len(raw)-1])
	}
	keytabPath := filepath.Join(t.TempDir(), "svc.keytab")
	if err := os.WriteFile(keytabPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reached := 0
	certsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(certsrv.Close)
	items, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{{
		ID: "corp-adcs", Type: "adcs", Name: "Corp AD CS", Endpoint: certsrv.URL + "/certsrv", CAConfig: `HOST\CA`, Template: "WebServer",
		KerberosRealm: "CORP.EXAMPLE", KerberosPrincipal: "svc-trstctl", KerberosKDCs: []string{"127.0.0.1:1"},
		KerberosKeytabRef: "file:" + keytabPath, Network: config.ExternalCANetworkConfig{AllowInsecureHTTP: true},
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("construct registry: %v", err)
	}
	implementation, cleanup, err := items[0].Factory(context.Background())
	if err != nil {
		t.Fatalf("build the Kerberos AD CS issuer (the keytab must load byte-exact): %v", err)
	}
	defer cleanup()
	_, err = implementation.Issue(context.Background(), ca.IssueRequest{CSR: []byte("csr-der"), DNSNames: []string{"web01.corp.example"}})
	if err == nil || !strings.Contains(err.Error(), "Negotiate authentication failed") {
		t.Fatalf("issue without a KDC = %v; want the Negotiate refusal", err)
	}
	if reached != 0 {
		t.Fatalf("certsrv was reached %d times without Kerberos; want none (no Basic or anonymous fallback)", reached)
	}
}
