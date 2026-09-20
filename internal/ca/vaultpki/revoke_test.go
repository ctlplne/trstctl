// SPDX-License-Identifier: BUSL-1.1

package vaultpki_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/vaultpki"
)

// Revocation through Vault's PKI engine reaches Vault (epic R2).
//
// Vault revokes by serial, so unlike ACME this needs no copy of the
// certificate. What the test asserts is the same property either way: the
// AUTHORITY was contacted. A Revoke that returns nil without a request having
// been made leaves a compromised certificate valid behind a receipt saying it
// is not.
func TestRevokeReachesVault(t *testing.T) {
	stub := newVaultStub(t, "vault-token-sensitive")
	defer stub.Close()

	p := vaultpki.New(vaultpki.Config{
		Name: "vault-pki", BaseURL: stub.URL(), Token: []byte("vault-token-sensitive"),
		Mount: "pki", Role: "web",
	}, vaultpki.WithHTTPClient(stub.Client()))

	if err := p.Revoke(context.Background(), ca.RevokeRequest{
		TenantID: "tenant-a", Serial: "3f:2a:11", ReasonCode: 1,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	last := stub.LastRequest()
	if !strings.HasSuffix(last.path, "/pki/revoke") {
		t.Fatalf("Vault received a request to %q, want the pki revoke endpoint — a Revoke that "+
			"never reaches Vault leaves the certificate valid", last.path)
	}
	if last.token != "vault-token-sensitive" {
		t.Errorf("revocation did not authenticate to Vault (token %q)", last.token)
	}
}

// A revocation with no serial is refused locally rather than sent as a request
// Vault would reject: "trstctl had nothing to revoke with" is the more useful
// sentence than whatever Vault answers to an empty serial.
func TestRevokeWithoutSerialIsRefusedLocally(t *testing.T) {
	stub := newVaultStub(t, "vault-token-sensitive")
	defer stub.Close()

	p := vaultpki.New(vaultpki.Config{
		Name: "vault-pki", BaseURL: stub.URL(), Token: []byte("vault-token-sensitive"),
		Mount: "pki", Role: "web",
	}, vaultpki.WithHTTPClient(stub.Client()))

	if err := p.Revoke(context.Background(), ca.RevokeRequest{TenantID: "tenant-a"}); err == nil {
		t.Fatal("a revocation with no serial reported success")
	}
	if last := stub.LastRequest(); last.path != "" {
		t.Errorf("a revocation with no serial still reached Vault at %q", last.path)
	}
}

// The capability matrix must match the code.
func TestVaultIsInTheRevokeMatrix(t *testing.T) {
	if !ca.CanRevoke("vaultpki") {
		t.Error("vaultpki implements revocation but the capability matrix says it cannot")
	}
}

func TestRevokeFormatsInventorySerialForVault(t *testing.T) {
	stub := newVaultStub(t, "vault-token-sensitive")
	defer stub.Close()
	p := vaultpki.New(vaultpki.Config{Name: "vault-pki", BaseURL: stub.URL(),
		Token: []byte("vault-token-sensitive"), Mount: "pki", Role: "web"}, vaultpki.WithHTTPClient(stub.Client()))
	for _, tc := range []struct{ input, want string }{
		{"3f2a11", "3f:2a:11"},
		{"f2a11", "0f:2a:11"},
		{"3F:2A:11", "3f:2a:11"},
		{"3f-2a-11", "3f:2a:11"},
	} {
		if err := p.Revoke(t.Context(), ca.RevokeRequest{TenantID: "tenant-a", Serial: tc.input}); err != nil {
			t.Fatal(err)
		}
		if got := stub.LastRequest().serial; got != tc.want {
			t.Errorf("serial %q sent as %q, want Vault lookup key %q", tc.input, got, tc.want)
		}
	}
}

// Stock Vault returns HTTP 200 with data:null and an expiry warning instead of
// revoking an expired leaf. Transport acceptance is not issuer confirmation.
func TestRevokeRequiresVaultConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		confirmed  bool
	}{
		{"expired_warning", `{"data":null,"warnings":["certificate already expired; refusing to add to CRL"]}`, false},
		{"empty_data", `{"data":{}}`, false},
		{"zero_time", `{"data":{"revocation_time":0}}`, false},
		{"negative_time", `{"data":{"revocation_time":-1}}`, false},
		{"queued", `{"data":{"state":"pending"}}`, false},
		{"application_error", `{"data":{"revocation_time":1433269787},"errors":["secret-provider-error"]}`, false},
		{"confirmed", `{"data":{"revocation_time":1433269787}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/pki/revoke" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			plugin := vaultpki.New(vaultpki.Config{BaseURL: server.URL, Token: []byte("local-qa-token"), Mount: "pki", Role: "web"}, vaultpki.WithHTTPClient(server.Client()))
			defer plugin.Destroy()
			err := plugin.Revoke(t.Context(), ca.RevokeRequest{TenantID: "tenant-a", Serial: "3f2a11"})
			if (err == nil) != tc.confirmed {
				t.Fatalf("confirmed=%t, revoke error=%v", tc.confirmed, err)
			}
			if err != nil && (strings.Contains(err.Error(), "secret-provider-error") || strings.Contains(err.Error(), "local-qa-token")) {
				t.Fatal("provider response or credentials escaped in error")
			}
		})
	}
}
