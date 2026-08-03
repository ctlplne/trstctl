// SPDX-License-Identifier: MPL-2.0

package vaultpki_test

import (
	"context"
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
