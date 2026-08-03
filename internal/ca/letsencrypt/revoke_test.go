// SPDX-License-Identifier: MPL-2.0

package letsencrypt_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
)

// Revocation through the ACME authority, proven end to end (epic R2).
//
// The acceptance criterion is specifically "no silent no-op", so what this
// asserts is not that Revoke returned nil — it is that the AUTHORITY received a
// revoke-cert request. An operator revoking a compromised key and being told it
// worked, while the authority still considers the certificate valid, is worse
// than being told trstctl cannot do it: the second sends them to the vendor
// console, the first sends them home.
func TestRevokeReachesTheACMEAuthority(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)

	plugin := newRemoteAccountPlugin(t, "letsencrypt", srv.DirectoryURL())
	ctx := context.Background()

	issued, err := plugin.Issue(ctx, ca.IssueRequest{
		CSR:      buildCSR(t, "revoke.example.test", []string{"revoke.example.test"}),
		DNSNames: []string{"revoke.example.test"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(issued.CertificatePEM) == 0 {
		t.Fatal("precondition: nothing was issued to revoke")
	}
	if before := len(srv.Revocations()); before != 0 {
		t.Fatalf("precondition: authority already saw %d revocations", before)
	}

	if err := plugin.Revoke(ctx, ca.RevokeRequest{
		Serial:         issued.Serial,
		CertificatePEM: issued.CertificatePEM,
		ReasonCode:     1, // keyCompromise
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if got := len(srv.Revocations()); got != 1 {
		t.Fatalf("the authority received %d revoke-cert requests, want 1 — a Revoke that "+
			"returns nil without reaching the authority leaves a compromised certificate "+
			"live behind a receipt that says otherwise", got)
	}
}

// ACME revokes by certificate bytes, not by serial. A request carrying only a
// serial must be REFUSED, not sent as something the protocol cannot express.
func TestRevokeWithoutTheCertificateIsRefused(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)

	plugin := newRemoteAccountPlugin(t, "letsencrypt", srv.DirectoryURL())
	err = plugin.Revoke(context.Background(), ca.RevokeRequest{Serial: "01"})
	if err == nil {
		t.Fatal("a revocation with no certificate reported success")
	}
	if !errors.Is(err, ca.ErrRevocationUnsupported) {
		t.Errorf("error = %v; want ErrRevocationUnsupported — the operator needs to know this "+
			"is a limit of what ACME offers, not a transient failure to retry", err)
	}
	if got := len(srv.Revocations()); got != 0 {
		t.Errorf("the authority received %d requests for a revocation that cannot be expressed", got)
	}
}

// The capability matrix must match the interface: letsencrypt claims revoke and
// implements it.
func TestLetsEncryptIsInTheRevokeMatrix(t *testing.T) {
	if !ca.CanRevoke("letsencrypt") {
		t.Error("letsencrypt implements Revoker but the capability matrix says it cannot revoke")
	}
	var _ ca.Revoker = (*letsencrypt.Plugin)(nil)
}
