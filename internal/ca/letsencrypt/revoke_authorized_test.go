// SPDX-License-Identifier: BUSL-1.1

package letsencrypt_test

import (
	"context"
	"encoding/pem"
	"net"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// N10: revoking a certificate another account requested (RFC 8555 §7.6).
// trstctl's account has no issuance record for it, so it first obtains valid
// authorizations for every name in the certificate, then asks; the authority
// accepts that from an account authorized for all of the names and refuses it
// from an account that is not.
func TestRevokeWithAuthorizationsRevokesAnotherAccountsCertificateN10(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.EnforceRevocationAuthority()
	ctx := context.Background()

	// Another account requested two certificates for names the tenant owns.
	other := newRemoteAccountPlugin(t, "someone-else", srv.DirectoryURL())
	issue := func(names ...string) ([]byte, certinfo.Info) {
		t.Helper()
		issued, err := other.Issue(ctx, ca.IssueRequest{TenantID: "tenant-other", CSR: buildCSR(t, names[0], names), DNSNames: names})
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(issued.CertificatePEM)
		info, err := certinfo.Inspect(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return block.Bytes, info
	}
	rogueDER, rogue := issue("rogue.corp.test", "www.rogue.corp.test")
	secondDER, second := issue("second.corp.test")
	owner := srv.OwnerOf(rogue.SerialNumber)

	trstctl := newRemoteAccountPlugin(t, "letsencrypt", srv.DirectoryURL())
	// Without authorizations for its names, trstctl's account is refused.
	err = trstctl.Revoke(ctx, ca.RevokeRequest{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secondDER}), ReasonCode: 1})
	if err == nil || srv.RevokedBy(second.SerialNumber) != "" {
		t.Fatalf("an unauthorized account revoked another account's certificate: %v", err)
	}

	if err := trstctl.RevokeWithAuthorizations(ctx, "tenant-a", rogueDER, 1); err != nil {
		t.Fatalf("revoke with authorizations: %v", err)
	}
	by := srv.RevokedBy(rogue.SerialNumber)
	if by == "" || by == owner {
		t.Fatalf("the certificate was revoked by %q (issued by %q); want trstctl's own account", by, owner)
	}
	// Asking again finds it revoked: the authority's alreadyRevoked confirms.
	if err := trstctl.RevokeWithAuthorizations(ctx, "tenant-a", rogueDER, 1); err != nil {
		t.Fatalf("a repeated revocation: %v", err)
	}
	if srv.RevokedBy(second.SerialNumber) != "" {
		t.Fatal("the other certificate was revoked too")
	}
}

// A certificate with an IP identifier cannot be revoked by proving control of
// DNS names, and bytes that are no certificate are not sent; nothing reaches
// the authority.
func TestRevokeWithAuthorizationsRefusesWhatItCannotAuthorizeN10(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.EnforceRevocationAuthority()
	ctx := context.Background()
	other := newRemoteAccountPlugin(t, "someone-else", srv.DirectoryURL())
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "ip.corp.test",
		DNSNames: []string{"ip.corp.test"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.10")}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := other.Issue(ctx, ca.IssueRequest{TenantID: "tenant-other", CSR: csr, DNSNames: []string{"ip.corp.test"}})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	plugin := newRemoteAccountPlugin(t, "letsencrypt", srv.DirectoryURL())
	if err := plugin.RevokeWithAuthorizations(ctx, "tenant-a", block.Bytes, 1); err == nil || !strings.Contains(err.Error(), "all DNS names") {
		t.Fatalf("a certificate with an IP identifier = %v", err)
	}
	if err := plugin.RevokeWithAuthorizations(ctx, "tenant-a", []byte("not a certificate"), 1); err == nil {
		t.Fatal("bytes that are no certificate were sent for revocation")
	}
	if len(srv.Revocations()) != 0 {
		t.Fatalf("the authority received %d revocations", len(srv.Revocations()))
	}
}
