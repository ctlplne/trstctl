// SPDX-License-Identifier: BUSL-1.1

package letsencrypt_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/crypto"
)

// A177: against an authority that requires an external account binding
// (RFC 8555 §7.3.4), registration without one or with the wrong MAC key is
// refused before any order, and with the right binding the plugin registers
// once, issues, reuses the account and revokes.
func TestPluginPresentsExternalAccountBindingToAnEABGatedAuthority(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	hmacKey := bytes.Repeat([]byte{0x7a}, 32)
	srv.RequireEAB("partner-kid-42", hmacKey)
	ctx := context.Background()
	csr := buildCSR(t, "eab.acme.test", []string{"eab.acme.test"})
	issue := func(p *letsencrypt.Plugin) (ca.Certificate, error) {
		return p.Issue(ctx, ca.IssueRequest{TenantID: "t1", CSR: csr, DNSNames: []string{"eab.acme.test"}, TTL: 24 * time.Hour})
	}
	build := func(opts ...letsencrypt.Option) *letsencrypt.Plugin {
		t.Helper()
		account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(account.Destroy)
		plugin, err := letsencrypt.NewPluginWithRemoteAccountSigner("partner-ca", srv.DirectoryURL(), http.DefaultClient, account, opts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(plugin.Destroy)
		return plugin
	}

	// The plugin sanitizes upstream errors, so the refusal class is read from
	// the authority: what matters is that no order was placed and why.
	if _, err := issue(build()); err == nil || !strings.HasSuffix(srv.LastAccountProblem(), ":externalAccountRequired") {
		t.Fatalf("registration without a binding = %v (authority said %q), want the authority's externalAccountRequired refusal", err, srv.LastAccountProblem())
	}
	if _, err := issue(build(letsencrypt.WithExternalAccountBinding("partner-kid-42", bytes.Repeat([]byte{0x01}, 32)))); err == nil || !strings.HasSuffix(srv.LastAccountProblem(), ":unauthorized") {
		t.Fatalf("registration with the wrong MAC key = %v (authority said %q), want unauthorized", err, srv.LastAccountProblem())
	}
	if _, err := issue(build(letsencrypt.WithExternalAccountBinding("other-kid", hmacKey))); err == nil || !strings.HasSuffix(srv.LastAccountProblem(), ":unauthorized") {
		t.Fatalf("registration under an unknown kid = %v (authority said %q), want unauthorized", err, srv.LastAccountProblem())
	}
	if srv.EABRegistrations() != 0 {
		t.Fatalf("%d bindings verified before a correct one was presented", srv.EABRegistrations())
	}

	// The caller keeps custody of its own buffer: wiping it after construction
	// must not break the driver's copy.
	callerKey := append([]byte(nil), hmacKey...)
	bound := build(letsencrypt.WithExternalAccountBinding("partner-kid-42", callerKey))
	for i := range callerKey {
		callerKey[i] = 0
	}
	cert, err := issue(bound)
	if err != nil {
		t.Fatalf("issue with the binding: %v", err)
	}
	if cert.Serial == "" || len(cert.CertificatePEM) == 0 {
		t.Fatalf("issued certificate = %+v", cert)
	}
	if srv.EABRegistrations() != 1 {
		t.Fatalf("verified bindings = %d, want 1", srv.EABRegistrations())
	}
	// Renewal through the same plugin reuses the registered account.
	renewed, err := issue(bound)
	if err != nil {
		t.Fatalf("second issuance (renewal) with the binding: %v", err)
	}
	if renewed.Serial == cert.Serial {
		t.Fatal("renewal returned the first certificate")
	}
	if err := bound.Revoke(ctx, ca.RevokeRequest{TenantID: "t1", Serial: renewed.Serial, CertificatePEM: renewed.CertificatePEM}); err != nil {
		t.Fatalf("revoke with the binding: %v", err)
	}
	if got := srv.Revocations(); len(got) != 1 {
		t.Fatalf("authority recorded %d revocations, want 1", len(got))
	}
	if bytes.Contains(cert.CertificatePEM, hmacKey) {
		t.Fatal("the MAC key leaked into the issued material")
	}
}

// A56: the client requests the configured draft-ietf-acme-profiles profile on
// every order, only when the authority advertises it; an unadvertised name is
// refused before any order exists.
func TestPluginRequestsTheConfiguredProfileOnlyWhenAdvertised(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	srv.AdvertiseProfiles(map[string]string{"short": "six-day leaves", "classic": "ninety-day leaves"})
	ctx := context.Background()
	csr := buildCSR(t, "profile.acme.test", []string{"profile.acme.test"})
	build := func(opts ...letsencrypt.Option) *letsencrypt.Plugin {
		t.Helper()
		account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(account.Destroy)
		plugin, err := letsencrypt.NewPluginWithRemoteAccountSigner("profiled-ca", srv.DirectoryURL(), http.DefaultClient, account, opts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(plugin.Destroy)
		return plugin
	}
	issue := func(p *letsencrypt.Plugin) (ca.Certificate, error) {
		return p.Issue(ctx, ca.IssueRequest{TenantID: "t1", CSR: csr, DNSNames: []string{"profile.acme.test"}, TTL: 24 * time.Hour})
	}
	if _, err := issue(build(letsencrypt.WithProfile("tenday"))); err == nil {
		t.Fatal("an unadvertised profile must be refused before an order exists")
	}
	if got := srv.OrderProfiles(); len(got) != 0 {
		t.Fatalf("an order was created for an unadvertised profile: %v", got)
	}
	cert, err := issue(build(letsencrypt.WithProfile("short")))
	if err != nil {
		t.Fatalf("issue with an advertised profile: %v", err)
	}
	if cert.Serial == "" {
		t.Fatal("no certificate issued")
	}
	if _, err := issue(build()); err != nil {
		t.Fatalf("issue without a profile: %v", err)
	}
	if got := srv.OrderProfiles(); len(got) != 2 || got[0] != "short" || got[1] != "" {
		t.Fatalf("orders requested profiles %v, want [short \"\"]", got)
	}
}
