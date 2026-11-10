// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/profile"
)

// P15-L10: a certificate profile's refusal at ACME finalize is the client's
// error, as RFC 8555 section 6.7 types it: a name the profile does not permit
// is rejectedIdentifier, and anything else about the request is badCSR, both
// 400. It used to answer 500 serverInternal, telling the client the server had
// failed and to try again.
func TestServedACMEFinalizeAnswersAProfileRefusalAsTheClientsErrorP15L10(t *testing.T) {
	hmacKey, rsaKey := bytes.Repeat([]byte{0x5a}, 32), bytes.Repeat([]byte{0x5b}, 32)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: []config.ACMEExternalAccountBindingKey{
			{KeyID: "scoped", HMACKey: hmacKey, Profile: "internal-only"},
			{KeyID: "rsa", HMACKey: rsaKey, Profile: "rsa-only"},
		}},
	}, func(d *Deps) { d.DefaultProfile = "internal-only" })
	storeServerTestProfile(t, h.store, h.tenant, "internal-only", profile.CertificateProfile{
		Name: "internal-only", ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
		AllowedDNSSuffixes: []string{"internal.example.test"},
	})
	storeServerTestProfile(t, h.store, h.tenant, "rsa-only", profile.CertificateProfile{
		Name: "rsa-only", ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
		AllowedKeyAlgorithms: []string{"RSA"},
	})
	// A 500 sends the ACME client into its retry loop; the deadline bounds it.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	newDriver := func(kid string, key []byte, profileName string) *acmekey.Driver {
		t.Helper()
		account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(account.Destroy)
		d, err := acmekey.NewDriverWithDigestSigner(h.ts.URL+"/directory", nil, h.ts.Client(), account)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(d.Destroy)
		return d.WithExternalAccountBinding(kid, key).WithProfile(profileName)
	}
	driver := newDriver("scoped", hmacKey, "internal-only")
	issue := func(name string) error {
		t.Helper()
		subject, err := crypto.GenerateHostSubjectKey(name, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		defer subject.Destroy()
		_, err = driver.IssueChain(ctx, acmekey.OrderRequest{TenantID: h.tenant, DNSNames: []string{name}, CSR: subject.CSRDER})
		return err
	}
	err := issue("outside.example.test")
	if err == nil || !strings.Contains(err.Error(), "rejectedIdentifier") || !strings.Contains(err.Error(), "does not permit DNS SAN") ||
		strings.Contains(err.Error(), "serverInternal") {
		t.Fatalf("a name the profile does not permit = %v, want rejectedIdentifier naming the refusal", err)
	}
	if err := issue("host.internal.example.test"); err != nil {
		t.Fatalf("a name the profile permits: %v", err)
	}

	// A key the profile does not allow is badCSR.
	driver = newDriver("rsa", rsaKey, "rsa-only")
	err = issue("host.internal.example.test")
	if err == nil || !strings.Contains(err.Error(), "badCSR") || !strings.Contains(err.Error(), "does not allow key algorithm") ||
		strings.Contains(err.Error(), "serverInternal") {
		t.Fatalf("a key algorithm the profile does not allow = %v, want badCSR naming the refusal", err)
	}
}
