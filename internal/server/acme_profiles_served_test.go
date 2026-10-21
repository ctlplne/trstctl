// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/profile"
)

// A55/A56 on the served ACME mount: the directory advertises the default and
// every credential-pinned profile; an order under a credential that pins a
// trust-authenticated profile is issued under it (ready without challenges)
// while an unpinned credential gets the public-trust default; a client that
// requests the advertised pinned profile issues end to end, and one that asks
// for a different profile than its credential pins is refused with
// invalidProfile before any order exists.
func TestServedACMEProfilesPerCredentialAndOnRequest(t *testing.T) {
	pinnedKey := bytes.Repeat([]byte{0x51}, 32)
	plainKey := bytes.Repeat([]byte{0x52}, 32)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: []config.ACMEExternalAccountBindingKey{
			{KeyID: "pinned", HMACKey: pinnedKey, Profile: "internal-acme"},
			{KeyID: "plain", HMACKey: plainKey},
		}},
	}, func(d *Deps) { d.DefaultProfile = "public-acme" })
	storeServerTestProfile(t, h.store, h.tenant, "public-acme", profile.CertificateProfile{
		Name: "public-acme", ACMEAuthMode: profile.ACMEAuthModePublicTrust,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
	})
	storeServerTestProfile(t, h.store, h.tenant, "internal-acme", profile.CertificateProfile{
		Name: "internal-acme", ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
	})
	ctx := context.Background()

	// The directory advertises both profiles.
	res, err := h.ts.Client().Get(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	var directory struct {
		Meta struct {
			Profiles map[string]string `json:"profiles"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(res.Body).Decode(&directory); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if _, ok := directory.Meta.Profiles["public-acme"]; !ok {
		t.Fatalf("directory does not advertise the default profile: %v", directory.Meta.Profiles)
	}
	if _, ok := directory.Meta.Profiles["internal-acme"]; !ok {
		t.Fatalf("directory does not advertise the credential-pinned profile: %v", directory.Meta.Profiles)
	}

	// A55: the pinned credential's orders are issued under its profile, which
	// here means trust-authenticated orders with no challenges to solve.
	pinned := registerWithEAB(t, h, "pinned", pinnedKey)
	order, err := pinned.AuthorizeOrder(ctx, xacme.DomainIDs("pinned.internal.example.test"))
	if err != nil {
		t.Fatalf("order under the pinned credential: %v", err)
	}
	if order.Status != xacme.StatusReady {
		t.Fatalf("pinned credential order status = %q, want ready under the trust-authenticated profile", order.Status)
	}
	plain := registerWithEAB(t, h, "plain", plainKey)
	order, err = plain.AuthorizeOrder(ctx, xacme.DomainIDs("plain.example.test"))
	if err != nil {
		t.Fatalf("order under the unpinned credential: %v", err)
	}
	if order.Status != xacme.StatusPending {
		t.Fatalf("unpinned credential order status = %q, want pending under the public-trust default", order.Status)
	}

	// A56: a client that asks for the advertised pinned profile issues end to
	// end; one that asks for the other profile is refused before any order.
	account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(account.Destroy)
	subject, err := crypto.GenerateHostSubjectKey("client.internal.example.test", []string{"client.internal.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	driver, err := acmekey.NewDriverWithDigestSigner(h.ts.URL+"/directory", nil, h.ts.Client(), account)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(driver.Destroy)
	driver = driver.WithExternalAccountBinding("pinned", pinnedKey).WithProfile("public-acme")
	if _, err := driver.IssueChain(ctx, acmekey.OrderRequest{TenantID: h.tenant, DNSNames: []string{"client.internal.example.test"}, CSR: subject.CSRDER}); err == nil || !strings.Contains(err.Error(), "invalidProfile") {
		t.Fatalf("requesting a profile the credential does not pin = %v, want invalidProfile", err)
	}
	driver = driver.WithProfile("internal-acme")
	chain, err := driver.IssueChain(ctx, acmekey.OrderRequest{TenantID: h.tenant, DNSNames: []string{"client.internal.example.test"}, CSR: subject.CSRDER})
	if err != nil {
		t.Fatalf("issue with the pinned profile requested: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("no certificate chain returned")
	}
	// A misspelled profile is refused by the client before any order.
	driver = driver.WithProfile("internal-acm")
	if _, err := driver.IssueChain(ctx, acmekey.OrderRequest{TenantID: h.tenant, DNSNames: []string{"client.internal.example.test"}, CSR: subject.CSRDER}); err == nil || !strings.Contains(err.Error(), "does not offer") {
		t.Fatalf("unadvertised profile = %v, want the client's own refusal", err)
	}
	_ = http.StatusOK
}
