// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// CR-052: a leaf's extended key usages come from its profile, never from the
// CSR alone. A profile that lists none allows serverAuth and clientAuth, a CSR
// asking for anything else is refused, and ocspSigning (which would make the
// leaf a delegated OCSP responder for the issuing CA every tenant shares) and
// anyExtendedKeyUsage are never issued.

// ekuCSR is a CSR for name asking for the given extended key usages.
func ekuCSR(t *testing.T, name string, ekus ...string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}, RequestedEKUs: ekus}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The CA hierarchy's authority lane never copies ocspSigning or
// anyExtendedKeyUsage from a CA's constraint onto a leaf.
func TestAuthorityLaneNeverCopiesOCSPSigningOrAnyOntoALeaf(t *testing.T) {
	got := applyAuthorityLane(crypto.LeafProfile{}, store.CAAuthority{EKUs: []string{"serverAuth", "any", "ocspSigning"}})
	if !slices.Equal(got.AllowedExtKeyUsage, []string{"serverAuth"}) {
		t.Fatalf("leaf extended key usages = %v, want [serverAuth]", got.AllowedExtKeyUsage)
	}
	if got := applyAuthorityLane(crypto.LeafProfile{}, store.CAAuthority{EKUs: []string{"any"}}); len(got.AllowedExtKeyUsage) != 0 {
		t.Fatalf("an unrestricted CA gave its leaf %v, want the default pair", got.AllowedExtKeyUsage)
	}
}

// Every enrollment protocol (ACME, EST, SCEP, CMP) resolves a leaf's
// extended key usages through protocolIssuer.enforceProfile.
func TestServedProtocolLeafEKUsStayWithinTheProfileCR052(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	storeServerTestProfile(t, h.store, h.tenant, "cr052-empty", profile.CertificateProfile{Name: "cr052-empty"})
	storeServerTestProfile(t, h.store, h.tenant, "cr052-smime", profile.CertificateProfile{Name: "cr052-smime", AllowedEKUs: []string{"serverAuth", "emailProtection"}})
	// A profile stored before profile writes refused these usages.
	storeServerTestProfile(t, h.store, h.tenant, "cr052-stored-responder", profile.CertificateProfile{Name: "cr052-stored-responder", AllowedEKUs: []string{"serverAuth", "ocspSigning"}})
	issuer := &protocolIssuer{store: h.store, log: h.log}
	// A deployment leaf profile that sets its own list bounds every profile.
	bounded := &protocolIssuer{store: h.store, log: h.log, leafProfile: crypto.LeafProfile{AllowedExtKeyUsage: []string{"serverAuth", "clientAuth"}}}
	resolve := func(p *protocolIssuer, protocolName, profileName string, ekus ...string) (crypto.LeafProfile, error) {
		info, err := crypto.InspectCSR(ekuCSR(t, "svc.cr052.test", ekus...))
		if err != nil {
			t.Fatal(err)
		}
		prof, _, err := p.enforceProfile(ctx, h.tenant, protocolName, profileName, info, []string{"svc.cr052.test"}, time.Hour)
		return prof, err
	}
	for _, protocolName := range []string{"acme", "est", "scep", "cmp"} {
		t.Run(protocolName, func(t *testing.T) {
			for _, ekus := range [][]string{{"ocspSigning"}, {"serverAuth", "ocspSigning"}, {"codeSigning"}, {"any"}} {
				if prof, err := resolve(issuer, protocolName, "cr052-empty", ekus...); err == nil {
					t.Errorf("a CSR asking for %v under a profile listing no usages got %v", ekus, prof.AllowedExtKeyUsage)
				}
			}
			// A CSR asking for no usage leaves the list to the deployment, a
			// managed CA's own usages or the signer's default pair.
			prof, err := resolve(issuer, protocolName, "cr052-empty")
			if err != nil || len(prof.AllowedExtKeyUsage) != 0 {
				t.Errorf("a CSR asking for no usage got %v (%v), want the deployment default", prof.AllowedExtKeyUsage, err)
			}
			if prof, err := resolve(issuer, protocolName, "cr052-stored-responder"); err == nil {
				t.Errorf("a stored profile listing ocspSigning issued %v", prof.AllowedExtKeyUsage)
			}
			if prof, err := resolve(issuer, protocolName, "cr052-smime", "emailProtection"); err != nil || !slices.Equal(prof.AllowedExtKeyUsage, []string{"emailProtection"}) {
				t.Errorf("an emailProtection request under its profile got %v (%v)", prof.AllowedExtKeyUsage, err)
			}
			if prof, err := resolve(bounded, protocolName, "cr052-smime", "emailProtection"); err == nil {
				t.Errorf("a usage outside the deployment's list was issued: %v", prof.AllowedExtKeyUsage)
			}
		})
	}
}

// A managed CA's own extended key usage constraint still decides the usages of
// a leaf issued under a profile that lists none, and a deployment list narrower
// than the default pair still issues a CSR that asks for nothing.
func TestBoundEmptyProfileKeepsTheIssuingCAsOwnUsagesCR052(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	storeServerTestProfile(t, h.store, h.tenant, "cr052-lane-empty", profile.CertificateProfile{Name: "cr052-lane-empty"})
	d := &issuanceDispatcher{store: h.store, defaultProfile: "cr052-lane-empty"}
	lp, err := d.enforceProfileForPurpose(ctx, h.tenant, "private", ekuCSR(t, "svc.cr052.test"), []string{"svc.cr052.test"}, time.Hour, "api")
	if err != nil {
		t.Fatalf("a plain CSR was refused: %v", err)
	}
	for _, caEKUs := range [][]string{{"clientAuth"}, {"codeSigning"}, {"emailProtection"}} {
		if got := applyAuthorityLane(lp, store.CAAuthority{EKUs: caEKUs}); !slices.Equal(got.AllowedExtKeyUsage, caEKUs) {
			t.Errorf("a managed CA constrained to %v gave its leaf %v under a profile listing no usages", caEKUs, got.AllowedExtKeyUsage)
		}
	}
	narrow := &protocolIssuer{store: h.store, log: h.log, leafProfile: crypto.LeafProfile{AllowedExtKeyUsage: []string{"serverAuth"}}}
	info, err := crypto.InspectCSR(ekuCSR(t, "svc.cr052.test"))
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := narrow.enforceProfile(ctx, h.tenant, "est", "cr052-lane-empty", info, []string{"svc.cr052.test"}, time.Hour)
	if err != nil || !slices.Equal(got.AllowedExtKeyUsage, []string{"serverAuth"}) {
		t.Fatalf("a plain CSR under a serverAuth-only deployment list got %v (%v), want [serverAuth]", got.AllowedExtKeyUsage, err)
	}
}

// The platform issuing CA's timeStamping refusal is a profile decision on both
// entry points: a profile refusal for the platform CA (no upstream external CA;
// the identity's authority "platform"), and no refusal when an upstream or a
// tenant-managed CA signs.
func TestPlatformTimeStampingIsRefusedByTheProfileDecisionCR052(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	storeServerTestProfile(t, h.store, h.tenant, "cr052-stamp", profile.CertificateProfile{Name: "cr052-stamp", AllowedEKUs: []string{"timeStamping"}})
	storeServerTestProfile(t, h.store, h.tenant, "cr052-stamp-upstream", profile.CertificateProfile{Name: "cr052-stamp-upstream", AllowedEKUs: []string{"timeStamping"}, UpstreamExternalCA: "adcs-lab"})
	issuer := &protocolIssuer{store: h.store, log: h.log}
	info, err := crypto.InspectCSR(ekuCSR(t, "tsa.cr052.test", "timeStamping"))
	if err != nil {
		t.Fatal(err)
	}
	var refusal *profile.Refusal
	if _, _, err := issuer.enforceProfile(ctx, h.tenant, "est", "cr052-stamp", info, []string{"tsa.cr052.test"}, time.Hour); !errors.As(err, &refusal) {
		t.Fatalf("the platform CA's timeStamping decision = %v, want a profile refusal", err)
	}
	if _, _, err := issuer.enforceProfile(ctx, h.tenant, "est", "cr052-stamp-upstream", info, []string{"tsa.cr052.test"}, time.Hour); err != nil {
		t.Fatalf("an upstream CA's timeStamping decision refused it: %v", err)
	}
	d := &issuanceDispatcher{store: h.store, defaultProfile: "cr052-stamp"}
	if _, err := d.enforceProfileForPurpose(ctx, h.tenant, "platform", ekuCSR(t, "tsa.cr052.test"), []string{"tsa.cr052.test"}, time.Hour, "api"); !errors.As(err, &refusal) {
		t.Fatalf("the lifecycle platform decision = %v, want a profile refusal", err)
	}
	if lp, err := d.enforceProfileForPurpose(ctx, h.tenant, "private", ekuCSR(t, "tsa.cr052.test"), []string{"tsa.cr052.test"}, time.Hour, "api"); err != nil || !slices.Equal(lp.AllowedExtKeyUsage, []string{"timeStamping"}) {
		t.Fatalf("a tenant-managed CA's timeStamping decision = %v (%v)", lp.AllowedExtKeyUsage, err)
	}
}

// A platform timeStamping refusal on the lifecycle path is a definite
// no-effect profile refusal: it never counts toward the tenant's issuance
// circuit, so the tenant's next ordinary issuance goes through at once.
func TestServedPlatformTimeStampingRefusalLeavesTheIssuanceCircuitClosedCR052(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant,
		"profiles:read", "profiles:write", "owners:read", "owners:write",
		"identities:read", "identities:write", "certs:read", "certs:issue")
	if code, body := secretsReq(t, h, http.MethodPost, "/api/v1/profiles", tok, map[string]any{
		"name": "cr052-circuit-stamp", "spec": map[string]any{"allowed_ekus": []string{"timeStamping"}},
	}); code != http.StatusCreated {
		t.Fatalf("a timeStamping profile was refused: %d %s", code, body)
	}
	storeServerTestProfile(t, h.store, h.tenant, "cr052-circuit-empty", profile.CertificateProfile{Name: "cr052-circuit-empty"})
	code, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "owner-cr052-circuit", "email": "owner@example.test"})
	if code != http.StatusCreated {
		t.Fatalf("create owner = %d %s", code, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	issue := func(profileName, name string) bool {
		t.Helper()
		code, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
			"owner_id": owner.ID, "kind": "x509", "name": name, "attributes": map[string]any{"profile": profileName},
		})
		if code != http.StatusCreated {
			t.Fatalf("create identity = %d %s", code, body)
		}
		var ident struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &ident); err != nil {
			t.Fatal(err)
		}
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: ekuCSR(t, name)})
		_, _ = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
			"to": "issued", "reason": "cr052", "subject_csr_pem": string(csrPEM),
		})
		drainCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_ = h.srv.Drain(drainCtx)
		certs, err := h.store.ListCertificatesPage(ctx, h.tenant, "00000000-0000-0000-0000-000000000000", nil, 200, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range certs {
			if info, err := certinfo.Inspect(c.CertificateDER); err == nil && info.CommonName == name {
				return true
			}
		}
		return false
	}
	for i := 0; i < 3; i++ {
		if issue("cr052-circuit-stamp", fmt.Sprintf("stamp%d.corp.cr052.test", i)) {
			t.Fatal("the platform issuing CA issued a timeStamping leaf")
		}
	}
	for _, c := range h.srv.outbox.CircuitStates() {
		if c.TenantID == h.tenant && (c.State != orchestrator.CircuitClosed || c.Failures != 0) {
			t.Fatalf("refused timeStamping issuances counted toward circuit %s: state %v, %d failures (%s)", c.Destination, c.State, c.Failures, c.LastError)
		}
	}
	if !issue("cr052-circuit-empty", "ordinary.corp.cr052.test") {
		t.Fatal("the tenant's next ordinary issuance was held back")
	}
}

// An EAB-authorized ACME client under a profile listing no extended key usages
// cannot get a leaf carrying ocspSigning or codeSigning; an ordinary order
// gets serverAuth and clientAuth.
func TestServedACMEClientNeverGetsAnOCSPResponderLeafCR052(t *testing.T) {
	ctx := context.Background()
	credKey := bytes.Repeat([]byte{0x63}, 32)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: []config.ACMEExternalAccountBindingKey{
			{KeyID: "cr052", HMACKey: credKey, Profile: "cr052-acme", AllowedIdentifiers: []string{"*.corp.cr052.test"}},
			{KeyID: "cr052-stamp", HMACKey: credKey, Profile: "cr052-acme-stamp", AllowedIdentifiers: []string{"*.stamp.cr052.test"}},
		}},
	}, func(d *Deps) { d.DefaultProfile = "cr052-acme" })
	storeServerTestProfile(t, h.store, h.tenant, "cr052-acme", profile.CertificateProfile{
		Name: "cr052-acme", ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"},
	})
	storeServerTestProfile(t, h.store, h.tenant, "cr052-acme-stamp", profile.CertificateProfile{
		Name: "cr052-acme-stamp", ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
		MaxValidity: profile.Duration(2160 * time.Hour), AllowedProtocols: []string{"acme"}, AllowedEKUs: []string{"timeStamping"},
	})
	account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(account.Destroy)
	driver, err := acmekey.NewDriverWithDigestSigner(h.ts.URL+"/directory", nil, h.ts.Client(), account)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(driver.Destroy)
	driver = driver.WithExternalAccountBinding("cr052", credKey)
	order := func(name string, ekus ...string) ([][]byte, error) {
		return driver.IssueChain(ctx, acmekey.OrderRequest{TenantID: h.tenant, DNSNames: []string{name}, CSR: ekuCSR(t, name, ekus...)})
	}
	if chain, err := order("ws1.corp.cr052.test", "ocspSigning", "codeSigning"); err == nil {
		info, _ := certinfo.Inspect(chain[0])
		t.Fatalf("the ACME order asking for ocspSigning and codeSigning was issued: %v", info.ExtKeyUsages)
	}
	// The platform issuing CA never signs timeStamping: the profile decision
	// refuses it before signing, so the client is told badCSR at once rather
	// than retrying a server error.
	stampAccount, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stampAccount.Destroy)
	stampDriver, err := acmekey.NewDriverWithDigestSigner(h.ts.URL+"/directory", nil, h.ts.Client(), stampAccount)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stampDriver.Destroy)
	stampDriver = stampDriver.WithExternalAccountBinding("cr052-stamp", credKey)
	for _, ekus := range [][]string{nil, {"timeStamping"}} {
		stampCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := stampDriver.IssueChain(stampCtx, acmekey.OrderRequest{TenantID: h.tenant, DNSNames: []string{"tsa.stamp.cr052.test"}, CSR: ekuCSR(t, "tsa.stamp.cr052.test", ekus...)})
		cancel()
		if err == nil || !strings.Contains(err.Error(), "badCSR") {
			t.Fatalf("a timeStamping order on the platform CA (CSR asks %v) ended with %v, want a badCSR refusal", ekus, err)
		}
	}
	chain, err := order("ws2.corp.cr052.test")
	if err != nil {
		t.Fatalf("an ordinary ACME order was refused: %v", err)
	}
	info, err := certinfo.Inspect(chain[0])
	if err != nil || !slices.Equal(info.ExtKeyUsages, []string{"serverAuth", "clientAuth"}) {
		t.Fatalf("an ordinary ACME leaf carries %v (%v), want [serverAuth clientAuth]", info.ExtKeyUsages, err)
	}
}

// The served API refuses a profile listing ocspSigning or anyExtendedKeyUsage,
// and its issuance path (the one the lifecycle transitions use) refuses a CSR
// asking for a usage its profile does not allow and a profile stored with one
// of those usages before this check.
func TestServedAPIProfilesNeverIssueOCSPSigningCR052(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant,
		"profiles:read", "profiles:write", "owners:read", "owners:write",
		"identities:read", "identities:write", "certs:read", "certs:issue")
	for _, ekus := range [][]string{{"ocspSigning", "codeSigning"}, {"serverAuth", "any"}, {"1.3.6.1.5.5.7.3.9"}} {
		code, body := secretsReq(t, h, http.MethodPost, "/api/v1/profiles", tok, map[string]any{
			"name": "cr052-written", "spec": map[string]any{"allowed_ekus": ekus},
		})
		if code == http.StatusCreated || code == http.StatusOK {
			t.Fatalf("a profile listing %v was written: %d %s", ekus, code, body)
		}
	}
	storeServerTestProfile(t, h.store, h.tenant, "cr052-lifecycle-empty", profile.CertificateProfile{Name: "cr052-lifecycle-empty"})
	// timeStamping is a usage a tenant-managed CA may issue, so the profile is
	// accepted; the platform issuing CA never signs it (its own TSA
	// certificate anchors the audit trail).
	code, body := secretsReq(t, h, http.MethodPost, "/api/v1/profiles", tok, map[string]any{
		"name": "cr052-lifecycle-stamp", "spec": map[string]any{"allowed_ekus": []string{"timeStamping"}},
	})
	if code != http.StatusCreated {
		t.Fatalf("a timeStamping profile was refused: %d %s", code, body)
	}
	storeServerTestProfile(t, h.store, h.tenant, "cr052-lifecycle-stored-responder", profile.CertificateProfile{Name: "cr052-lifecycle-stored-responder", AllowedEKUs: []string{"serverAuth", "ocspSigning"}})

	code, body = secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "owner-cr052", "email": "owner@example.test"})
	if code != http.StatusCreated {
		t.Fatalf("create owner = %d %s", code, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	// issue drives one identity to issued under profileName with a CSR asking
	// for ekus, and returns the issued leaf's usages, or nil when none was issued.
	issue := func(t *testing.T, profileName, name string, ekus ...string) []string {
		t.Helper()
		code, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
			"owner_id": owner.ID, "kind": "x509", "name": name, "attributes": map[string]any{"profile": profileName},
		})
		if code != http.StatusCreated {
			t.Fatalf("create identity = %d %s", code, body)
		}
		var ident struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &ident); err != nil {
			t.Fatal(err)
		}
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: ekuCSR(t, name, ekus...)})
		_, _ = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
			"to": "issued", "reason": "cr052", "subject_csr_pem": string(csrPEM),
		})
		drainCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_ = h.srv.Drain(drainCtx)
		certs, err := h.store.ListCertificatesPage(ctx, h.tenant, "00000000-0000-0000-0000-000000000000", nil, 100, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range certs {
			if info, err := certinfo.Inspect(c.CertificateDER); err == nil && info.CommonName == name {
				return info.ExtKeyUsages
			}
		}
		return nil
	}
	if got := issue(t, "cr052-lifecycle-empty", "signer.corp.cr052.test", "codeSigning"); got != nil {
		t.Errorf("a CSR asking for codeSigning under a profile listing no usages was issued %v", got)
	}
	if got := issue(t, "cr052-lifecycle-stored-responder", "responder.corp.cr052.test"); got != nil {
		t.Errorf("a stored profile listing ocspSigning issued %v", got)
	}
	if got := issue(t, "cr052-lifecycle-stamp", "stamp.corp.cr052.test"); got != nil {
		t.Errorf("the platform issuing CA signed a timeStamping leaf: %v", got)
	}
	if got := issue(t, "cr052-lifecycle-empty", "web.corp.cr052.test"); !slices.Equal(got, []string{"serverAuth", "clientAuth"}) {
		t.Errorf("an ordinary API issuance got %v, want [serverAuth clientAuth]", got)
	}
}
