// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/profile"
)

func cr803ESTEnroll(t *testing.T, h *servedHarness, token, uri string) (int, []byte, []byte) {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{URIs: []string{uri}}, key)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(csr))))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := readAllClose(resp)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	p7, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(body)))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := crypto.CertsFromPKCS7(p7)
	if err != nil || len(certs) == 0 {
		t.Fatalf("EST returned no certificate: %v", err)
	}
	pkcs8, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, certs[0], pkcs8
}

func TestCR803ServedESTCannotIssueSiblingSPIFFEPath(t *testing.T) {
	const profileName = "spiffe-prod"
	const prefix = "spiffe://served.test/ns/prod"
	h := newServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) { d.DefaultProfile = profileName })
	registerServedTenant(t, h, "CR-803 URI profile tenant")
	storeServerTestProfile(t, h.store, h.tenant, profileName, profile.CertificateProfile{
		Name: profileName, AllowedURIPrefixes: []string{prefix},
		AllowedEKUs: []string{"clientAuth"}, MaxValidity: profile.Duration(24 * time.Hour),
	})
	token := seedAPIToken(t, h.store, servedTestTenant)
	allowed, _, key := cr803ESTEnroll(t, h, token, prefix+"/sa/web")
	secret.Wipe(key)
	if allowed != http.StatusOK {
		t.Fatalf("in-prefix EST enrollment status=%d, want 200", allowed)
	}
	outside, _, key := cr803ESTEnroll(t, h, token, "spiffe://served.test/ns/dev/sa/web")
	secret.Wipe(key)
	if outside == http.StatusOK {
		t.Fatal("unrelated namespace was issued; profile policy is not active")
	}
	sibling, leaf, key := cr803ESTEnroll(t, h, token, "spiffe://served.test/ns/production/sa/admin")
	defer secret.Wipe(key)
	if sibling == http.StatusOK {
		check, err := crypto.VerifyX509SVID(leaf, h.srv.caCertDER, key, time.Now())
		if err == nil {
			t.Fatalf("profile %q issued sibling SPIFFE ID %q verifiable under its workload bundle", prefix, check.SPIFFEID)
		}
		t.Fatalf("profile %q issued sibling SPIFFE path (verification error %v)", prefix, err)
	}
}
