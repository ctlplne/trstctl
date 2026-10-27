// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// A195: evaluating a request decides exactly as signing it would, without
// signing: an in-profile CSR is allowed with the TTL the CA would sign (clamped
// to the issuer when the profile says so), and an out-of-profile CSR is refused
// with the same profile violation the signer returns.
func TestEvaluateLeafRequestDecidesAsSigningWould(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl Evaluation Test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr := func(names ...string) []byte {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: names[0], DNSNames: names}, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	profile := crypto.LeafProfile{PermittedDNSSuffixes: []string{"apps.example.com"}, MaxValidity: 48 * time.Hour, ClampTTLToIssuer: true}

	inside := csr("web.apps.example.com")
	ttl, err := crypto.EvaluateLeafRequest(caDER, inside, 72*time.Hour, profile)
	if err != nil || ttl <= 23*time.Hour || ttl > 24*time.Hour {
		t.Fatalf("an in-profile request = %s, %v; want allowed at the issuer's remaining lifetime", ttl, err)
	}
	if _, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, inside, 72*time.Hour, profile); err != nil {
		t.Fatalf("signing what evaluation allowed failed: %v", err)
	}

	outside := csr("web.other.example.net")
	_, evalErr := crypto.EvaluateLeafRequest(caDER, outside, time.Hour, profile)
	_, signErr := crypto.SignLeafFromCSRWithProfile(caDER, caKey, outside, time.Hour, profile)
	if !crypto.IsLeafProfileViolation(evalErr) || signErr == nil || evalErr.Error() != signErr.Error() {
		t.Fatalf("out-of-profile request: evaluate %v, sign %v; want the same profile violation", evalErr, signErr)
	}
	if _, err := crypto.EvaluateLeafRequest(caDER, []byte("not a csr"), time.Hour, profile); err == nil {
		t.Fatal("a malformed CSR was allowed")
	}
}
