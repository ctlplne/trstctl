// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// svidFixture is a CA, a workload key and the SVID the CA signed for it.
type svidFixture struct {
	caDER, svid, keyPKCS8 []byte
}

func newSVIDFixture(t *testing.T, name string) svidFixture {
	t.Helper()
	ca, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := SelfSignedCACert(ca, name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leaf.Destroy)
	svid, err := SignSVID(caDER, ca, leaf.Public().DER, "spiffe://example.org/payments", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := leaf.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secret.Wipe(key) })
	return svidFixture{caDER: caDER, svid: svid, keyPKCS8: key}
}

// A249: the evaluator checks an X.509-SVID as the workload receiving it would.
func TestVerifyX509SVIDAsAWorkloadDoes(t *testing.T) {
	f := newSVIDFixture(t, "Workload CA")
	now := time.Now()
	check, err := VerifyX509SVID(f.svid, f.caDER, f.keyPKCS8, now)
	if err != nil {
		t.Fatal(err)
	}
	if check.SPIFFEID != "spiffe://example.org/payments" || check.ChainLength != 1 || check.Authorities != 1 || !check.NotAfter.After(now) {
		t.Fatalf("check = %+v", check)
	}
	// x509_svid may carry intermediates after the leaf, and a bundle may hold
	// more than one authority.
	other := newSVIDFixture(t, "Another CA")
	bundle := append(append([]byte(nil), other.caDER...), f.caDER...)
	if check, err := VerifyX509SVID(append(append([]byte(nil), f.svid...), f.caDER...), bundle, f.keyPKCS8, now); err != nil || check.ChainLength != 2 || check.Authorities != 2 {
		t.Fatalf("leaf+intermediate against a two-authority bundle = %+v, %v", check, err)
	}

	for _, tc := range []struct {
		name               string
		chain, bundle, key []byte
		at                 time.Time
		want               string
	}{
		{"another trust domain's bundle", f.svid, other.caDER, f.keyPKCS8, now, "does not chain"},
		{"another workload's key", f.svid, f.caDER, other.keyPKCS8, now, "not the SVID's"},
		{"after the SVID expires", f.svid, f.caDER, f.keyPKCS8, now.Add(2 * time.Hour), "does not chain"},
		{"no chain", nil, f.caDER, f.keyPKCS8, now, "empty"},
		{"no bundle", f.svid, nil, f.keyPKCS8, now, "empty"},
		{"a truncated chain", f.svid[:len(f.svid)/2], f.caDER, f.keyPKCS8, now, "parse the SVID chain"},
		{"a key that is not PKCS#8", f.svid, f.caDER, []byte("not a key"), now, "parse the SVID's private key"},
		{"a CA certificate as the leaf", f.caDER, f.caDER, f.keyPKCS8, now, "URI SAN"},
	} {
		if _, err := VerifyX509SVID(tc.chain, tc.bundle, tc.key, tc.at); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}
