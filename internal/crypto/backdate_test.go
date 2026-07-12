// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/x509"
	"testing"
	"time"
)

// TestIssuanceNotBeforeSkewDefaultsToFiveMinutes is the OPS-CLOCKSKEW-001
// acceptance: common CA practice backdates NotBefore by five minutes so a
// fresh certificate is immediately valid at verifiers with modest clock skew.
// The old hardcoded one-minute backdate failed a verifier running 4 minutes
// slow; the default must cover that.
func TestIssuanceNotBeforeSkewDefaultsToFiveMinutes(t *testing.T) {
	if got := IssuanceBackdateSkew(); got != 5*time.Minute {
		t.Fatalf("default issuance backdate skew = %v, want 5m", got)
	}
	now := time.Now()
	nb := IssuanceNotBefore(now)
	if want := now.Add(-5 * time.Minute); !nb.Equal(want) {
		t.Fatalf("IssuanceNotBefore = %v, want %v", nb, want)
	}
}

// TestFreshLeafIsValidAtSkewedVerifier proves the served issuance path
// (self-signed CA + leaf) produces a certificate that a verifier whose clock
// runs four minutes SLOW still accepts immediately (OPS-CLOCKSKEW-001).
func TestFreshLeafIsValidAtSkewedVerifier(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	caDER, err := SelfSignedCACert(key, "skew test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	skewedVerifierNow := time.Now().Add(-4 * time.Minute)
	if skewedVerifierNow.Before(cert.NotBefore) {
		t.Fatalf("certificate NotBefore %v is not yet valid at a verifier running 4m slow (%v); backdate skew too small", cert.NotBefore, skewedVerifierNow)
	}
}

// TestSetIssuanceBackdateSkewBounds: the skew is configurable within sane
// bounds and restores cleanly; nonsense values fail closed to the previous
// value rather than weakening or absurdly widening the validity window.
func TestSetIssuanceBackdateSkewBounds(t *testing.T) {
	original := IssuanceBackdateSkew()
	t.Cleanup(func() {
		if err := SetIssuanceBackdateSkew(original); err != nil {
			t.Fatalf("restore skew: %v", err)
		}
	})
	if err := SetIssuanceBackdateSkew(2 * time.Minute); err != nil {
		t.Fatalf("2m is a legitimate operator skew: %v", err)
	}
	if got := IssuanceBackdateSkew(); got != 2*time.Minute {
		t.Fatalf("skew after set = %v, want 2m", got)
	}
	now := time.Now()
	if nb := IssuanceNotBefore(now); !nb.Equal(now.Add(-2 * time.Minute)) {
		t.Fatalf("IssuanceNotBefore did not honor the configured skew: %v", nb)
	}
	for _, bad := range []time.Duration{0, -time.Minute, 29 * time.Second, 2 * time.Hour} {
		if err := SetIssuanceBackdateSkew(bad); err == nil {
			t.Fatalf("skew %v accepted; want rejection (30s..1h bounds)", bad)
		}
	}
	if got := IssuanceBackdateSkew(); got != 2*time.Minute {
		t.Fatalf("rejected sets must not change the skew: %v", got)
	}
}
