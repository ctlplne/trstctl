// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// TestCRLPublicationRefusesToUnrevoke is the regression guard for the
// un-revocation defect. Revocation is monotonic: a serial, once revoked, stays
// revoked until it expires. A regenerated full CRL that omits a serial the
// previous CRL carried does not merely lose information — every relying party
// that fetches it stops treating that certificate as revoked. Nothing compared
// the new CRL against its predecessor, so a racing regeneration, a partial read,
// or a lagging projection could publish exactly that.
func TestCRLPublicationRefusesToUnrevoke(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	caDER, err := crypto.SelfSignedCACert(signer, "trstctl CRL monotonicity CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	next := now.Add(time.Hour)

	mk := func(serials []string, number int64) []byte {
		t.Helper()
		entries := make([]crypto.RevokedSerial, 0, len(serials))
		for _, s := range serials {
			entries = append(entries, crypto.RevokedSerial{Serial: s, RevokedAt: now, Reason: 1})
		}
		der, err := crypto.CreateCRL(caDER, signer, entries, number, now, next)
		if err != nil {
			t.Fatalf("create CRL: %v", err)
		}
		return der
	}

	previous := mk([]string{"0a", "0b", "0c"}, 1)

	// The defect: a regenerated CRL missing "0b".
	dropped := mk([]string{"0a", "0c"}, 2)
	err = assertCRLDoesNotUnrevoke(previous, dropped, caDER)
	if err == nil {
		t.Fatal("a CRL that drops an already-revoked serial was accepted; publishing it un-revokes that certificate")
	}
	if !strings.Contains(err.Error(), "un-revoke") {
		t.Errorf("refusal should say why it matters, got: %v", err)
	}

	// The same set is fine.
	if err := assertCRLDoesNotUnrevoke(previous, mk([]string{"0a", "0b", "0c"}, 2), caDER); err != nil {
		t.Fatalf("an unchanged revocation set was refused: %v", err)
	}

	// Growing is the normal case and must be allowed.
	if err := assertCRLDoesNotUnrevoke(previous, mk([]string{"0a", "0b", "0c", "0d"}, 2), caDER); err != nil {
		t.Fatalf("a CRL adding a newly revoked serial was refused: %v", err)
	}

	// A missing predecessor is not evidence of a bad successor — first
	// publication must not be blocked.
	if err := assertCRLDoesNotUnrevoke(nil, dropped, caDER); err != nil {
		t.Fatalf("first CRL publication was refused: %v", err)
	}
}
