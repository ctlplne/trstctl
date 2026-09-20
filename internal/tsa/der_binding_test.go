// SPDX-License-Identifier: BUSL-1.1

package tsa

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// TestVerifyRejectsSubstitutedDERToken is the regression guard for the unchecked
// RFC 3161 artifact.
//
// Verify validated Info, Signature and TSACertDER — the JSON manifest — and
// never looked at DER, which is the token a recipient feeds to `openssl ts
// -verify` or archives as the durable proof. Token is JSON-tagged and travels
// inside audit export bundles (internal/auditanchor verifies one it did not
// issue), so a bundle with an intact manifest could carry a DER lifted from an
// unrelated issuance and Verify would still return nil.
func TestVerifyRejectsSubstitutedDERToken(t *testing.T) {
	a, root := newTSA(t, func() time.Time { return time.Unix(1_900_000_000, 0).UTC() })

	imprint := imprintOf("the data that was actually timestamped")
	tok, err := a.Timestamp(t.Context(), imprint)
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	if len(tok.DER) == 0 {
		t.Fatal("fixture is broken: the issued token carries no RFC 3161 DER")
	}
	if err := Verify(tok, imprint, root); err != nil {
		t.Fatalf("a freshly issued token must verify: %v", err)
	}

	// A second, unrelated issuance. Its DER is a perfectly valid RFC 3161 token —
	// just not a token for this data.
	otherImprint := imprintOf("some completely different data")
	other, err := a.Timestamp(t.Context(), otherImprint)
	if err != nil {
		t.Fatalf("second timestamp: %v", err)
	}
	if bytes.Equal(tok.DER, other.DER) {
		t.Fatal("fixture is broken: two different imprints produced identical tokens")
	}

	forged := tok
	forged.DER = other.DER
	if err := Verify(forged, imprint, root); err == nil {
		t.Fatal("Verify accepted a token whose manifest attests this data but whose RFC 3161 " +
			"DER attests something else; a recipient would hand those bytes on as proven")
	}

	// Garbage in the DER field must be caught too.
	junk := tok
	junk.DER = []byte("not a timestamp token at all")
	if err := Verify(junk, imprint, root); err == nil {
		t.Fatal("Verify accepted a token whose DER is not the verified artifact")
	}
}

// TestVerifyAcceptsManifestOnlyToken guards the compatibility edge: tokens
// predating the RFC 3161 wire format carry only the manifest, which is
// independently signed. Rejecting those would break historical export bundles,
// and stripping the DER removes the artifact an attacker wants to forge rather
// than smuggling one through.
func TestVerifyAcceptsManifestOnlyToken(t *testing.T) {
	a, root := newTSA(t, func() time.Time { return time.Unix(1_900_000_000, 0).UTC() })
	imprint := imprintOf("legacy anchor")
	tok, err := a.Timestamp(t.Context(), imprint)
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	tok.DER = nil
	if err := Verify(tok, imprint, root); err != nil {
		t.Fatalf("a manifest-only token must still verify: %v", err)
	}
}

func imprintOf(s string) []byte { return crypto.SHA256Sum([]byte(s)) }
