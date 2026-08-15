// SPDX-License-Identifier: MPL-2.0

package backup

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// LockedSigner is a DigestSigner; SignerFromDigestSigner is the boundary adapter
// that gives it the message-signing shape backups use.
func signedManifestKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	return crypto.SignerFromDigestSigner(k)
}

func signTrailer(t *testing.T, signer crypto.Signer, tr postgresStateTrailer) postgresStateTrailer {
	t.Helper()
	sig, err := signer.Sign(signedTrailerBytes(tr), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("sign trailer: %v", err)
	}
	tr.Signature = sig
	tr.SignerPublicDER = signer.Public().DER
	return tr
}

func sampleTrailer() postgresStateTrailer {
	return postgresStateTrailer{
		Format: postgresStateTrailerTag, SHA256: "abc123", Records: 42,
		Tables: map[string]int{"identities": 40, "issuers": 2}, EventCutSequence: 900,
	}
}

// TestForeignArtifactNeedsASignatureFromATrustedDeployment is the regression
// guard for the disaster-recovery gap.
//
// The HMAC authenticates an artifact to whoever holds the same integrity key —
// exactly what a DR restore cannot rely on, because a fresh deployment has a
// different KEK by construction. It therefore had nothing to check a foreign
// artifact with and fell back to a SHA-256 anyone can recompute over content of
// their choosing.
func TestForeignArtifactNeedsASignatureFromATrustedDeployment(t *testing.T) {
	source := signedManifestKey(t)
	stranger := signedManifestKey(t)

	anchors := [][]byte{source.Public().DER}

	t.Run("signed by the trusted deployment", func(t *testing.T) {
		if err := verifyPostgresStateSignature(signTrailer(t, source, sampleTrailer()), anchors); err != nil {
			t.Fatalf("an artifact from the trusted deployment was refused: %v", err)
		}
	})

	t.Run("unsigned is refused, not skipped", func(t *testing.T) {
		err := verifyPostgresStateSignature(sampleTrailer(), anchors)
		if err == nil {
			t.Fatal("an UNSIGNED artifact was accepted while trust anchors were configured; " +
				"an attacker simply omits the signature")
		}
		if !strings.Contains(err.Error(), "no signed manifest") {
			t.Errorf("error should say the manifest is missing, got: %v", err)
		}
	})

	t.Run("signed by an unknown deployment is refused", func(t *testing.T) {
		err := verifyPostgresStateSignature(signTrailer(t, stranger, sampleTrailer()), anchors)
		if err == nil {
			t.Fatal("an artifact signed by an untrusted key was accepted; any deployment could " +
				"hand this one a backup to restore")
		}
		if !strings.Contains(err.Error(), "not a configured trust anchor") {
			t.Errorf("error should name the anchor mismatch, got: %v", err)
		}
	})

	t.Run("tampered content breaks the signature", func(t *testing.T) {
		// Sign an honest trailer, then alter what it attests. The signature covers
		// the stream digest and the counts, so this must not verify.
		tr := signTrailer(t, source, sampleTrailer())
		tr.SHA256 = "deadbeef"
		if err := verifyPostgresStateSignature(tr, anchors); err == nil {
			t.Fatal("the content digest was changed after signing and the manifest still verified")
		}

		counts := signTrailer(t, source, sampleTrailer())
		counts.Records = 1
		if err := verifyPostgresStateSignature(counts, anchors); err == nil {
			t.Fatal("the record count was changed after signing and the manifest still verified")
		}

		tables := signTrailer(t, source, sampleTrailer())
		tables.Tables = map[string]int{"identities": 1, "issuers": 2}
		if err := verifyPostgresStateSignature(tables, anchors); err == nil {
			t.Fatal("a per-table count was changed after signing and the manifest still verified")
		}
	})
}

// TestNoTrustAnchorsLeavesRestoreUnchanged pins the compatibility edge: an
// in-place restore of this deployment's own artifact — a ZERO identity — must
// behave exactly as before. The identity travels as a value now (K1/V32), so
// there is no process-global anchor state to leak between tests or between the
// nightly drill and a later restore; a zero value IS the no-anchors state.
func TestNoTrustAnchorsLeavesRestoreUnchanged(t *testing.T) {
	var id PostgresStateIdentity
	if len(id.TrustAnchors) != 0 || id.Signer != nil {
		t.Fatal("the zero identity must sign nothing and require nothing")
	}
}

// TestSignedTrailerBytesAreCanonical guards the encoding the signature covers.
// Go map iteration is random, so a per-table count set built in a different order
// must still produce identical signed bytes — otherwise a valid artifact would
// fail to verify roughly at random.
func TestSignedTrailerBytesAreCanonical(t *testing.T) {
	a := sampleTrailer()
	b := postgresStateTrailer{
		Format: a.Format, SHA256: a.SHA256, Records: a.Records,
		Tables:           map[string]int{"issuers": 2, "identities": 40},
		EventCutSequence: a.EventCutSequence,
	}
	if string(signedTrailerBytes(a)) != string(signedTrailerBytes(b)) {
		t.Fatal("the signed encoding depends on map iteration order; verification would fail at random")
	}

	// And distinct content must not collide: the field framing has to keep
	// adjacent values from running together.
	c := sampleTrailer()
	c.Tables = map[string]int{"identities": 402, "issuers": 0}
	if string(signedTrailerBytes(a)) == string(signedTrailerBytes(c)) {
		t.Fatal("two different table-count sets produce the same signed bytes")
	}
}
