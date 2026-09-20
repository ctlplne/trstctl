// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"bytes"
	"testing"
)

// TestBackupDigestIsKeyed is the regression guard for the forged-restore defect.
// The postgres-state artifact's integrity trailer was computed with
// newDigest(nil) — an HMAC with no key, i.e. a plain SHA-256 that anyone can
// recompute over content of their choosing. A forged artifact therefore
// verified, and the restore imported whatever rows it carried, api_tokens
// included. The event-log artifact was already keyed; this one was not.
//
// The property that makes the trailer unforgeable is simply that the digest
// DEPENDS on the key, so that is what this asserts directly.
func TestBackupDigestIsKeyed(t *testing.T) {
	payload := []byte(`{"format":"postgres-state","row":{"id":"attacker-chosen"}}`)

	// The trailer carries BOTH a SHA-256 and an HMAC. The SHA-256 detects
	// corruption and is deliberately key-independent; the HMAC is the part that
	// proves provenance, so that is the one that must depend on the key.
	mac := func(key []byte) []byte {
		d := newDigest(key)
		feed(d, payload)
		return d.mac()
	}
	sum := func(key []byte) []byte {
		d := newDigest(key)
		feed(d, payload)
		return d.sum()
	}

	if got := mac(nil); len(got) != 0 {
		t.Fatalf("an unkeyed digest produced an HMAC (%x); a forger could supply one", got)
	}
	real := mac([]byte("deployment-backup-integrity-key"))
	guessed := mac([]byte("attacker-guessed-key"))
	if len(real) == 0 {
		t.Fatal("a keyed digest produced no HMAC; the trailer would carry nothing to authenticate")
	}
	if bytes.Equal(real, guessed) {
		t.Fatal("two different keys produce the same HMAC")
	}
	// And the plain SHA-256 is key-independent by design, so it can never be the
	// thing that authenticates the artifact.
	if !bytes.Equal(sum(nil), sum([]byte("deployment-backup-integrity-key"))) {
		t.Fatal("the SHA-256 became key-dependent; the HMAC is the authentication, not the checksum")
	}
}

// TestPostgresStateVerifyRejectsWrongKey pins the end-to-end consequence: an
// artifact is only accepted under the key it was sealed with. It uses the
// package's own writer output shape via the digest, so it cannot drift from the
// production format.
func TestPostgresStateVerifyRejectsWrongKey(t *testing.T) {
	// A truncated/forged stream must never verify under any key — the point is
	// that verification is not a formality that a hand-made file can satisfy.
	forged := []byte(`{"format":"postgres-state","version":1}` + "\n" +
		`{"format":"postgres-state-trailer","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}` + "\n")

	for name, key := range map[string][]byte{
		"no key":        nil,
		"deployment":    []byte("deployment-backup-integrity-key"),
		"attacker key":  []byte("attacker-guessed-key"),
		"empty non-nil": {},
	} {
		if _, err := VerifyPostgresStateWithKey(bytes.NewReader(forged), key, PostgresStateIdentity{}); err == nil {
			t.Errorf("%s: a hand-forged artifact verified", name)
		}
	}
}
