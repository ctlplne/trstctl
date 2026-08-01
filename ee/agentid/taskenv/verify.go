// SPDX-License-Identifier: LicenseRef-trstctl-EE

package taskenv

import (
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// verify.go is the pure, testable in-signer verification of a task envelope (AGID-claim-2 /
// INV-A4): the requester signature and the non-expiry check the isolated signer runs as
// a PRECONDITION of the key operation. It performs NO key operation and holds no key: it
// resolves the requester's public key through a caller-supplied trust lookup and checks
// the signature (via internal/crypto, AN-3) and the expiry window against the issuance
// time. The delegation gate (AGID-04, extended by AGID-05) calls this before any keygen;
// on failure the gate mints a signed refusal with zero key ops (INV-A1 preserved).

// TrustLookup resolves a requester key id to the PKIX/DER SubjectPublicKeyInfo of the
// requester's public key, and whether it is trusted. The signer holds this mapping (a
// registry of requester identities to their phishing-resistant keys); a caller cannot
// inject their own key, exactly as the delegation gate's root-anchor trust store makes a
// carried chain trustworthy. An unresolved id returns (nil,false) and the envelope is
// refused fail-closed (ErrUnknownRequester).
type TrustLookup func(requesterKeyID string) (publicDER []byte, trusted bool)

// VerifySignatureAndExpiry verifies a task envelope's requester signature and non-expiry
// as a precondition of a key operation (AGID-claim-2). It is pure and fail-closed:
//
//   - the envelope must state some intent (Validate);
//   - the requester key id must resolve through trustLookup to a trusted public key
//     (else ErrUnknownRequester);
//   - the requester signature must verify against that key over the canonical bytes
//     (else ErrSignature);
//   - the issuance time now must fall within the expiry window (else ErrExpired).
//
// It performs NO key operation. The delegation gate turns any returned error into a
// signed refusal naming the task_envelope check, with zero key ops.
func VerifySignatureAndExpiry(env Envelope, now time.Time, trustLookup TrustLookup) error {
	if err := env.Validate(); err != nil {
		return err
	}
	if trustLookup == nil {
		// No way to resolve the requester key: cannot trust the signature. Fail closed.
		return ErrUnknownRequester
	}
	pubDER, trusted := trustLookup(env.RequesterKey.ID)
	if !trusted || len(pubDER) == 0 {
		return ErrUnknownRequester
	}
	if err := env.VerifySignature(crypto.PublicKey{DER: pubDER}); err != nil {
		return err
	}
	if !withinNow(env.Expiry, now) {
		return ErrExpired
	}
	return nil
}

// withinNow reports whether now falls within the expiry window (inclusive). A
// zero-valued window (NotBefore == 0 && NotAfter == 0) is treated as "no bound" (always
// valid) so a caller that omits expiry is not force-expired; a set NotAfter is honored
// strictly. This mirrors the delegation gate's withinNow so envelope expiry and hop
// validity share their semantics.
func withinNow(w Window, now time.Time) bool {
	ts := now.Unix()
	if w.NotBefore == 0 && w.NotAfter == 0 {
		return true
	}
	if w.NotBefore != 0 && ts < w.NotBefore {
		return false
	}
	if w.NotAfter != 0 && ts > w.NotAfter {
		return false
	}
	return true
}
