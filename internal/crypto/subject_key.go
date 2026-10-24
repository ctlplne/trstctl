// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
)

// ErrWeakKey marks the refusal of a key that fails one of the structural
// weak-key checks RefuseWeakKey runs (small factor, close primes, ROCA, an
// operator blocklist hit, a small EC scalar, a bad RSA exponent).
// errors.Is(err, ErrWeakKey) holds for every such refusal.
var ErrWeakKey = errors.New("crypto: weak key")

// ErrCompromisedKey marks the refusal of a subject key the tenant has recorded
// as compromised (a key-compromise flow, or a revocation with reason
// keyCompromise): CA/B BR 6.1.1.3, condition 4.
var ErrCompromisedKey = errors.New("crypto: key recorded as compromised")

// WeakKeyError names the structural checks a key failed (the
// internal/crypto/weakkey check codes) and why.
type WeakKeyError struct {
	Checks  []string
	Reasons string
}

func (e *WeakKeyError) Error() string {
	return "crypto: refusing a weak key (" + strings.Join(e.Checks, ", ") + "): " + e.Reasons
}

// Is makes errors.Is(err, ErrWeakKey) hold.
func (e *WeakKeyError) Is(target error) bool { return target == ErrWeakKey }

// RefusedSubjectKey reports whether err refuses a subject key as weak or as
// recorded compromised, so a front door can answer with its own bad-request
// shape rather than a server error.
func RefusedSubjectKey(err error) bool {
	return errors.Is(err, ErrWeakKey) || errors.Is(err, ErrCompromisedKey)
}

// SubjectKeyRefusalDetail renders a subject-key refusal as one sentence
// naming the failed check, or "" when err is no such refusal.
func SubjectKeyRefusalDetail(err error) string {
	var weak *WeakKeyError
	switch {
	case errors.As(err, &weak):
		return "the subject key fails the weak-key check " + strings.Join(weak.Checks, ", ") + ": " + weak.Reasons
	case errors.Is(err, ErrCompromisedKey):
		return "the subject key is recorded as compromised in this tenant (CA/B BR 6.1.1.3); generate a new key"
	default:
		return ""
	}
}

var (
	oidSubjectKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSubjectKeyEC  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// RefuseWeakSubjectKey refuses to certify a subject public key (a CSR's, an
// SVID's, an agent's) that fails a structural weak-key check, naming the
// check (owner decision, batch 11). Only RSA and EC keys have structural
// checks; Ed25519 and post-quantum keys pass. Size and algorithm floors are
// not checked here: they stay with each profile's key policy.
func RefuseWeakSubjectKey(spkiDER []byte) error {
	var spki opaquePublicKeyInfo
	rest, err := asn1.Unmarshal(spkiDER, &spki)
	if err != nil || len(rest) != 0 {
		return errors.New("crypto: subject public key does not parse")
	}
	if !spki.Algorithm.Algorithm.Equal(oidSubjectKeyRSA) && !spki.Algorithm.Algorithm.Equal(oidSubjectKeyEC) {
		return nil
	}
	if err := RefuseWeakKey(PublicKey{DER: spkiDER}); err != nil {
		return fmt.Errorf("subject key: %w", err)
	}
	return nil
}

// subjectKeyRefusal is a leaf-profile rejection of the subject key itself:
// IsLeafProfileViolation holds, so issuers already map it to a deny, and so
// do errors.Is(err, ErrWeakKey) or errors.Is(err, ErrCompromisedKey).
type subjectKeyRefusal struct {
	*leafProfileError
	cause error
}

func (e *subjectKeyRefusal) Unwrap() []error { return []error{e.leafProfileError, e.cause} }

func newSubjectKeyRefusal(cause error) error {
	return &subjectKeyRefusal{leafProfileError: &leafProfileError{msg: cause.Error()}, cause: cause}
}
