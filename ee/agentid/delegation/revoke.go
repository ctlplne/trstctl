// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"encoding/hex"
	"errors"
)

// revoke.go defines the narrow non-revocation reader the gate consults before any key
// op: the gate must refuse a chain whose head (or any ancestor) has been revoked by
// the AGID-02 ledger projection. The gate depends only on this small interface -- NOT
// the SQL *Repo -- so it is testable with a fake and keeps the heavy store out of the
// AN-4 signer's dependency closure. The production adapter over the AGID-02 projection
// reader is wired at attach time (a later card); a signer built with no reader treats
// EVERY subject as non-revoked ONLY if explicitly constructed that way, and the
// production wiring always supplies a real reader (fail-closed by construction).

// ErrRevoked is returned by the gate when a delegation record on the chain has been
// revoked. Fail-closed: a revoked chain yields a signed refusal, no key op.
var ErrRevoked = errors.New("delegation: a delegation record on the chain is revoked")

// RevocationReader answers, as of the signer's current view, whether a delegation
// record digest has been revoked by the AGID-02 revocation projection. It is a PURE
// read: it performs no key operation and no mutation. The gate calls IsRevoked for
// each hop digest of the chain (and refuses if any is revoked), so a revocation of any
// ancestor stops issuance of a fresh descendant (the pre-issuance half of the cascade;
// the cascade over already-issued credentials is AGID-10/11).
//
// The digest argument is the raw record digest (Record.Digest); implementations key
// on its hex form to match the projection's hex-keyed maps.
type RevocationReader interface {
	// IsRevoked reports whether the record identified by recordDigest is revoked, as
	// of the reader's current watermark. A reader error is surfaced to the gate, which
	// fails closed (a reader that cannot answer must not let issuance proceed).
	IsRevoked(tenantID string, recordDigest []byte) (bool, error)
}

// NeverRevoked is a RevocationReader that reports nothing revoked. It exists ONLY for
// tests and for the single-hop/no-chain paths where there is no chain record to
// revoke; production wiring supplies a real projection-backed reader. It is exported
// so tests and the attestation-gated fallback (which has no chain) can pass it
// explicitly rather than a nil reader (a nil reader is rejected by the gate
// constructor, fail-closed).
type NeverRevoked struct{}

// IsRevoked always reports false, nil.
func (NeverRevoked) IsRevoked(string, []byte) (bool, error) { return false, nil }

// MapRevocationReader is an in-memory RevocationReader backed by a set of revoked
// record-digest hex strings, keyed by tenant. It is the test twin of the AGID-02
// projection: a test seeds the revoked digests and asserts the gate refuses a chain
// touching any of them. It is exported so adversarial tests across packages can use
// it.
type MapRevocationReader struct {
	// Revoked maps tenant id -> set of revoked record-digest hex strings.
	Revoked map[string]map[string]struct{}
	// Err, when non-nil, is returned by IsRevoked to exercise the reader-error
	// fail-closed path.
	Err error
}

// IsRevoked reports whether recordDigest (hex) is in the revoked set for tenantID.
func (m MapRevocationReader) IsRevoked(tenantID string, recordDigest []byte) (bool, error) {
	if m.Err != nil {
		return false, m.Err
	}
	set, ok := m.Revoked[tenantID]
	if !ok {
		return false, nil
	}
	_, revoked := set[hex.EncodeToString(recordDigest)]
	return revoked, nil
}
