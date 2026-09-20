// SPDX-License-Identifier: BUSL-1.1

package rpverify

import (
	"errors"
	"fmt"
)

// ErrStaleIssuerEpoch is returned when a leaf carries an issuer epoch below the
// relying party's last-accepted issuer epoch for that authority (PCAS-claim-27).
var ErrStaleIssuerEpoch = errors.New("rpverify: leaf carries an issuer epoch below the last-accepted issuer epoch")

// LeafTuple is the (issuer-epoch, rotation-version) tuple an end-entity leaf carries
// under an issuer-level succession (PCAS-claim-27). The issuer epoch is the algorithm-epoch
// of the issuing authority at issuance; the rotation version is the leaf's ordinary
// (algorithm-invariant) re-issuance counter.
type LeafTuple struct {
	IssuerEpoch     uint64
	RotationVersion uint64
}

// AcceptLeafTuple checks a leaf's carried issuer epoch against the relying party's
// durable last-accepted issuer epoch for authorityID, using the same EpochStore
// discipline as chain verification (keyed by the authority identifier). A leaf whose
// issuer epoch is below last-accepted is rejected (PCAS-claim-27); a current-or-newer
// issuer epoch is accepted and advances the store. A nil store disables the
// discipline (single-shot check).
func AcceptLeafTuple(authorityID string, tuple LeafTuple, store EpochStore) error {
	if store == nil {
		return nil
	}
	last, ok, err := store.LastAccepted(authorityID)
	if err != nil {
		return err
	}
	if ok && tuple.IssuerEpoch < last {
		return fmt.Errorf("%w: authority %q leaf issuer epoch %d < last-accepted %d", ErrStaleIssuerEpoch, authorityID, tuple.IssuerEpoch, last)
	}
	if !ok || tuple.IssuerEpoch > last {
		if err := store.SetLastAccepted(authorityID, tuple.IssuerEpoch); err != nil {
			return err
		}
	}
	return nil
}
