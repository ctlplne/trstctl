// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import "fmt"

// KeyHandle returns the deterministic in-signer key handle for an identity's key at
// a given algorithm-epoch. The signer holds the genesis key under KeyHandle(id, 0)
// and persists each minted successor under KeyHandle(id, newEpoch); a succession
// therefore resolves its predecessor as KeyHandle(id, currentEpoch) with no handle
// needing to cross the wire or be stored separately from the epoch (INT-03). The
// handle is opaque to relying parties — it is a signer-local key reference, never a
// credential or an identity claim.
func KeyHandle(identityID string, epoch uint64) string {
	return fmt.Sprintf("pcas:%s:%d", identityID, epoch)
}
