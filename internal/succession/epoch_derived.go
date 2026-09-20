// SPDX-License-Identifier: BUSL-1.1

package succession

import "trstctl.com/trstctl/internal/eventspec"

// DerivedEpoch computes an identity's algorithm-epoch purely from its event
// history — the count of recorded algorithm-change (succession) events — with no
// separately stored counter (PCAS-claim-47 / INV-16). For a valid monotone chain it
// equals the stored epoch (the highest bound epoch), so monotonicity does not
// depend on the storage form of the counter. Malformed events are surfaced as
// errors; unknown/forward events are skipped (same rule as Decode).
func DerivedEpoch(seq []eventspec.Event, identityID string) (uint64, error) {
	var count uint64
	for _, e := range seq {
		pl, err := Decode(e)
		if err != nil {
			return 0, err
		}
		if s, ok := pl.(SuccessionV1); ok && s.IdentityID == identityID {
			count++
		}
	}
	return count, nil
}
