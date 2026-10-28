// SPDX-License-Identifier: BUSL-1.1

package retirement

import (
	"encoding/json"
	"fmt"
)

// RosterEntry is one relying party's acknowledgment key as a retirement
// policy stores it.
type RosterEntry struct {
	RelyingParty string `json:"relying_party"`
	PublicDER    []byte `json:"public_der"`
}

// DecodeRoster reads a retirement policy's stored roster. Entries without a
// name or key are skipped; they could never verify an acknowledgment.
func DecodeRoster(raw json.RawMessage) (Roster, error) {
	if len(raw) == 0 {
		return Roster{}, nil
	}
	var entries []RosterEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("retirement: decode roster: %w", err)
	}
	roster := Roster{}
	for _, e := range entries {
		if e.RelyingParty != "" && len(e.PublicDER) > 0 {
			roster[e.RelyingParty] = e.PublicDER
		}
	}
	return roster, nil
}
