// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"errors"
	"strings"
)

// ValidateKEMRewrapStages gives a signed request one unambiguous, bounded set
// of stage names. Their order is part of the immutable request digest.
func ValidateKEMRewrapStages(stages []string) error {
	if len(stages) == 0 || len(stages) > 32 {
		return errors.New("pcas KEM rewrap: 1 to 32 stages are required")
	}
	seen := make(map[string]bool, len(stages))
	for _, stage := range stages {
		if stage == "" || len(stage) > 128 || strings.TrimSpace(stage) != stage || seen[stage] {
			return errors.New("pcas KEM rewrap: stage names must be distinct, nonempty and at most 128 bytes")
		}
		seen[stage] = true
	}
	return nil
}
