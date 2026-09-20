// SPDX-License-Identifier: BUSL-1.1

// Package quorum is the tiny, signer-safe break-glass quorum primitive. It is
// kept separate from the wider breakglass package so AN-4 signer integrations can
// reuse distinct-operator m-of-n verification without linking admin, store, or
// event-log dependencies.
package quorum

import "fmt"

// Quorum enforces m-of-n operator authorization.
type Quorum struct {
	Threshold int      // m
	Operators []string // the n authorized operators
}

// Verify checks that the approvals meet the quorum: every approver is an
// authorized operator and the count of distinct approvers is at least Threshold.
func (q Quorum) Verify(approvals []string) error {
	if q.Threshold <= 0 {
		return fmt.Errorf("breakglass: quorum threshold must be positive")
	}
	allowed := make(map[string]bool, len(q.Operators))
	for _, op := range q.Operators {
		allowed[op] = true
	}
	seen := map[string]bool{}
	count := 0
	for _, a := range approvals {
		if !allowed[a] {
			return fmt.Errorf("breakglass: %q is not an authorized break-glass operator", a)
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		count++
	}
	if count < q.Threshold {
		return fmt.Errorf("breakglass: quorum not met (%d of %d required)", count, q.Threshold)
	}
	return nil
}
