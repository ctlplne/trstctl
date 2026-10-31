// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"fmt"
	"strings"
)

// DestinationScope confines every stage of a sweep to the same destination
// family. Exact and prefix includes form a union; either exclusion removes a
// destination. Empty includes mean all. Comparisons are literal, never SQL LIKE
// patterns. This scope routes claims and grants no receiver or tenant authority.
type DestinationScope struct {
	IncludePrefixes     []string
	ExcludePrefixes     []string
	IncludeDestinations []string
	ExcludeDestinations []string
}

func (s DestinationScope) validate() error {
	seen := make(map[string]string, len(s.IncludePrefixes)+len(s.ExcludePrefixes))
	for kind, prefixes := range map[string][]string{"include": s.IncludePrefixes, "exclude": s.ExcludePrefixes} {
		for _, prefix := range prefixes {
			if prefix == "" {
				return fmt.Errorf("orchestrator: outbox destination scope has an empty %s prefix", kind)
			}
			if prior, ok := seen[prefix]; ok {
				return fmt.Errorf("orchestrator: outbox destination prefix %q appears in both/duplicate %s and %s sets", prefix, prior, kind)
			}
			seen[prefix] = kind
		}
	}
	for kind, destinations := range map[string][]string{"include destination": s.IncludeDestinations, "exclude destination": s.ExcludeDestinations} {
		for _, destination := range destinations {
			if destination == "" {
				return fmt.Errorf("orchestrator: outbox destination scope has an empty %s", kind)
			}
			if prior, ok := seen[destination]; ok {
				return fmt.Errorf("orchestrator: outbox destination scope repeats a coordinate in %s and %s", prior, kind)
			}
			seen[destination] = kind
		}
	}
	return nil
}

func (s DestinationScope) matches(destination string) bool {
	included := len(s.IncludePrefixes) == 0 && len(s.IncludeDestinations) == 0
	for _, exact := range s.IncludeDestinations {
		if destination == exact {
			included = true
			break
		}
	}
	for _, prefix := range s.IncludePrefixes {
		if strings.HasPrefix(destination, prefix) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, exact := range s.ExcludeDestinations {
		if destination == exact {
			return false
		}
	}
	for _, prefix := range s.ExcludePrefixes {
		if strings.HasPrefix(destination, prefix) {
			return false
		}
	}
	return true
}

func (o *Outbox) constrainScope(scope DestinationScope) (DestinationScope, error) {
	if err := scope.validate(); err != nil {
		return DestinationScope{}, err
	}
	if len(o.excludedDestinations) == 0 {
		return scope, nil
	}
	// Copy the caller's slice: parallel family sweeps may share that definition.
	scope.ExcludeDestinations = append([]string(nil), scope.ExcludeDestinations...)
	seen := make(map[string]bool, len(scope.ExcludeDestinations)+len(o.excludedDestinations))
	for _, destination := range scope.ExcludeDestinations {
		seen[destination] = true
	}
	for _, destination := range o.excludedDestinations {
		if destination == "" {
			return DestinationScope{}, fmt.Errorf("orchestrator: empty construction-level outbox exclusion")
		}
		if !seen[destination] {
			scope.ExcludeDestinations = append(scope.ExcludeDestinations, destination)
			seen[destination] = true
		}
	}
	return scope, nil
}
