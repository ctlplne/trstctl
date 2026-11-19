// SPDX-License-Identifier: BUSL-1.1

// Package githubidentity defines the issuer and ID wire format shared by
// configuration, trust management and GitHub Actions proof verification.
package githubidentity

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
)

const DefaultIssuer = "https://token.actions.githubusercontent.com"

const (
	RepositoryOwnerIDClaim = "repository_owner_id"
	RepositoryIDClaim      = "repository_id"
)

// EffectiveIssuer identifies the namespace that owns the configured pins.
func EffectiveIssuer(issuer string) string {
	if issuer == "" {
		return DefaultIssuer
	}
	return issuer
}

// ValidID requires a canonical positive decimal string in the uint64 range.
func ValidID(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == value
}

// PinIDs preserves the difference between an omitted list and an explicit
// empty list. A present null, non-string element or noncanonical ID is invalid.
type PinIDs []string

func (ids *PinIDs) UnmarshalJSON(raw []byte) error {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return errors.New("GitHub pins must be an array of ID strings")
	}
	normalized, err := NormalizeIDs(values)
	if err != nil {
		return err
	}
	*ids = normalized
	return nil
}

// NormalizeIDs canonicalizes an ID list's order and removes duplicates.
func NormalizeIDs(values []string) ([]string, error) {
	ids := slices.Clone(values)
	for _, id := range ids {
		if !ValidID(id) {
			return nil, errors.New("GitHub pins must be canonical positive decimal strings within the unsigned 64-bit range")
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}
