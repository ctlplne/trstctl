// SPDX-License-Identifier: BUSL-1.1

// Package tenantnames holds deployment-owned DNS namespace grants for the
// platform issuing CA. A tenant's certificate profile cannot grant itself names.
package tenantnames

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Grants maps a canonical tenant UUID to the DNS suffixes its platform-CA
// certificates may carry. The deployment operator supplies this map.
type Grants map[string][]string

// Validate refuses malformed and overlapping grants at startup, before an
// issuance can depend on ambiguous ownership.
func (g Grants) Validate() error {
	for tenantID, suffixes := range g {
		parsed, err := uuid.Parse(tenantID)
		if err != nil || parsed == uuid.Nil || parsed.String() != tenantID || len(suffixes) == 0 {
			return fmt.Errorf("tenant DNS namespace %q requires a canonical tenant UUID and DNS suffixes", tenantID)
		}
		for _, suffix := range suffixes {
			if !validSuffix(suffix) {
				return fmt.Errorf("tenant DNS namespace %q has invalid suffix %q", tenantID, suffix)
			}
			for otherID, otherSuffixes := range g {
				if otherID >= tenantID {
					continue
				}
				for _, other := range otherSuffixes {
					if within(suffix, other) || within(other, suffix) {
						return fmt.Errorf("tenant DNS namespaces %q and %q overlap", tenantID, otherID)
					}
				}
			}
		}
	}
	return nil
}

// Allows returns false for a tenant with no operator grant and for any name
// outside its suffixes. A leading wildcard is permitted only inside a grant.
func (g Grants) Allows(tenantID, name string) bool {
	name = strings.ToLower(name)
	name = strings.TrimPrefix(name, "*.")
	if !validSuffix(name) {
		return false
	}
	for _, suffix := range g[tenantID] {
		if within(name, suffix) {
			return true
		}
	}
	return false
}

func within(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

func validSuffix(name string) bool {
	if name == "" || name != strings.ToLower(strings.TrimSpace(name)) || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}
