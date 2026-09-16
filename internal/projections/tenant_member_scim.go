// SPDX-License-Identifier: MPL-2.0
package projections

import "trstctl.com/trstctl/internal/store"

// Privacy-sanitized history can carry an empty object after clearing its entire
// provisioning identity. It is absence of personal metadata, not an empty alias.
func normalizedSCIMIdentity(identity *store.SCIMIdentity) *store.SCIMIdentity {
	if identity != nil && identity.UserName == "" && identity.ExternalID == "" && identity.SubjectAttribute == "" {
		return nil
	}
	return identity
}
