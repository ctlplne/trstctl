// SPDX-License-Identifier: BUSL-1.1

package events

import "strings"

// IsLegacyProviderGlobalAudit identifies only the historical Provider audit
// partition that predates UUID tenant identifiers on deployment-wide events.
// Its envelope stays immutable. Core consumers with no Provider side effect may
// advance past it, while the licensed projection still replays the original.
// New Provider events use the reserved UUID partition instead.
func IsLegacyProviderGlobalAudit(event Event) bool {
	return event.TenantID == "provider-control-plane" && strings.HasPrefix(event.Type, "provider.")
}
