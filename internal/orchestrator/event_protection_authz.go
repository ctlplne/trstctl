// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "trstctl.com/trstctl/internal/eventprivacy"

// The source policy supplies no permission or service grant. It selects only
// the closed audit representation needed when detailed data cannot be written.
func WithEventProtectionSourcePolicy(policy *eventprivacy.SourcePolicy) OrchestratorOption {
	return func(o *Orchestrator) { o.eventProtectionSourcePolicy = policy }
}
