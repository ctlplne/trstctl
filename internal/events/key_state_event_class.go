// SPDX-License-Identifier: BUSL-1.1
package events

// RequiresExclusiveKeyStateAdmission classifies event types whose projection
// changes tenant or deployment key state. Ingress and projection use the same
// closed list so a shared command cannot publish an event it cannot project.
func RequiresExclusiveKeyStateAdmission(eventType string) bool {
	switch eventType {
	case "tenant.offboarded",
		"pam.session.recording_chunk_rewrapped",
		"tenant.key_domain.migration_started", "tenant.key_domain.migration_progressed",
		"tenant.key_domain.migration_completed", "tenant.key_domain.migration_failed",
		"tenant.key_domain.seal_requested", "tenant.key_domain.seal_failed",
		"tenant.key_domain.sealed", "tenant.key_domain.unseal_requested",
		"tenant.key_domain.unsealed", "tenant.key_domain.rotation_started",
		"tenant.key_domain.rotation_progressed", "tenant.key_domain.rotation_completed",
		"tenant.key_domain.rotation_failed",
		"deployment.kek.rotation_started", "deployment.kek.rotation_progressed",
		"deployment.kek.rotation_completed", "deployment.kek.rotation_failed":
		return true
	default:
		return false
	}
}
