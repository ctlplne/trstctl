// SPDX-License-Identifier: BUSL-1.1

package api

func sshTrustReadinessSchema() *Schema {
	return object(map[string]*Schema{
		"enabled": {Type: "boolean"}, "confirmed": {Type: "boolean"}, "ca_fingerprint": {Type: "string"}, "policy_digest": {Type: "string"}, "issue_code": {Type: "string", Enum: []string{"local_configuration_invalid", "report_state_paused"}},
	}, "enabled", "confirmed")
}

func sshTrustFleetPlanSchema() *Schema {
	host := object(map[string]*Schema{"agent_id": {Type: "string", Format: "uuid"}, "readiness_digest": {Type: "string"}, "state": {Type: "string", Enum: []string{"ready", "skipped"}}, "reason": {Type: "string", Enum: []string{"disabled", "unconfirmed", "misconfigured", "not_reported", "stale", "not_host_role", "ca_not_staged", "claims_paused"}}}, "agent_id", "state")
	return object(map[string]*Schema{"name": {Type: "string"}, "reason": {Type: "string"}, "public_ca_key": {Type: "string", Format: "byte", Description: "Canonical public OpenSSH CA line, encoded as base64 in the reviewed plan."}, "ca_fingerprint": {Type: "string"}, "expires_at": {Type: "string", Format: "date-time"}, "hosts": {Type: "array", Items: host}}, "name", "reason", "public_ca_key", "ca_fingerprint", "expires_at", "hosts")
}

func sshTrustFleetPreviewInputSchema() *Schema {
	return object(map[string]*Schema{
		"name": {Type: "string"}, "reason": {Type: "string"}, "public_ca_key": {Type: "string", Description: "One plain OpenSSH CA public key, never a private key."}, "agent_ids": {Type: "array", Items: &Schema{Type: "string", Format: "uuid"}},
	}, "name", "reason", "public_ca_key", "agent_ids")
}

func sshTrustFleetPlanInputSchema() *Schema {
	return object(map[string]*Schema{"plan": ref("SSHTrustFleetPlan"), "plan_digest": {Type: "string"}}, "plan", "plan_digest")
}
func sshTrustFleetPreviewSchema() *Schema {
	s := sshTrustFleetPlanInputSchema()
	s.Properties["ready_hosts"] = &Schema{Type: "integer"}
	s.Properties["skipped_hosts"] = &Schema{Type: "integer"}
	s.Properties["effect_free"] = &Schema{Type: "boolean"}
	s.Properties["job_kind_enabled"] = &Schema{Type: "boolean"}
	s.Required = append(s.Required, "ready_hosts", "skipped_hosts", "effect_free", "job_kind_enabled")
	return s
}
func sshTrustFleetApprovalSchema() *Schema {
	s := sshTrustFleetPlanInputSchema()
	for k, v := range map[string]*Schema{"approval_request_id": {Type: "string", Format: "uuid"}, "approval_intent_digest": {Type: "string"}, "status": {Type: "string"}, "required_approvals": {Type: "integer"}, "approval_count": {Type: "integer"}, "expires_at": {Type: "string", Format: "date-time"}} {
		s.Properties[k] = v
	}
	s.Required = append(s.Required, "approval_request_id", "approval_intent_digest", "status", "required_approvals", "approval_count", "expires_at")
	return s
}
func sshTrustFleetStartInputSchema() *Schema {
	s := sshTrustFleetPlanInputSchema()
	s.Properties["approval_request_id"] = &Schema{Type: "string", Format: "uuid"}
	s.Properties["approval_intent_digest"] = &Schema{Type: "string"}
	s.Required = append(s.Required, "approval_request_id", "approval_intent_digest")
	return s
}
func sshTrustFleetReportSchema() *Schema {
	return object(map[string]*Schema{
		"rollout_id": {Type: "string", Format: "uuid"}, "agent_id": {Type: "string", Format: "uuid"}, "plan_digest": {Type: "string"}, "readiness_digest": {Type: "string"}, "ca_fingerprint": {Type: "string"},
		"state": {Type: "string", Enum: []string{"verified", "failed", "refused"}}, "phase": {Type: "string", Enum: []string{"preflight", "backup", "write_trust", "write_config", "validate", "reload", "health", "readback", "complete"}}, "rollback": {Type: "string", Enum: []string{"not_needed", "not_available", "verified", "failed"}},
		"reason_code": {Type: "string", Enum: []string{"local_not_enabled", "local_unconfirmed", "other_agent", "policy_changed", "ca_pin_changed", "execution_window_ended", "canceled", "local_configuration_invalid", "host_busy", "apply_failed", "readback_failed"}}, "changed": {Type: "boolean"}, "ca_read_back": {Type: "boolean"}, "effective_config_read_back": {Type: "boolean"}, "trust_file_sha256": {Type: "string"}, "config_file_sha256": {Type: "string"}, "validated": {Type: "boolean"}, "reloaded": {Type: "boolean"}, "healthy": {Type: "boolean"}, "checked_at": {Type: "string", Format: "date-time"},
	}, "rollout_id", "agent_id", "plan_digest", "readiness_digest", "ca_fingerprint", "state", "phase", "rollback", "changed", "ca_read_back", "effective_config_read_back", "validated", "reloaded", "healthy", "checked_at")
}
func sshTrustFleetHostSchema() *Schema {
	return object(map[string]*Schema{
		"agent_id": {Type: "string", Format: "uuid"}, "state": {Type: "string", Enum: []string{"queued", "skipped", "verified", "failed", "refused"}}, "skip_reason": {Type: "string"}, "receipt": ref("SSHTrustFleetReport"), "receipt_event_id": {Type: "string", Format: "uuid"}, "job_id": {Type: "integer", Format: "int64"}, "attempt": {Type: "integer"}, "checked_at": {Type: "string", Format: "date-time"},
	}, "agent_id", "state")
}
func sshTrustFleetRolloutSchema() *Schema {
	return object(map[string]*Schema{
		"tenant_id": {Type: "string", Format: "uuid"}, "id": {Type: "string", Format: "uuid"}, "plan": ref("SSHTrustFleetPlan"), "plan_digest": {Type: "string"}, "approval_request_id": {Type: "string", Format: "uuid"}, "requester": {Type: "string"}, "state": {Type: "string", Enum: []string{"pending", "verified", "attention_required", "execution_window_expired"}}, "window_expired": {Type: "boolean"}, "created_at": {Type: "string", Format: "date-time"}, "updated_at": {Type: "string", Format: "date-time"}, "hosts": {Type: "array", Items: ref("SSHTrustFleetHost")},
	}, "tenant_id", "id", "plan", "plan_digest", "approval_request_id", "requester", "state", "window_expired", "created_at", "updated_at", "hosts")
}
func sshTrustFleetListSchema() *Schema {
	return object(map[string]*Schema{"items": {Type: "array", Items: ref("SSHTrustFleetRollout")}, "next_cursor": {Type: "string"}}, "items")
}
