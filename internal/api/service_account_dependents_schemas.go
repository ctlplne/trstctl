// SPDX-License-Identifier: BUSL-1.1
package api

func serviceDependentSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	id := func() *Schema { return &Schema{Type: "string", Format: "uuid"} }
	stamp := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	integer := func() *Schema { return &Schema{Type: "integer", Format: "int64"} }
	boolean := func() *Schema { return &Schema{Type: "boolean"} }
	array := func(item *Schema) *Schema { return &Schema{Type: "array", Items: item} }
	return map[string]*Schema{
		"PAMDependentAccountBinding":     object(map[string]*Schema{"account_id": id(), "provider_id": str(), "name": str(), "dn": str(), "sid": str(), "guid": str()}, "account_id", "provider_id", "name", "dn", "sid", "guid"),
		"PAMDependentHostBinding":        object(map[string]*Schema{"account": ref("PAMDependentAccountBinding"), "agent_id": id(), "revision": integer(), "enabled": boolean()}, "account", "agent_id", "revision", "enabled"),
		"PAMDependentInventoryIntent":    object(map[string]*Schema{"run_id": id(), "binding": ref("PAMDependentHostBinding"), "binding_digest": str()}, "run_id", "binding", "binding_digest"),
		"PAMDependentFamilyCoverage":     object(map[string]*Schema{"family": {Type: "string", Enum: []string{"services", "tasks", "iis"}}, "status": {Type: "string", Enum: []string{"complete", "unavailable"}}, "failure": str()}, "family", "status"),
		"PAMDependentNativeService":      object(map[string]*Schema{"name": str(), "account_sid": str(), "config_sha256": str(), "dependencies": array(str()), "was_running": boolean()}, "name", "account_sid", "config_sha256", "was_running"),
		"PAMDependentNativeTask":         object(map[string]*Schema{"path": str(), "account_sid": str(), "config_sha256": str(), "enabled": boolean(), "logon_type": integer(), "action_count": integer()}, "path", "account_sid", "config_sha256", "enabled", "logon_type", "action_count"),
		"PAMDependentNativePool":         object(map[string]*Schema{"name": str(), "account_sid": str(), "config_sha256": str(), "encryption_provider": str(), "password_protected": boolean(), "was_started": boolean()}, "name", "account_sid", "config_sha256", "encryption_provider", "password_protected", "was_started"),
		"PAMDependentInventoryReport":    object(map[string]*Schema{"run_id": id(), "binding_digest": str(), "observed_at": stamp(), "coverage": array(ref("PAMDependentFamilyCoverage")), "services": array(ref("PAMDependentNativeService")), "tasks": array(ref("PAMDependentNativeTask")), "pools": array(ref("PAMDependentNativePool"))}, "run_id", "binding_digest", "observed_at", "coverage"),
		"PAMServiceDependentHostRequest": object(map[string]*Schema{"enabled": boolean()}, "enabled"),
		"PAMServiceDependentScanHead":    object(map[string]*Schema{"delivery_status": str(), "id": id(), "agent_id": id(), "binding_digest": str(), "status": str(), "failure": str(), "queued_at": stamp(), "received_at": stamp(), "service_count": integer(), "task_count": integer(), "pool_count": integer(), "current": boolean()}, "id", "agent_id", "binding_digest", "status", "queued_at", "service_count", "task_count", "pool_count", "current"),
		"PAMServiceDependentHost":        object(map[string]*Schema{"binding": ref("PAMDependentHostBinding"), "binding_digest": str(), "latest_scan": ref("PAMServiceDependentScanHead"), "saved_by": str(), "updated_at": stamp()}, "binding", "binding_digest", "saved_by", "updated_at"),
		"PAMServiceDependentHostList":    object(map[string]*Schema{"items": array(ref("PAMServiceDependentHost")), "next_cursor": str()}, "items"),
		"PAMServiceDependentScan":        object(map[string]*Schema{"delivery_status": str(), "id": id(), "intent": ref("PAMDependentInventoryIntent"), "status": {Type: "string", Enum: []string{"queued", "complete", "partial", "retrying", "failed", "superseded"}}, "queued_by": str(), "queued_at": stamp(), "queued_event_id": id(), "outbox_id": integer(), "report": ref("PAMDependentInventoryReport"), "report_digest": str(), "failure": str(), "service_count": integer(), "task_count": integer(), "pool_count": integer(), "received_at": stamp(), "observed_at": stamp(), "attempt": integer(), "receipt_job_id": integer(), "receipt_statement": str(), "receipt_signature_base64": str(), "signer_fingerprint": str()}, "id", "intent", "status", "queued_by", "queued_at", "queued_event_id", "service_count", "task_count", "pool_count"),
	}
}
