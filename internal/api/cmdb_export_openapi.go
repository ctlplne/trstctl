// SPDX-License-Identifier: BUSL-1.1

package api

func cmdbExportBindingSchema() *Schema {
	return object(map[string]*Schema{"id": {Type: "string"}, "enabled": {Type: "boolean"}, "data_source": {Type: "string"}}, "id", "enabled", "data_source")
}

func cmdbExportInputSchema() *Schema {
	return object(map[string]*Schema{"binding_id": {Type: "string"}, "certificate_id": {Type: "string", Format: "uuid"}}, "binding_id", "certificate_id")
}

func cmdbExportStatusSchema() *Schema {
	receipt := object(map[string]*Schema{
		"operation_id": {Type: "string", Format: "uuid"}, "binding_id": {Type: "string"}, "binding_digest": {Type: "string"},
		"certificate_id": {Type: "string", Format: "uuid"}, "fingerprint": {Type: "string"}, "certificate_status": {Type: "string"},
		"sys_id": {Type: "string"}, "values_digest": {Type: "string"}, "checked_at": {Type: "string", Format: "date-time"},
	}, "operation_id", "binding_id", "binding_digest", "certificate_id", "fingerprint", "certificate_status", "sys_id", "values_digest", "checked_at")
	return object(map[string]*Schema{
		"id": {Type: "string", Format: "uuid"}, "binding_id": {Type: "string"}, "certificate_id": {Type: "string", Format: "uuid"},
		"fingerprint": {Type: "string"}, "status": {Type: "string"}, "attempts": {Type: "integer"}, "last_error": {Type: "string"},
		"verified_at": {Type: "string", Format: "date-time"}, "receipt": receipt,
	}, "id", "binding_id", "certificate_id", "fingerprint", "status", "attempts")
}
