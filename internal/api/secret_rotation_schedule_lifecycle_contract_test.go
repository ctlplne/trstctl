// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/eventledger"
)

func TestSecretRotationScheduleLifecycleContract(t *testing.T) {
	doc := New(nil, nil, nil).Spec()
	read := doc.Paths["/api/v1/secrets/rotation-schedules/{id}"]["get"]
	if read == nil || read.OperationID != "getSecretRotationSchedule" || read.XPermission != "secrets:read" {
		t.Fatalf("exact tenant-scoped schedule read is incomplete: %+v", read)
	}
	for path, operationID := range map[string]string{
		"/api/v1/secrets/rotation-schedules/{id}/pause":  "pauseSecretRotationSchedule",
		"/api/v1/secrets/rotation-schedules/{id}/resume": "resumeSecretRotationSchedule",
		"/api/v1/secrets/rotation-schedules/{id}/retire": "retireSecretRotationSchedule",
	} {
		op := doc.Paths[path]["post"]
		if op == nil || op.OperationID != operationID || op.XPermission != "secrets:write" {
			t.Errorf("secret schedule lifecycle route %s is incomplete: %+v", path, op)
		}
	}
	schema := doc.Components.Schemas["SecretRotationSchedule"]
	if schema == nil || schema.Properties["retired_at"] == nil {
		t.Fatal("schedule readback must distinguish retired from paused")
	}
	for action, wantType := range map[string]string{
		"pause_secret_rotation_schedule":  eventledger.EventSecretRotationSchedulePaused,
		"resume_secret_rotation_schedule": eventledger.EventSecretRotationScheduleResumed,
		"retire_secret_rotation_schedule": eventledger.EventSecretRotationScheduleRetired,
	} {
		types, ok := eventledger.EventTypesForFeatureAction("F37", action)
		if !ok || len(types) != 1 || types[0] != wantType {
			t.Errorf("F37 audit action %s mixes control events: %v, %t", action, types, ok)
		}
	}
}
