// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestDecodeSecretRotationScheduleTickReceiptRejectsUnownedErrorTextAUD115(t *testing.T) {
	tests := []struct {
		name          string
		systemError   string
		runError      string
		rotationError string
		rollbackError string
		deferredError string
	}{
		{name: "aggregate system error", systemError: "provider echoed credential AUD-115"},
		{name: "run error", runError: "provider echoed credential AUD-115"},
		{name: "nested rotation error", rotationError: "provider echoed credential AUD-115"},
		{name: "nested rollback error", rollbackError: "provider echoed credential AUD-115"},
		{name: "deferred error", deferredError: "provider echoed credential AUD-115"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := marshalSecretRotationScheduleTickErrorFixture(t,
				test.systemError, test.runError, test.rotationError,
				test.rollbackError, test.deferredError,
			)
			if _, err := decodeSecretRotationScheduleTickReceipt(raw); !errors.Is(
				err, ErrSecretRotationScheduleTickConflict,
			) {
				t.Fatalf("decode arbitrary scheduler error = %v, want tick conflict", err)
			}
		})
	}
}

func TestDecodeSecretRotationScheduleTickReceiptAcceptsOwnedErrorVocabularyAUD115(t *testing.T) {
	raw := marshalSecretRotationScheduleTickErrorFixture(t,
		SecretRotationScheduleTickProcessingError,
		"connector delivery failed",
		"connector delivery failed",
		SecretRotationScheduleRollbackError,
		SecretRotationScheduleApprovalPendingError,
	)
	if _, err := decodeSecretRotationScheduleTickReceipt(raw); err != nil {
		t.Fatalf("decode owned scheduler error vocabulary: %v", err)
	}
}

func TestRetainedSecretRotationScheduleTerminalRevalidatesClosedReceiptAUD113(t *testing.T) {
	status := 200
	valid := []byte(`{"ran":0,"scanned":0,"runs":[],"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,"complete":true,"partial":false}`)
	base := SecretRotationScheduleTick{
		Phase:              "terminal",
		TerminalHTTPStatus: &status,
		Receipt:            append([]byte(nil), valid...),
		TerminalBody:       append([]byte(nil), valid...),
	}
	if err := validateSecretRotationScheduleTickRetainedTerminal(base); err != nil {
		t.Fatalf("validate owned retained terminal: %v", err)
	}

	for name, mutate := range map[string]func(*SecretRotationScheduleTick){
		"arbitrary restored system error": func(tick *SecretRotationScheduleTick) {
			tick.Receipt = bytes.Replace(tick.Receipt, []byte(`"partial":false`),
				[]byte(`"partial":false,"system_error":"provider leaked restored bytes"`), 1)
		},
		"invalid restored terminal body": func(tick *SecretRotationScheduleTick) {
			tick.TerminalBody = bytes.Replace(tick.TerminalBody, []byte(`"complete":true`),
				[]byte(`"complete":false`), 1)
		},
		"receipt and raw body disagree": func(tick *SecretRotationScheduleTick) {
			tick.TerminalBody = bytes.Replace(tick.TerminalBody, []byte(`"partial":false`),
				[]byte(`"partial":false,"failed_schedule_id":"11300000-0000-4000-8000-000000000001"`), 1)
		},
		"successful terminal names a failed schedule": func(tick *SecretRotationScheduleTick) {
			withFailure := bytes.Replace(tick.Receipt, []byte(`"partial":false`),
				[]byte(`"partial":false,"failed_schedule_id":"11300000-0000-4000-8000-000000000001"`), 1)
			tick.Receipt = withFailure
			tick.TerminalBody = append([]byte(nil), withFailure...)
		},
		"successful terminal claims completion before frozen snapshot exhaustion": func(tick *SecretRotationScheduleTick) {
			tick.SnapshotCount = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			tick := base
			tick.Receipt = append([]byte(nil), base.Receipt...)
			tick.TerminalBody = append([]byte(nil), base.TerminalBody...)
			mutate(&tick)
			if err := validateSecretRotationScheduleTickRetainedTerminal(tick); !errors.Is(
				err, ErrSecretRotationScheduleTickConflict,
			) {
				t.Fatalf("validate corrupted retained terminal = %v, want tick conflict", err)
			}
		})
	}

	t.Run("failed terminal claims successful limit completion", func(t *testing.T) {
		failedStatus := 503
		limitReceipt := marshalSecretRotationScheduleFailedLimitFixture(t)
		tick := SecretRotationScheduleTick{
			Phase:              "terminal",
			Ran:                50,
			Scanned:            500,
			SnapshotCount:      500,
			TerminalHTTPStatus: &failedStatus,
			Receipt:            append([]byte(nil), limitReceipt...),
			TerminalBody:       append([]byte(nil), limitReceipt...),
		}
		if err := validateSecretRotationScheduleTickRetainedTerminal(tick); !errors.Is(
			err, ErrSecretRotationScheduleTickConflict,
		) {
			t.Fatalf("validate failed terminal with limit flags = %v, want tick conflict", err)
		}
	})
}

func marshalSecretRotationScheduleFailedLimitFixture(t *testing.T) []byte {
	t.Helper()
	raw := marshalSecretRotationScheduleTickErrorFixture(t,
		SecretRotationScheduleTickProcessingError,
		"connector delivery failed", "connector delivery failed",
		SecretRotationScheduleRollbackError,
		SecretRotationScheduleApprovalPendingError,
	)
	var receipt map[string]any
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	run := receipt["runs"].([]any)[0]
	deferred := receipt["deferred"].([]any)[0]
	runs := make([]any, 50)
	for index := range runs {
		runs[index] = run
	}
	deferredRows := make([]any, 450)
	for index := range deferredRows {
		deferredRows[index] = deferred
	}
	receipt["ran"] = 50
	receipt["scanned"] = 500
	receipt["runs"] = runs
	receipt["deferred"] = deferredRows
	receipt["run_limit_reached"] = true
	receipt["scan_limit_reached"] = true
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func marshalSecretRotationScheduleTickErrorFixture(
	t *testing.T,
	systemError, runError, rotationError, rollbackError, deferredError string,
) []byte {
	t.Helper()
	receipt := map[string]any{
		"ran":                1,
		"scanned":            2,
		"run_limit_reached":  false,
		"scan_limit_reached": false,
		"complete":           false,
		"partial":            true,
		"system_error":       systemError,
		"failed_schedule_id": "11500000-0000-4000-8000-000000000001",
		"runs": []any{map[string]any{
			"schedule_id": "11500000-0000-4000-8000-000000000002",
			"run_id":      "11500000-0000-4000-8000-000000000003",
			"due_at":      "2026-08-11T11:00:00Z",
			"status":      "delivery_failed",
			"rotation": map[string]any{
				"key":                "rotation/aud115",
				"old_ref":            "version:1",
				"new_ref":            "version:2",
				"completed":          false,
				"queued":             false,
				"rolled_back":        false,
				"rollback_attempted": rollbackError != "",
				"rollback_failed":    rollbackError != "",
				"rollback_error":     rollbackError,
				"failed_phase":       "delivery",
				"error":              rotationError,
			},
			"error":      runError,
			"ran_at":     "2026-08-11T11:00:01Z",
			"reconciled": false,
		}},
		"deferred": []any{map[string]any{
			"schedule_id": "11500000-0000-4000-8000-000000000004",
			"reason":      "approval_pending",
			"due_at":      "2026-08-11T11:00:02Z",
			"error":       deferredError,
		}},
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal scheduler error fixture: %v", err)
	}
	return raw
}
