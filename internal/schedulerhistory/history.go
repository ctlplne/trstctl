// SPDX-License-Identifier: MPL-2.0

// Package schedulerhistory owns the closed historical wire contract for
// secret.rotation_schedule.ran. It is deliberately dependency-light so event
// sanitation, audit, backup, projections, and the scheduler cannot drift onto
// different definitions of a safe legacy error.
package schedulerhistory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	EventType           = "secret.rotation_schedule.ran"
	LegacySchemaVersion = 1

	// RewriteProfile is signed into every continuity receipt created by the
	// one-time legacy scheduler-history sanitation.
	RewriteProfile = "secret_rotation_schedule_v1_error_closure/v1"

	RollbackError          = "scheduled rotation rollback failed"
	TickInterruptedError   = "scheduler operation was interrupted; retry this tick"
	TickProcessingError    = "scheduler processing failed; retry this tick and inspect server logs"
	ApprovalPendingError   = "scheduled rotation is waiting for approval"
	CommandInProgressError = "scheduled rotation command is already in progress"
	ConfigUnanchoredError  = "schedule configuration must be re-saved before it can run"
	GenericDeferredError   = "scheduled rotation is deferred"
)

// ErrSanitationRequired is intentionally fixed. Callers may expose or log this
// error without accidentally copying the unsafe provider text into another
// durable surface.
var ErrSanitationRequired = errors.New("legacy secret-rotation scheduler history sanitation is required")

// CanonicalError maps every non-empty historical detail to scheduler-owned text.
// Unknown input is classified from status and is never returned.
func CanonicalError(status, detail string) string {
	if detail == "" {
		return ""
	}
	switch status {
	case "completed", "queued", "privacy_erased":
		return ""
	case "delivery_failed":
		return "connector delivery failed"
	case "rollback_failed":
		return RollbackError
	case "unsupported":
		if isUnsupportedError(detail) {
			return detail
		}
		return "scheduled rotation is unavailable"
	case "failed", "rolled_back", "retire_pending":
		if isGenericTerminalError(detail) {
			return detail
		}
		return "scheduled rotation failed"
	default:
		return "scheduled rotation failed"
	}
}

// IsCanonicalError reports whether detail is already in the closed vocabulary
// and agrees with the terminal status.
func IsCanonicalError(status, detail string) bool {
	return CanonicalError(status, detail) == detail
}

func isGenericTerminalError(detail string) bool {
	switch detail {
	case "application-secret approval is no longer usable",
		"no such secret",
		"resource not found",
		"approval requester cannot approve their own request",
		"approval request expired",
		"approval request superseded",
		"approval authority already consumed",
		"approval target version or state drifted",
		"approval request has not reached quorum",
		"connector rotation target is required",
		"secret sync target is not configured",
		"connector rotation old_ref must be version:<n>",
		"connector rotation old_ref does not name the current version",
		"scheduled rotation failed":
		return true
	default:
		return false
	}
}

func isUnsupportedError(detail string) bool {
	switch detail {
	case "dynamic-lease rotation is unavailable until its issue, delivery, and predecessor retirement phases share one durable worker command",
		"scheduled static-provider rotation is unavailable until a durable worker owns stage, cutover, verification, rollback, and retirement",
		"scheduled rotation is unavailable":
		return true
	default:
		return false
	}
}

// DeferredError maps a scheduler-owned reason to its fixed operator detail.
func DeferredError(reason string) string {
	switch reason {
	case "approval_pending":
		return ApprovalPendingError
	case "command_claimed", "command_in_flight":
		return CommandInProgressError
	case "config_revision_unanchored":
		return ConfigUnanchoredError
	default:
		return GenericDeferredError
	}
}

// IsCanonicalTickSystemError closes the tick-level error vocabulary.
func IsCanonicalTickSystemError(detail, superseded string) bool {
	switch detail {
	case "", TickInterruptedError, TickProcessingError, superseded:
		return true
	default:
		return false
	}
}

type legacyRun struct {
	ScheduleID string
	RunID      string
	Status     string
	NewRef     string
	Error      string
	fields     map[string]fieldSpan
}

type fieldSpan struct {
	start int
	end   int
	raw   []byte
}

// RequiresSanitation reports whether one event contains an unsafe legacy error.
// Malformed target payloads fail closed; unrelated event schemas are untouched.
func RequiresSanitation(eventType string, schemaVersion int, data []byte) (bool, error) {
	if eventType != EventType || schemaVersion != LegacySchemaVersion {
		return false, nil
	}
	_, changed, err := RewriteLegacyRun(data)
	return changed, err
}

// ValidateSanitizedLegacyRun rejects provider-controlled error text.
func ValidateSanitizedLegacyRun(data []byte) error {
	run, err := decodeLegacyRun(data)
	if err != nil {
		return err
	}
	if CanonicalError(run.Status, run.Error) != run.Error {
		return ErrSanitationRequired
	}
	return nil
}

// RewriteLegacyRun replaces only the JSON token containing error. Whitespace,
// field order, optional-field presence, escapes, and every non-error byte remain
// exact. This makes the transformation easy to audit and pair-validate.
func RewriteLegacyRun(data []byte) ([]byte, bool, error) {
	run, err := decodeLegacyRun(data)
	if err != nil {
		return nil, false, err
	}
	canonical := CanonicalError(run.Status, run.Error)
	if canonical == run.Error {
		return append([]byte(nil), data...), false, nil
	}
	span, ok := run.fields["error"]
	if !ok {
		return nil, false, errors.New("scheduler history: non-empty error lacks its JSON field")
	}
	replacement, err := json.Marshal(canonical)
	if err != nil {
		return nil, false, errors.New("scheduler history: encode canonical error")
	}
	next := make([]byte, 0, len(data))
	next = append(next, data[:span.start]...)
	next = append(next, replacement...)
	next = append(next, data[span.end:]...)
	if err := ValidateLegacyRunPair(data, next); err != nil {
		return nil, false, err
	}
	return next, true, nil
}

// ValidateLegacyRunPair proves that after is exactly the deterministic rewrite
// of before. Comparing the complete expected byte string is stronger than merely
// comparing decoded fields: no second JSON token may change.
func ValidateLegacyRunPair(before, after []byte) error {
	beforeRun, err := decodeLegacyRun(before)
	if err != nil {
		return err
	}
	if _, err := decodeLegacyRun(after); err != nil {
		return err
	}
	canonical := CanonicalError(beforeRun.Status, beforeRun.Error)
	if canonical == beforeRun.Error {
		if !bytes.Equal(before, after) {
			return errors.New("scheduler history: canonical legacy pair changed bytes")
		}
		return nil
	}
	span := beforeRun.fields["error"]
	replacement, err := json.Marshal(canonical)
	if err != nil {
		return errors.New("scheduler history: encode pair canonical error")
	}
	expected := make([]byte, 0, len(before))
	expected = append(expected, before[:span.start]...)
	expected = append(expected, replacement...)
	expected = append(expected, before[span.end:]...)
	if !bytes.Equal(expected, after) {
		return errors.New("scheduler history: legacy pair changed bytes outside the error token")
	}
	return ValidateSanitizedLegacyRun(after)
}

func decodeLegacyRun(data []byte) (legacyRun, error) {
	run := legacyRun{fields: make(map[string]fieldSpan, 5)}
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil {
		return run, errors.New("scheduler history: legacy payload is not valid JSON")
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return run, errors.New("scheduler history: legacy payload is not an object")
	}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return run, errors.New("scheduler history: legacy payload key is invalid")
		}
		key, ok := keyToken.(string)
		if !ok {
			return run, errors.New("scheduler history: legacy payload key is not a string")
		}
		if _, duplicate := run.fields[key]; duplicate {
			return run, errors.New("scheduler history: legacy payload repeats a field")
		}
		switch key {
		case "schedule_id", "run_id", "status", "new_ref", "error":
		default:
			return run, errors.New("scheduler history: legacy payload has an unknown field")
		}
		start, err := jsonValueStart(data, int(dec.InputOffset()))
		if err != nil {
			return run, err
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return run, errors.New("scheduler history: legacy field has an invalid value")
		}
		end := int(dec.InputOffset())
		if start < 0 || end < start || end > len(data) {
			return run, errors.New("scheduler history: legacy payload offsets are invalid")
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return run, errors.New("scheduler history: legacy field is not a string")
		}
		run.fields[key] = fieldSpan{start: start, end: end, raw: append([]byte(nil), raw...)}
		switch key {
		case "schedule_id":
			run.ScheduleID = value
		case "run_id":
			run.RunID = value
		case "status":
			run.Status = value
		case "new_ref":
			run.NewRef = value
		case "error":
			run.Error = value
		}
	}
	if _, err := dec.Token(); err != nil {
		return run, errors.New("scheduler history: legacy payload object is incomplete")
	}
	if err := requireJSONEOF(dec); err != nil {
		return run, err
	}
	for _, required := range []string{"schedule_id", "run_id", "status"} {
		if _, ok := run.fields[required]; !ok {
			return run, fmt.Errorf("scheduler history: legacy payload lacks required field %q", required)
		}
	}
	if run.ScheduleID == "" || run.RunID == "" || run.Status == "" {
		return run, errors.New("scheduler history: legacy payload has an empty required field")
	}
	return run, nil
}

func jsonValueStart(data []byte, afterKey int) (int, error) {
	i := afterKey
	for i < len(data) && isJSONSpace(data[i]) {
		i++
	}
	if i >= len(data) || data[i] != ':' {
		return 0, errors.New("scheduler history: legacy field lacks a value separator")
	}
	i++
	for i < len(data) && isJSONSpace(data[i]) {
		i++
	}
	if i >= len(data) {
		return 0, errors.New("scheduler history: legacy field lacks a value")
	}
	return i, nil
}

func isJSONSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func requireJSONEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("scheduler history: legacy payload has trailing data")
	}
	return nil
}
