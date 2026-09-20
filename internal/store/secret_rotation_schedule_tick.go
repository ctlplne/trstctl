// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/rotationcommand"
)

var (
	// ErrSecretRotationScheduleTickInProgress is a retryable live-owner conflict.
	// Callers must return it as an error, never as a cacheable idempotent result.
	ErrSecretRotationScheduleTickInProgress = errors.New("store: secret rotation schedule tick is owned by a live runner")
	// ErrSecretRotationScheduleTickConflict means retained aggregate authority
	// differs from the outer key/binding, phase, token, or generation presented.
	ErrSecretRotationScheduleTickConflict = errors.New("store: secret rotation schedule tick conflicts with retained authority")
	// ErrSecretRotationScheduleTickPrivacyErased is permanent closure evidence.
	// The stamped receiver may be inspected or offboarded, but never reclaimed.
	ErrSecretRotationScheduleTickPrivacyErased = errors.New("store: secret rotation schedule tick was closed by privacy erasure")
)

const SecretRotationScheduleTickSupersededError = "scheduler tick lease expired before durable completion; the exact tick was terminalized as indeterminate and a new Idempotency-Key is required"

const SecretRotationScheduleIdentityVersion = rotationcommand.EventSchemaVersion

// SecretRotationScheduleTickClaimState describes whether a callback owns the
// aggregate tick, can replay its terminal bytes, or must wait for a live owner.
type SecretRotationScheduleTickClaimState string

const (
	SecretRotationScheduleTickAcquired      SecretRotationScheduleTickClaimState = "acquired"
	SecretRotationScheduleTickTerminal      SecretRotationScheduleTickClaimState = "terminal"
	SecretRotationScheduleTickSameKeyBusy   SecretRotationScheduleTickClaimState = "same_key_busy"
	SecretRotationScheduleTickDifferentBusy SecretRotationScheduleTickClaimState = "different_key_busy"
)

// SecretRotationScheduleTickPreparation is the scheduler-specific prepared
// durable claim. ProtectedResult is opaque outer idempotency storage and is only
// opened by the orchestrator result protector.
type SecretRotationScheduleTickPreparation struct {
	Tick            SecretRotationScheduleTick
	State           SecretRotationScheduleTickClaimState
	OuterCompleted  bool
	ResultCodec     string
	ProtectedResult []byte
}

// SecretRotationScheduleTick is the independently durable receiver for one
// run-due HTTP command. Receipt contains the exact ordered, non-secret response
// accumulated so far. A row_started snapshot is persisted before child work.
type SecretRotationScheduleTick struct {
	TenantID                        string
	IdentityVersion                 int
	TenantRegistrationEventID       string
	TenantRegistrationEventSequence uint64
	IdempotencyKey                  string
	RequestBinding                  string
	DueThrough                      time.Time
	StartScheduleID                 string
	AfterScheduleID                 string
	Wrapped                         bool
	Phase                           string
	CurrentSchedule                 *SecretRotationSchedule
	CurrentCommandLeaseToken        string
	Ran                             int
	Scanned                         int
	SnapshotCount                   int
	Receipt                         json.RawMessage
	OwnerToken                      string
	OwnerGeneration                 int64
	TerminalHTTPStatus              *int
	TerminalBody                    json.RawMessage
	PrivacyRewriteVersion           int
	PrivacySubjectRef               string
	PrivacyOperationID              string
	PrivacyEventID                  string
	CreatedAt                       time.Time
	UpdatedAt                       time.Time
	CompletedAt                     *time.Time
}

func validSecretRotationScheduleTenantRegistration(eventID string, eventSequence uint64) bool {
	return eventSequence > 0 && eventID != "" && len(eventID) <= 512 &&
		utf8.ValidString(eventID) && strings.TrimSpace(eventID) == eventID &&
		strings.IndexFunc(eventID, unicode.IsControl) < 0
}

func validateSecretRotationScheduleRegistrationTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	identityVersion int,
	eventID string,
	eventSequence uint64,
) error {
	if identityVersion != SecretRotationScheduleIdentityVersion ||
		!validSecretRotationScheduleTenantRegistration(eventID, eventSequence) {
		return fmt.Errorf("%w: scheduler authority has no canonical tenant registration",
			ErrSecretRotationScheduleTickConflict)
	}
	if err := lockTenantLifecycleSharedTx(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("%w: lock live tenant registration: %v",
			ErrSecretRotationScheduleTickConflict, err)
	}
	snapshot, err := lockLiveTenantRegistrationSnapshotAfterLifecycleTx(ctx, tx, tenantID)
	if err != nil {
		return fmt.Errorf("%w: live tenant registration is unavailable: %v",
			ErrSecretRotationScheduleTickConflict, err)
	}
	if snapshot.EventSeq != eventSequence {
		return fmt.Errorf("%w: scheduler authority belongs to tenant registration sequence %d, current is %d",
			ErrSecretRotationScheduleTickConflict, eventSequence, snapshot.EventSeq)
	}
	return nil
}

// SecretRotationScheduleCommandLeaseRelease identifies a child command lease
// that aggregate progress must release after locking cursor -> tick -> command.
type SecretRotationScheduleCommandLeaseRelease struct {
	ScheduleID string
	RunID      string
	LeaseToken string
}

// SecretRotationScheduleTickRowOutcome is the one new immutable result a
// scheduler row may add to its aggregate receipt. Exactly one of Run or
// Deferred may be present. An empty outcome means another reconciler already
// terminalized the frozen due edge, so the row consumes a scan without adding a
// duplicate child receipt.
type SecretRotationScheduleTickRowOutcome struct {
	Run      json.RawMessage
	Deferred json.RawMessage
}

type secretRotationScheduleTickReceipt struct {
	Ran              int               `json:"ran"`
	Scanned          int               `json:"scanned"`
	Runs             []json.RawMessage `json:"runs"`
	Deferred         []json.RawMessage `json:"deferred"`
	RunLimitReached  bool              `json:"run_limit_reached"`
	ScanLimitReached bool              `json:"scan_limit_reached"`
	Complete         bool              `json:"complete"`
	Partial          bool              `json:"partial"`
	FailedScheduleID string            `json:"failed_schedule_id,omitempty"`
	SystemError      string            `json:"system_error,omitempty"`
}

func initialSecretRotationScheduleTickReceipt() ([]byte, error) {
	return json.Marshal(secretRotationScheduleTickReceipt{
		Runs:     []json.RawMessage{},
		Deferred: []json.RawMessage{},
	})
}

func decodeSecretRotationScheduleTickReceipt(raw []byte) (secretRotationScheduleTickReceipt, error) {
	var receipt secretRotationScheduleTickReceipt
	// The privacy rewriter and the runtime receiver intentionally share one
	// closed JSON schema. Passing an empty subject performs validation only: it
	// rejects duplicate keys at every nesting level, rejects unknown fields, and
	// proves all run/deferral/rotation field types without changing any bytes.
	if len(raw) == 0 {
		return receipt, fmt.Errorf("%w: scheduler receipt is not a complete JSON object", ErrSecretRotationScheduleTickConflict)
	}
	if _, changed, err := rewriteSecretRotationSchedulePrivacyReceipt(raw, "", "", false, ""); err != nil || changed {
		if err != nil {
			return receipt, err
		}
		return receipt, fmt.Errorf("%w: scheduler receipt validation unexpectedly rewrote bytes", ErrSecretRotationScheduleTickConflict)
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Runs == nil || receipt.Deferred == nil {
		return receipt, fmt.Errorf("%w: scheduler receipt is not a complete JSON object", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationScheduleTickErrorVocabulary(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateSecretRotationScheduleTickErrorVocabulary(
	receipt secretRotationScheduleTickReceipt,
) error {
	if !isCanonicalSecretRotationScheduleTickSystemError(receipt.SystemError) {
		return fmt.Errorf("%w: scheduler receipt system_error is outside the closed vocabulary",
			ErrSecretRotationScheduleTickConflict)
	}
	for index, raw := range receipt.Runs {
		var run struct {
			Status   string `json:"status"`
			Error    string `json:"error"`
			Rotation struct {
				Error         string `json:"error"`
				RollbackError string `json:"rollback_error"`
			} `json:"rotation"`
		}
		if err := json.Unmarshal(raw, &run); err != nil {
			return fmt.Errorf("%w: scheduler run receipt %d cannot be decoded",
				ErrSecretRotationScheduleTickConflict, index)
		}
		if !IsCanonicalSecretRotationScheduleError(run.Status, run.Error) ||
			!IsCanonicalSecretRotationScheduleError(run.Status, run.Rotation.Error) {
			return fmt.Errorf("%w: scheduler run receipt %d error is outside the closed vocabulary",
				ErrSecretRotationScheduleTickConflict, index)
		}
		if run.Error != run.Rotation.Error {
			return fmt.Errorf("%w: scheduler run receipt %d disagrees with its rotation error",
				ErrSecretRotationScheduleTickConflict, index)
		}
		if run.Rotation.RollbackError != "" &&
			run.Rotation.RollbackError != SecretRotationScheduleRollbackError {
			return fmt.Errorf("%w: scheduler run receipt %d rollback_error is outside the closed vocabulary",
				ErrSecretRotationScheduleTickConflict, index)
		}
	}
	for index, raw := range receipt.Deferred {
		var deferred struct {
			Reason string `json:"reason"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(raw, &deferred); err != nil {
			return fmt.Errorf("%w: scheduler deferral receipt %d cannot be decoded",
				ErrSecretRotationScheduleTickConflict, index)
		}
		if deferred.Error != "" &&
			deferred.Error != SecretRotationScheduleDeferredError(deferred.Reason) {
			return fmt.Errorf("%w: scheduler deferral receipt %d error is outside the closed vocabulary",
				ErrSecretRotationScheduleTickConflict, index)
		}
	}
	return nil
}

func validateSecretRotationScheduleTickReceipt(raw []byte, ran, scanned int, terminalStatus int) error {
	receipt, err := decodeSecretRotationScheduleTickReceipt(raw)
	if err != nil {
		return err
	}
	if receipt.Ran != ran || receipt.Scanned != scanned || len(receipt.Runs) != ran || scanned < ran+len(receipt.Deferred) {
		return fmt.Errorf("%w: scheduler receipt disagrees with retained logical budgets", ErrSecretRotationScheduleTickConflict)
	}
	switch terminalStatus {
	case 0:
		if receipt.Complete || receipt.Partial || receipt.RunLimitReached || receipt.ScanLimitReached || receipt.SystemError != "" || receipt.FailedScheduleID != "" {
			return fmt.Errorf("%w: running receipt contains terminal evidence", ErrSecretRotationScheduleTickConflict)
		}
	case 200:
		if receipt.SystemError != "" || receipt.FailedScheduleID != "" || receipt.Partial ||
			receipt.Complete == (receipt.RunLimitReached || receipt.ScanLimitReached) {
			return fmt.Errorf("%w: successful terminal receipt has inconsistent completion evidence", ErrSecretRotationScheduleTickConflict)
		}
	case 503:
		if receipt.Complete || receipt.SystemError == "" || receipt.RunLimitReached || receipt.ScanLimitReached ||
			receipt.Partial != (ran > 0 || len(receipt.Deferred) > 0) {
			return fmt.Errorf("%w: failed terminal receipt has inconsistent partial evidence", ErrSecretRotationScheduleTickConflict)
		}
	default:
		return fmt.Errorf("%w: unsupported terminal HTTP status %d", ErrSecretRotationScheduleTickConflict, terminalStatus)
	}
	if receipt.RunLimitReached && ran != 50 {
		return fmt.Errorf("%w: run limit flag without a consumed 50-run budget", ErrSecretRotationScheduleTickConflict)
	}
	if receipt.ScanLimitReached && scanned != 500 {
		return fmt.Errorf("%w: scan limit flag without a consumed 500-row budget", ErrSecretRotationScheduleTickConflict)
	}
	return nil
}

func validateSecretRotationScheduleTickTerminalReceiptSemantics(
	tick SecretRotationScheduleTick,
	receipt secretRotationScheduleTickReceipt,
	httpStatus int,
) error {
	if httpStatus != 200 {
		return nil
	}
	wantRunLimit := tick.Ran == 50
	wantScanLimit := tick.Scanned == 500
	wantComplete := tick.Scanned == tick.SnapshotCount && !wantRunLimit && !wantScanLimit
	if receipt.RunLimitReached != wantRunLimit || receipt.ScanLimitReached != wantScanLimit ||
		receipt.Complete != wantComplete {
		return fmt.Errorf("%w: successful terminal receipt disagrees with the frozen aggregate boundary",
			ErrSecretRotationScheduleTickConflict)
	}
	return nil
}

func secretRotationScheduleTickJSONEqual(left, right json.RawMessage) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func secretRotationScheduleTickJSONPrefixEqual(left, right []json.RawMessage) bool {
	if len(left) > len(right) {
		return false
	}
	for index := range left {
		if !secretRotationScheduleTickJSONEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}

func validateSecretRotationScheduleTickProgress(
	retained SecretRotationScheduleTick,
	raw []byte,
	ran, scanned int,
) error {
	if retained.CurrentSchedule == nil || retained.Phase != "row_started" ||
		scanned != retained.Scanned+1 || (ran != retained.Ran && ran != retained.Ran+1) {
		return fmt.Errorf("%w: row completion disagrees with retained phase or budget", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationScheduleTickReceipt(retained.Receipt, retained.Ran, retained.Scanned, 0); err != nil {
		return err
	}
	previous, err := decodeSecretRotationScheduleTickReceipt(retained.Receipt)
	if err != nil {
		return err
	}
	next, err := decodeSecretRotationScheduleTickReceipt(raw)
	if err != nil {
		return err
	}
	if !secretRotationScheduleTickJSONPrefixEqual(previous.Runs, next.Runs) ||
		!secretRotationScheduleTickJSONPrefixEqual(previous.Deferred, next.Deferred) {
		return fmt.Errorf("%w: row completion rewrites ordered receipt history", ErrSecretRotationScheduleTickConflict)
	}

	type scheduleEvidence struct {
		ScheduleID string    `json:"schedule_id"`
		RunID      string    `json:"run_id"`
		DueAt      time.Time `json:"due_at"`
		Status     string    `json:"status"`
	}
	switch {
	case ran == retained.Ran+1:
		if len(next.Runs) != len(previous.Runs)+1 || len(next.Deferred) != len(previous.Deferred) {
			return fmt.Errorf("%w: successful row must append exactly one run", ErrSecretRotationScheduleTickConflict)
		}
		var evidence scheduleEvidence
		if json.Unmarshal(next.Runs[len(next.Runs)-1], &evidence) != nil ||
			evidence.ScheduleID != retained.CurrentSchedule.ID ||
			!evidence.DueAt.Equal(retained.CurrentSchedule.NextRunAt) ||
			!secretRotationScheduleTerminalStatus(evidence.Status) ||
			evidence.RunID != rotationcommand.RunID(
				retained.TenantID, retained.TenantRegistrationEventSequence,
				retained.CurrentSchedule.ID, retained.CurrentSchedule.NextRunAt) {
			return fmt.Errorf("%w: appended run is not the exact lifecycle-bound terminal due edge",
				ErrSecretRotationScheduleTickConflict)
		}
	case len(next.Deferred) == len(previous.Deferred)+1:
		if len(next.Runs) != len(previous.Runs) {
			return fmt.Errorf("%w: deferred row rewrites successful runs", ErrSecretRotationScheduleTickConflict)
		}
		var evidence scheduleEvidence
		if json.Unmarshal(next.Deferred[len(next.Deferred)-1], &evidence) != nil ||
			evidence.ScheduleID != retained.CurrentSchedule.ID || !evidence.DueAt.Equal(retained.CurrentSchedule.NextRunAt) {
			return fmt.Errorf("%w: appended deferral names another due edge", ErrSecretRotationScheduleTickConflict)
		}
	case len(next.Runs) == len(previous.Runs) && len(next.Deferred) == len(previous.Deferred):
		// A stale due edge was already terminalized by another reconciler. It
		// consumes one scan budget but appends no duplicate child receipt.
	default:
		return fmt.Errorf("%w: row completion appends more than one outcome", ErrSecretRotationScheduleTickConflict)
	}
	return nil
}

func validateSecretRotationScheduleTickContinuation(
	retained, presented SecretRotationScheduleTick,
) error {
	if retained.TenantID != presented.TenantID ||
		retained.IdempotencyKey != presented.IdempotencyKey ||
		retained.RequestBinding != presented.RequestBinding ||
		retained.Phase != presented.Phase ||
		retained.OwnerToken != presented.OwnerToken ||
		retained.OwnerGeneration != presented.OwnerGeneration ||
		retained.Ran != presented.Ran || retained.Scanned != presented.Scanned ||
		retained.SnapshotCount != presented.SnapshotCount ||
		retained.AfterScheduleID != presented.AfterScheduleID ||
		!bytes.Equal(retained.Receipt, presented.Receipt) {
		return fmt.Errorf("%w: scheduler caller no longer presents the last store-returned progress",
			ErrSecretRotationScheduleTickConflict)
	}
	return nil
}

func validateSecretRotationScheduleTickRowOutcome(
	retained SecretRotationScheduleTick,
	outcome SecretRotationScheduleTickRowOutcome,
) error {
	if retained.CurrentSchedule == nil || retained.Phase != "row_started" {
		return fmt.Errorf("%w: incremental outcome has no retained row snapshot",
			ErrSecretRotationScheduleTickConflict)
	}
	hasRun := len(outcome.Run) > 0
	hasDeferred := len(outcome.Deferred) > 0
	if hasRun && hasDeferred {
		return fmt.Errorf("%w: one scheduler row cannot append both a run and a deferral",
			ErrSecretRotationScheduleTickConflict)
	}
	type scheduleEvidence struct {
		ScheduleID string    `json:"schedule_id"`
		RunID      string    `json:"run_id"`
		DueAt      time.Time `json:"due_at"`
		Status     string    `json:"status"`
	}
	switch {
	case hasRun:
		if _, changed, err := rewriteSecretRotationSchedulePrivacyRun(outcome.Run, "", ""); err != nil {
			return err
		} else if changed {
			return fmt.Errorf("%w: incremental run required an unexpected privacy rewrite",
				ErrSecretRotationScheduleTickConflict)
		}
		if err := validateSecretRotationScheduleTickErrorVocabulary(secretRotationScheduleTickReceipt{
			Runs: []json.RawMessage{outcome.Run}, Deferred: []json.RawMessage{},
		}); err != nil {
			return err
		}
		var evidence scheduleEvidence
		if json.Unmarshal(outcome.Run, &evidence) != nil ||
			evidence.ScheduleID != retained.CurrentSchedule.ID ||
			!evidence.DueAt.Equal(retained.CurrentSchedule.NextRunAt) ||
			!secretRotationScheduleTerminalStatus(evidence.Status) ||
			evidence.RunID != rotationcommand.RunID(
				retained.TenantID, retained.TenantRegistrationEventSequence,
				retained.CurrentSchedule.ID, retained.CurrentSchedule.NextRunAt) {
			return fmt.Errorf("%w: incremental run is not the exact lifecycle-bound terminal due edge",
				ErrSecretRotationScheduleTickConflict)
		}
	case hasDeferred:
		if _, changed, err := rewriteSecretRotationSchedulePrivacyDeferred(outcome.Deferred, "", ""); err != nil {
			return err
		} else if changed {
			return fmt.Errorf("%w: incremental deferral required an unexpected privacy rewrite",
				ErrSecretRotationScheduleTickConflict)
		}
		if err := validateSecretRotationScheduleTickErrorVocabulary(secretRotationScheduleTickReceipt{
			Runs: []json.RawMessage{}, Deferred: []json.RawMessage{outcome.Deferred},
		}); err != nil {
			return err
		}
		var evidence scheduleEvidence
		if json.Unmarshal(outcome.Deferred, &evidence) != nil ||
			evidence.ScheduleID != retained.CurrentSchedule.ID ||
			!evidence.DueAt.Equal(retained.CurrentSchedule.NextRunAt) {
			return fmt.Errorf("%w: incremental deferral names another due edge",
				ErrSecretRotationScheduleTickConflict)
		}
	}
	return nil
}

func appendSecretRotationScheduleTickRowOutcome(
	retained SecretRotationScheduleTick,
	outcome SecretRotationScheduleTickRowOutcome,
) ([]byte, int, int, error) {
	if err := validateSecretRotationScheduleTickRowOutcome(retained, outcome); err != nil {
		return nil, 0, 0, err
	}
	var receipt secretRotationScheduleTickReceipt
	if json.Unmarshal(retained.Receipt, &receipt) != nil || receipt.Runs == nil || receipt.Deferred == nil ||
		receipt.Ran != retained.Ran || receipt.Scanned != retained.Scanned ||
		len(receipt.Runs) != retained.Ran || retained.Scanned < retained.Ran+len(receipt.Deferred) ||
		receipt.Complete || receipt.Partial || receipt.RunLimitReached || receipt.ScanLimitReached ||
		receipt.FailedScheduleID != "" || receipt.SystemError != "" {
		return nil, 0, 0, fmt.Errorf("%w: retained incremental receipt state is inconsistent",
			ErrSecretRotationScheduleTickConflict)
	}
	if len(outcome.Run) > 0 {
		receipt.Runs = append(receipt.Runs, append(json.RawMessage(nil), outcome.Run...))
		receipt.Ran++
	} else if len(outcome.Deferred) > 0 {
		receipt.Deferred = append(receipt.Deferred, append(json.RawMessage(nil), outcome.Deferred...))
	}
	receipt.Scanned++
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, 0, 0, err
	}
	return encoded, receipt.Ran, receipt.Scanned, nil
}

func validateSecretRotationScheduleTickTerminal(retained SecretRotationScheduleTick, body []byte, httpStatus int) error {
	if err := validateSecretRotationScheduleTickReceipt(retained.Receipt, retained.Ran, retained.Scanned, 0); err != nil {
		return err
	}
	previous, err := decodeSecretRotationScheduleTickReceipt(retained.Receipt)
	if err != nil {
		return err
	}
	terminal, err := decodeSecretRotationScheduleTickReceipt(body)
	if err != nil {
		return err
	}
	if len(previous.Runs) != len(terminal.Runs) || len(previous.Deferred) != len(terminal.Deferred) ||
		!secretRotationScheduleTickJSONPrefixEqual(previous.Runs, terminal.Runs) ||
		!secretRotationScheduleTickJSONPrefixEqual(previous.Deferred, terminal.Deferred) {
		return fmt.Errorf("%w: terminal body rewrites ordered receipt history", ErrSecretRotationScheduleTickConflict)
	}
	if httpStatus == 503 && retained.Phase == "row_started" && retained.CurrentSchedule != nil &&
		terminal.FailedScheduleID != retained.CurrentSchedule.ID {
		return fmt.Errorf("%w: failed terminal body does not identify its started row", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationScheduleTickTerminalReceiptSemantics(retained, terminal, httpStatus); err != nil {
		return err
	}
	return nil
}

// validateSecretRotationScheduleTickRetainedTerminal re-validates terminal
// authority loaded from PostgreSQL. This is deliberately stricter than merely
// checking that terminal bytes exist: restored or pre-fix rows must still obey
// the current closed receipt schema, and the jsonb receipt must describe the
// same terminal result as the exact raw HTTP body.
func validateSecretRotationScheduleTickRetainedTerminal(tick SecretRotationScheduleTick) error {
	if tick.Phase != "terminal" || tick.TerminalHTTPStatus == nil || len(tick.TerminalBody) == 0 {
		return fmt.Errorf("%w: retained scheduler terminal is incomplete", ErrSecretRotationScheduleTickConflict)
	}
	status := *tick.TerminalHTTPStatus
	if err := validateSecretRotationScheduleTickReceipt(tick.Receipt, tick.Ran, tick.Scanned, status); err != nil {
		return err
	}
	if err := validateSecretRotationScheduleTickReceipt(tick.TerminalBody, tick.Ran, tick.Scanned, status); err != nil {
		return err
	}
	receipt, err := decodeSecretRotationScheduleTickReceipt(tick.Receipt)
	if err != nil {
		return err
	}
	if err := validateSecretRotationScheduleTickTerminalReceiptSemantics(tick, receipt, status); err != nil {
		return err
	}
	if !secretRotationScheduleTickJSONEqual(tick.Receipt, tick.TerminalBody) {
		return fmt.Errorf("%w: retained scheduler receipt differs from its terminal HTTP body", ErrSecretRotationScheduleTickConflict)
	}
	return nil
}

func indeterminateSecretRotationScheduleTickReceipt(tick SecretRotationScheduleTick) ([]byte, error) {
	if err := validateSecretRotationScheduleTickReceipt(tick.Receipt, tick.Ran, tick.Scanned, 0); err != nil {
		return nil, err
	}
	receipt, err := decodeSecretRotationScheduleTickReceipt(tick.Receipt)
	if err != nil {
		return nil, err
	}
	receipt.Complete = false
	receipt.Partial = receipt.Ran > 0 || len(receipt.Deferred) > 0
	receipt.RunLimitReached = false
	receipt.ScanLimitReached = false
	receipt.SystemError = SecretRotationScheduleTickSupersededError
	if tick.CurrentSchedule != nil {
		receipt.FailedScheduleID = tick.CurrentSchedule.ID
	}
	return json.Marshal(receipt)
}

const secretRotationScheduleTickSelect = `SELECT tenant_id::text, identity_version,
       tenant_registration_event_id, tenant_registration_event_sequence,
       idempotency_key, request_binding,
       due_through, start_schedule_id::text, after_schedule_id::text,
       wrapped, phase, current_schedule_id::text, current_due_at,
       current_provider, current_secret_key, current_old_ref,
	       current_interval_seconds, current_config_event_sequence,
	       current_command_lease_token,
	       ran, scanned, snapshot_count, receipt, owner_token, owner_generation,
	       terminal_http_status, terminal_body,
	       privacy_rewrite_version, privacy_subject_ref, privacy_operation_id, privacy_event_id,
	       created_at, updated_at, completed_at
	  FROM secret_rotation_schedule_ticks
	 WHERE tenant_id = $1`

func scanSecretRotationScheduleTick(row rowScanner, tick *SecretRotationScheduleTick) error {
	var (
		currentID, provider, key, oldRef, commandLeaseToken *string
		currentDueAt                                        *time.Time
		currentInterval                                     *int
		currentConfigEventSequence                          *uint64
		terminalBody                                        []byte
	)
	if err := row.Scan(
		&tick.TenantID, &tick.IdentityVersion,
		&tick.TenantRegistrationEventID, &tick.TenantRegistrationEventSequence,
		&tick.IdempotencyKey, &tick.RequestBinding,
		&tick.DueThrough, &tick.StartScheduleID, &tick.AfterScheduleID,
		&tick.Wrapped, &tick.Phase, &currentID, &currentDueAt,
		&provider, &key, &oldRef, &currentInterval, &currentConfigEventSequence, &commandLeaseToken,
		&tick.Ran, &tick.Scanned, &tick.SnapshotCount, &tick.Receipt, &tick.OwnerToken, &tick.OwnerGeneration,
		&tick.TerminalHTTPStatus, &terminalBody,
		&tick.PrivacyRewriteVersion, &tick.PrivacySubjectRef, &tick.PrivacyOperationID, &tick.PrivacyEventID,
		&tick.CreatedAt, &tick.UpdatedAt, &tick.CompletedAt,
	); err != nil {
		return err
	}
	if currentID != nil && currentDueAt != nil && provider != nil && key != nil && oldRef != nil && currentInterval != nil && currentConfigEventSequence != nil {
		tick.CurrentSchedule = &SecretRotationSchedule{
			ID: *currentID, TenantID: tick.TenantID,
			IdentityVersion:                 tick.IdentityVersion,
			TenantRegistrationEventID:       tick.TenantRegistrationEventID,
			TenantRegistrationEventSequence: tick.TenantRegistrationEventSequence,
			Provider:                        *provider,
			Key:                             *key, OldRef: *oldRef, IntervalSeconds: *currentInterval,
			Enabled: true, NextRunAt: *currentDueAt, ConfigEventSequence: *currentConfigEventSequence,
		}
	}
	if commandLeaseToken != nil {
		tick.CurrentCommandLeaseToken = *commandLeaseToken
	}
	if terminalBody != nil {
		tick.TerminalBody = append(json.RawMessage(nil), terminalBody...)
	}
	return nil
}

func lockSecretRotationScheduleCursor(ctx context.Context, tx pgx.Tx, tenantID string) (SecretRotationScheduleScanCursor, bool, error) {
	var cursor SecretRotationScheduleScanCursor
	var active bool
	err := tx.QueryRow(ctx,
		`SELECT tenant_id::text, after_schedule_id::text,
		        active_tick_key, active_tick_binding, lease_token,
		        lease_until, lease_generation, generation, updated_at,
		        lease_until IS NOT NULL AND lease_until > clock_timestamp()
		   FROM secret_rotation_schedule_scan_cursors
		  WHERE tenant_id = $1
		  FOR UPDATE`, tenantID).
		Scan(&cursor.TenantID, &cursor.AfterScheduleID,
			&cursor.ActiveTickKey, &cursor.ActiveTickBinding, &cursor.LeaseToken,
			&cursor.LeaseUntil, &cursor.LeaseGeneration, &cursor.Generation, &cursor.UpdatedAt, &active)
	return cursor, active, err
}

func validateSecretRotationScheduleTickOwner(cursor SecretRotationScheduleScanCursor, active bool, tick SecretRotationScheduleTick, token string, generation int64) error {
	if !active || token == "" || generation <= 0 ||
		cursor.ActiveTickKey != tick.IdempotencyKey || cursor.ActiveTickBinding != tick.RequestBinding ||
		cursor.LeaseToken != token || cursor.LeaseGeneration != generation ||
		tick.Phase == "terminal" || tick.OwnerToken != token || tick.OwnerGeneration != generation {
		return fmt.Errorf("%w: stale or expired aggregate tick owner", ErrSecretRotationScheduleTickConflict)
	}
	return nil
}

// ClaimSecretRotationScheduleTick is the standalone store entry point used by
// recovery tests. Production calls PrepareSecretRotationScheduleTickTx from the
// prepared durable idempotency transaction so the outer bind and work snapshot
// cannot be separated by a process crash.
func (s *Store) ClaimSecretRotationScheduleTick(
	ctx context.Context,
	tenantID, idempotencyKey, requestBinding,
	tenantRegistrationEventID string,
	tenantRegistrationEventSequence uint64,
	ownerToken, currentCommandLeaseToken string,
	leaseDuration time.Duration,
) (SecretRotationScheduleTick, SecretRotationScheduleTickClaimState, error) {
	var prepared SecretRotationScheduleTickPreparation
	if tenantID == "" || idempotencyKey == "" || requestBinding == "" ||
		!validSecretRotationScheduleTenantRegistration(tenantRegistrationEventID, tenantRegistrationEventSequence) ||
		ownerToken == "" || currentCommandLeaseToken == "" || leaseDuration <= 0 {
		return prepared.Tick, "", fmt.Errorf("%w: tick identity, owner tokens, and lease duration are required", ErrSecretRotationScheduleTickConflict)
	}
	err := s.WithPrivacyTenantProjectionRepeatableRead(
		ctx, tenantID, "secret rotation scheduler tick prepare", func(tx pgx.Tx) error {
			var err error
			prepared, err = s.PrepareSecretRotationScheduleTickTx(
				ctx, tx, tenantID, idempotencyKey, requestBinding,
				tenantRegistrationEventID, tenantRegistrationEventSequence, ownerToken,
				currentCommandLeaseToken, leaseDuration)
			return err
		})
	return prepared.Tick, prepared.State, err
}

// PrepareSecretRotationScheduleTickTx atomically binds the outer key, freezes
// the PostgreSQL cutoff and exact ordered work rows, and claims the tenant cursor.
// tx MUST be a repeatable-read owner transaction entered only after the shared
// privacy-operation barrier. Lock order is privacy operation -> backup fence ->
// cursor -> outer idempotency row -> tick -> snapshot rows.
func (s *Store) PrepareSecretRotationScheduleTickTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, idempotencyKey, requestBinding,
	tenantRegistrationEventID string,
	tenantRegistrationEventSequence uint64,
	ownerToken, currentCommandLeaseToken string,
	leaseDuration time.Duration,
) (SecretRotationScheduleTickPreparation, error) {
	prepared := SecretRotationScheduleTickPreparation{State: SecretRotationScheduleTickAcquired}
	if tx == nil || tenantID == "" || idempotencyKey == "" || requestBinding == "" || ownerToken == "" ||
		!validSecretRotationScheduleTenantRegistration(tenantRegistrationEventID, tenantRegistrationEventSequence) ||
		currentCommandLeaseToken == "" || leaseDuration <= 0 {
		return prepared, fmt.Errorf("%w: prepared tick transaction and exact identity are required", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationScheduleRegistrationTx(ctx, tx, tenantID,
		SecretRotationScheduleIdentityVersion, tenantRegistrationEventID,
		tenantRegistrationEventSequence); err != nil {
		return prepared, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO secret_rotation_schedule_scan_cursors (tenant_id)
		 VALUES ($1) ON CONFLICT DO NOTHING`, tenantID); err != nil {
		return prepared, err
	}
	cursor, active, err := lockSecretRotationScheduleCursor(ctx, tx, tenantID)
	if err != nil {
		return prepared, err
	}
	var (
		outerStatus, outerBinding, resultCodec string
		dueThrough                             time.Time
		protectedResult                        []byte
	)
	outerExists := true
	err = tx.QueryRow(ctx,
		`SELECT status, request_binding, created_at, result_codec, result
		   FROM idempotency_keys
		  WHERE tenant_id = $1 AND key = $2
		  FOR UPDATE`, tenantID, idempotencyKey).
		Scan(&outerStatus, &outerBinding, &dueThrough, &resultCodec, &protectedResult)
	if errors.Is(err, pgx.ErrNoRows) {
		outerExists = false
	} else if err != nil {
		return prepared, err
	} else if outerBinding != requestBinding {
		return prepared, ErrIdempotencyConflict
	} else if outerStatus != "bound" && outerStatus != "completed" {
		return prepared, fmt.Errorf("%w: outer idempotency status %q has no scheduler receiver contract", ErrSecretRotationScheduleTickConflict, outerStatus)
	}

	var tick SecretRotationScheduleTick
	tickExists := true
	err = scanSecretRotationScheduleTick(tx.QueryRow(ctx,
		secretRotationScheduleTickSelect+`
		 AND idempotency_key = $2
		 FOR UPDATE`, tenantID, idempotencyKey), &tick)
	if errors.Is(err, pgx.ErrNoRows) {
		tickExists = false
	} else if err != nil {
		return prepared, err
	} else if tick.RequestBinding != requestBinding || !tick.DueThrough.Equal(dueThrough) ||
		tick.IdentityVersion != SecretRotationScheduleIdentityVersion ||
		tick.TenantRegistrationEventID != tenantRegistrationEventID ||
		tick.TenantRegistrationEventSequence != tenantRegistrationEventSequence {
		return prepared, fmt.Errorf("%w: retained tick differs from the outer idempotency claim", ErrSecretRotationScheduleTickConflict)
	} else if err := validateSecretRotationScheduleTickSnapshotTx(ctx, tx, tick); err != nil {
		return prepared, err
	} else if tick.Phase != "terminal" && tick.Phase != "privacy_erased" {
		if err := validateSecretRotationScheduleTickReceipt(tick.Receipt, tick.Ran, tick.Scanned, 0); err != nil {
			return prepared, err
		}
	}
	if cursor.ActiveTickKey != "" && (!tickExists || cursor.ActiveTickKey != idempotencyKey) {
		var cursorTick SecretRotationScheduleTick
		cursorTickErr := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
			secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2
			 FOR UPDATE`, tenantID, cursor.ActiveTickKey), &cursorTick)
		foreignLifecycle := errors.Is(cursorTickErr, pgx.ErrNoRows) ||
			(cursorTickErr == nil && (cursorTick.IdentityVersion != SecretRotationScheduleIdentityVersion ||
				cursorTick.TenantRegistrationEventID != tenantRegistrationEventID ||
				cursorTick.TenantRegistrationEventSequence != tenantRegistrationEventSequence))
		if cursorTickErr != nil && !errors.Is(cursorTickErr, pgx.ErrNoRows) {
			return prepared, cursorTickErr
		}
		if foreignLifecycle {
			tag, clearErr := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_scan_cursors
				    SET active_tick_key = '', active_tick_binding = '',
				        lease_token = '', lease_until = NULL,
				        updated_at = clock_timestamp()
				  WHERE tenant_id = $1 AND active_tick_key = $2
				    AND active_tick_binding = $3 AND lease_generation = $4`,
				tenantID, cursor.ActiveTickKey, cursor.ActiveTickBinding, cursor.LeaseGeneration)
			if clearErr != nil {
				return prepared, clearErr
			}
			if tag.RowsAffected() != 1 {
				return prepared, fmt.Errorf("%w: foreign-lifecycle cursor reset changed %d rows",
					ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			cursor.ActiveTickKey = ""
			cursor.ActiveTickBinding = ""
			cursor.LeaseToken = ""
			cursor.LeaseUntil = nil
			active = false
		}
	}

	if tickExists && tick.Phase == "privacy_erased" {
		return prepared, ErrSecretRotationScheduleTickPrivacyErased
	}
	if outerExists && outerStatus == "completed" {
		if !tickExists || tick.Phase != "terminal" || tick.TerminalHTTPStatus == nil || len(tick.TerminalBody) == 0 || len(protectedResult) == 0 {
			return prepared, fmt.Errorf("%w: completed outer key lacks its exact terminal scheduler receiver", ErrSecretRotationScheduleTickConflict)
		}
		if err := validateSecretRotationScheduleTickRetainedTerminal(tick); err != nil {
			return prepared, err
		}
		prepared.Tick = tick
		prepared.State = SecretRotationScheduleTickTerminal
		prepared.OuterCompleted = true
		prepared.ResultCodec = resultCodec
		prepared.ProtectedResult = append([]byte(nil), protectedResult...)
		return prepared, nil
	}
	if outerExists && !tickExists {
		return prepared, fmt.Errorf("%w: bound outer key has no atomically prepared tick snapshot", ErrSecretRotationScheduleTickConflict)
	}
	if tickExists && tick.Phase == "terminal" {
		if err := validateSecretRotationScheduleTickRetainedTerminal(tick); err != nil {
			return prepared, err
		}
		prepared.Tick = tick
		prepared.State = SecretRotationScheduleTickTerminal
		return prepared, nil
	}

	if active {
		if cursor.ActiveTickKey == idempotencyKey && cursor.ActiveTickBinding == requestBinding {
			prepared.State = SecretRotationScheduleTickSameKeyBusy
		} else {
			prepared.State = SecretRotationScheduleTickDifferentBusy
		}
		prepared.Tick = tick
		return prepared, nil
	}

	var carried *SecretRotationSchedule
	if cursor.ActiveTickKey != "" {
		if cursor.ActiveTickKey == idempotencyKey && cursor.ActiveTickBinding == requestBinding {
			if !tickExists {
				return prepared, fmt.Errorf("%w: cursor names a missing active tick", ErrSecretRotationScheduleTickConflict)
			}
		} else {
			if tickExists {
				return prepared, fmt.Errorf("%w: requested nonterminal tick is outside active cursor authority", ErrSecretRotationScheduleTickConflict)
			}
			var superseded SecretRotationScheduleTick
			if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
				 AND idempotency_key = $2
				 FOR UPDATE`, tenantID, cursor.ActiveTickKey), &superseded); err != nil {
				return prepared, fmt.Errorf("%w: load expired active tick: %v", ErrSecretRotationScheduleTickConflict, err)
			}
			if err := validateSecretRotationScheduleTickSnapshotTx(ctx, tx, superseded); err != nil {
				return prepared, err
			}
			if superseded.RequestBinding != cursor.ActiveTickBinding || superseded.Phase == "terminal" ||
				superseded.OwnerToken != cursor.LeaseToken || superseded.OwnerGeneration != cursor.LeaseGeneration ||
				cursor.LeaseToken == "" || cursor.LeaseUntil == nil {
				return prepared, fmt.Errorf("%w: expired cursor and tick disagree", ErrSecretRotationScheduleTickConflict)
			}
			if superseded.Phase == "row_started" && superseded.CurrentSchedule != nil {
				copySchedule := *superseded.CurrentSchedule
				carried = &copySchedule
			}
			body, err := indeterminateSecretRotationScheduleTickReceipt(superseded)
			if err != nil {
				return prepared, err
			}
			if err := validateSecretRotationScheduleTickReceipt(body, superseded.Ran, superseded.Scanned, 503); err != nil {
				return prepared, err
			}
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_ticks
				    SET phase = 'terminal', receipt = $4::jsonb,
				        current_schedule_id = NULL, current_due_at = NULL,
				        current_provider = NULL, current_secret_key = NULL,
				        current_old_ref = NULL, current_interval_seconds = NULL,
				        current_config_event_sequence = NULL,
				        current_command_lease_token = NULL,
				        owner_token = '', terminal_http_status = 503,
				        terminal_body = $5, updated_at = clock_timestamp(),
				        completed_at = clock_timestamp()
				  WHERE tenant_id = $1 AND idempotency_key = $2
				    AND request_binding = $3 AND phase <> 'terminal'
				    AND owner_token = $6 AND owner_generation = $7
				    AND EXISTS (
				        SELECT 1 FROM secret_rotation_schedule_scan_cursors AS cursor
				         WHERE cursor.tenant_id = $1
				           AND cursor.active_tick_key = $2
				           AND cursor.active_tick_binding = $3
				           AND cursor.lease_token = $6
				           AND cursor.lease_generation = $7
				           AND cursor.lease_until <= clock_timestamp()
				    )`,
				tenantID, superseded.IdempotencyKey, superseded.RequestBinding,
				body, body, superseded.OwnerToken, superseded.OwnerGeneration)
			if err != nil {
				return prepared, err
			}
			if tag.RowsAffected() != 1 {
				return prepared, fmt.Errorf("%w: expired tick terminal CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
		}
	} else if tickExists {
		return prepared, fmt.Errorf("%w: nonterminal tick has no active cursor authority", ErrSecretRotationScheduleTickConflict)
	}

	if !outerExists {
		if err := tx.QueryRow(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status, request_binding)
			 VALUES ($1, $2, 'bound', $3)
			 RETURNING created_at`, tenantID, idempotencyKey, requestBinding).Scan(&dueThrough); err != nil {
			return prepared, fmt.Errorf("store: atomically bind scheduler idempotency key: %w", err)
		}
	}

	generation := cursor.LeaseGeneration + 1
	if !tickExists {
		initial, err := initialSecretRotationScheduleTickReceipt()
		if err != nil {
			return prepared, err
		}
		startID := cursor.AfterScheduleID
		if carried != nil {
			startID = carried.ID
		}
		tag, err := tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_ticks
			        (tenant_id, identity_version, tenant_registration_event_id,
			         tenant_registration_event_sequence,
			         idempotency_key, request_binding, due_through,
			         start_schedule_id, after_schedule_id, snapshot_count, receipt,
			         owner_token, owner_generation, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::uuid, $9::uuid, 0, $10::jsonb,
			         $11, $12, clock_timestamp(), clock_timestamp())`,
			tenantID, SecretRotationScheduleIdentityVersion,
			tenantRegistrationEventID, tenantRegistrationEventSequence,
			idempotencyKey, requestBinding, dueThrough,
			startID, cursor.AfterScheduleID, initial, ownerToken, generation)
		if err != nil {
			return prepared, err
		}
		if tag.RowsAffected() != 1 {
			return prepared, fmt.Errorf("%w: new tick receiver was not inserted", ErrSecretRotationScheduleTickConflict)
		}
		snapshotCount, err := insertSecretRotationScheduleTickSnapshotTx(
			ctx, tx, tenantID, idempotencyKey,
			tenantRegistrationEventID, tenantRegistrationEventSequence,
			dueThrough, startID, carried)
		if err != nil {
			return prepared, err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_ticks
			    SET snapshot_count = $3
			  WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantID, idempotencyKey, snapshotCount); err != nil {
			return prepared, err
		}
	} else {
		if tick.Phase == "row_started" {
			tick.CurrentCommandLeaseToken = currentCommandLeaseToken
		}
		tag, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_ticks
			    SET owner_token = $4, owner_generation = $5,
			        current_command_lease_token = CASE
			            WHEN phase = 'row_started' THEN $6
			            ELSE current_command_lease_token
			        END,
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND idempotency_key = $2
			    AND request_binding = $3 AND phase <> 'terminal'
			    AND owner_token = $7 AND owner_generation = $8`,
			tenantID, idempotencyKey, requestBinding, ownerToken, generation,
			currentCommandLeaseToken, tick.OwnerToken, tick.OwnerGeneration)
		if err != nil {
			return prepared, err
		}
		if tag.RowsAffected() != 1 {
			return prepared, fmt.Errorf("%w: expired same-key owner CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
		}
	}
	tag, err := tx.Exec(ctx,
		`UPDATE secret_rotation_schedule_scan_cursors
		    SET active_tick_key = $2, active_tick_binding = $3,
		        lease_token = $4,
		        lease_until = clock_timestamp() + make_interval(secs => $5::double precision),
		        lease_generation = $6, updated_at = clock_timestamp()
		  WHERE tenant_id = $1 AND lease_generation = $7
		    AND active_tick_key = $8 AND active_tick_binding = $9
		    AND lease_token = $10
		    AND (lease_until IS NULL OR lease_until <= clock_timestamp())`,
		tenantID, idempotencyKey, requestBinding, ownerToken,
		leaseDuration.Seconds(), generation, cursor.LeaseGeneration,
		cursor.ActiveTickKey, cursor.ActiveTickBinding, cursor.LeaseToken)
	if err != nil {
		return prepared, err
	}
	if tag.RowsAffected() != 1 {
		return prepared, fmt.Errorf("%w: aggregate cursor claim CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
	}
	if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
		secretRotationScheduleTickSelect+`
		 AND idempotency_key = $2`, tenantID, idempotencyKey), &prepared.Tick); err != nil {
		return prepared, err
	}
	if err := validateSecretRotationScheduleTickSnapshotTx(ctx, tx, prepared.Tick); err != nil {
		return prepared, err
	}
	return prepared, nil
}

func insertSecretRotationScheduleTickSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, idempotencyKey string,
	tenantRegistrationEventID string,
	tenantRegistrationEventSequence uint64,
	dueThrough time.Time,
	startID string,
	carried *SecretRotationSchedule,
) (int, error) {
	offset := 0
	excludedID := ""
	if carried != nil {
		if carried.TenantID != tenantID || carried.ID == "" || carried.Provider == "" || carried.Key == "" ||
			carried.OldRef == "" || carried.IntervalSeconds <= 0 ||
			carried.IdentityVersion != SecretRotationScheduleIdentityVersion ||
			carried.TenantRegistrationEventID != tenantRegistrationEventID ||
			carried.TenantRegistrationEventSequence != tenantRegistrationEventSequence ||
			carried.NextRunAt.After(dueThrough) {
			return 0, fmt.Errorf("%w: carried row snapshot is incomplete", ErrSecretRotationScheduleTickConflict)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedule_tick_rows
			        (tenant_id, identity_version, tenant_registration_event_id,
			         tenant_registration_event_sequence,
			         idempotency_key, ordinal, schedule_id, due_at,
			         provider, secret_key, old_ref, interval_seconds, config_event_sequence)
			 VALUES ($1, $2, $3, $4, $5, 1, $6::uuid, $7, $8, $9, $10, $11, $12)`,
			tenantID, SecretRotationScheduleIdentityVersion,
			tenantRegistrationEventID, tenantRegistrationEventSequence,
			idempotencyKey, carried.ID, carried.NextRunAt, carried.Provider,
			carried.Key, carried.OldRef, carried.IntervalSeconds, carried.ConfigEventSequence); err != nil {
			return 0, err
		}
		offset = 1
		excludedID = carried.ID
	}
	tag, err := tx.Exec(ctx,
		`WITH ring AS (
		    SELECT id, next_run_at, provider, secret_key, old_ref,
		           interval_seconds, config_event_sequence,
		           CASE WHEN id > $4::uuid THEN 0 ELSE 1 END AS segment
		      FROM secret_rotation_schedules
		     WHERE tenant_id = $1 AND enabled AND next_run_at <= $3
		       AND (config_event_sequence = 0 OR config_event_sequence > $10)
		       AND ($5 = '' OR id <> NULLIF($5, '')::uuid)
		), bounded AS (
		    SELECT *, row_number() OVER (ORDER BY segment, id)::integer + $6 AS ordinal
		      FROM ring
		     ORDER BY segment, id
		     LIMIT $7
		)
		INSERT INTO secret_rotation_schedule_tick_rows
		       (tenant_id, identity_version, tenant_registration_event_id,
		        tenant_registration_event_sequence,
		        idempotency_key, ordinal, schedule_id, due_at,
		        provider, secret_key, old_ref, interval_seconds, config_event_sequence)
		SELECT $1, $8, $9, $10, $2, ordinal, id, next_run_at, provider, secret_key, old_ref,
		       interval_seconds, config_event_sequence
		  FROM bounded
		 ORDER BY ordinal`,
		tenantID, idempotencyKey, dueThrough, startID, excludedID, offset, 500-offset,
		SecretRotationScheduleIdentityVersion, tenantRegistrationEventID,
		tenantRegistrationEventSequence)
	if err != nil {
		return 0, err
	}
	return offset + int(tag.RowsAffected()), nil
}

func validateSecretRotationScheduleTickSnapshotTx(ctx context.Context, tx pgx.Tx, tick SecretRotationScheduleTick) error {
	var count, minOrdinal, maxOrdinal int
	if err := tx.QueryRow(ctx,
		`SELECT count(*)::integer, coalesce(min(ordinal), 0), coalesce(max(ordinal), 0)
		   FROM secret_rotation_schedule_tick_rows
		  WHERE tenant_id = $1 AND idempotency_key = $2`,
		tick.TenantID, tick.IdempotencyKey).Scan(&count, &minOrdinal, &maxOrdinal); err != nil {
		return err
	}
	if count != tick.SnapshotCount || (count == 0 && (minOrdinal != 0 || maxOrdinal != 0)) ||
		(count > 0 && (minOrdinal != 1 || maxOrdinal != count)) || tick.Scanned > count {
		return fmt.Errorf("%w: tick snapshot ordinals or retained budget are incomplete", ErrSecretRotationScheduleTickConflict)
	}
	if tick.Phase == "row_started" {
		if tick.CurrentSchedule == nil || tick.Scanned >= tick.SnapshotCount {
			return fmt.Errorf("%w: started row is outside the immutable snapshot", ErrSecretRotationScheduleTickConflict)
		}
		row, err := getSecretRotationScheduleTickRowTx(ctx, tx, tick.TenantID, tick.IdempotencyKey, tick.Scanned+1)
		if err != nil || !sameSecretRotationScheduleSnapshot(row, *tick.CurrentSchedule) {
			return fmt.Errorf("%w: started row differs from immutable ordinal: %v", ErrSecretRotationScheduleTickConflict, err)
		}
	}
	return nil
}

func sameSecretRotationScheduleSnapshot(left, right SecretRotationSchedule) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.Provider == right.Provider &&
		left.IdentityVersion == right.IdentityVersion &&
		left.TenantRegistrationEventID == right.TenantRegistrationEventID &&
		left.TenantRegistrationEventSequence == right.TenantRegistrationEventSequence &&
		left.Key == right.Key && left.OldRef == right.OldRef && left.IntervalSeconds == right.IntervalSeconds &&
		left.ConfigEventSequence == right.ConfigEventSequence && left.NextRunAt.Equal(right.NextRunAt)
}

func getSecretRotationScheduleTickRowTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, idempotencyKey string,
	ordinal int,
) (SecretRotationSchedule, error) {
	var schedule SecretRotationSchedule
	err := tx.QueryRow(ctx,
		`SELECT schedule_id::text, tenant_id::text, identity_version,
		        tenant_registration_event_id, tenant_registration_event_sequence,
		        provider, secret_key, old_ref,
		        interval_seconds, config_event_sequence, due_at
		   FROM secret_rotation_schedule_tick_rows
		  WHERE tenant_id = $1 AND idempotency_key = $2 AND ordinal = $3`,
		tenantID, idempotencyKey, ordinal).Scan(
		&schedule.ID, &schedule.TenantID, &schedule.IdentityVersion,
		&schedule.TenantRegistrationEventID, &schedule.TenantRegistrationEventSequence,
		&schedule.Provider, &schedule.Key, &schedule.OldRef,
		&schedule.IntervalSeconds, &schedule.ConfigEventSequence, &schedule.NextRunAt)
	schedule.Enabled = err == nil
	return schedule, err
}

// GetSecretRotationScheduleTickRow returns one immutable ordinal. Mutable live
// schedule rows are never consulted after the outer bind commits.
func (s *Store) GetSecretRotationScheduleTickRow(
	ctx context.Context,
	tenantID, idempotencyKey string,
	ordinal int,
) (SecretRotationSchedule, error) {
	var schedule SecretRotationSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		schedule, err = getSecretRotationScheduleTickRowTx(ctx, tx, tenantID, idempotencyKey, ordinal)
		return err
	})
	return schedule, err
}

// StartSecretRotationScheduleTickRow durably records the exact non-secret row
// snapshot before any child command can begin.
func (s *Store) StartSecretRotationScheduleTickRow(
	ctx context.Context,
	tick SecretRotationScheduleTick,
	ownerToken string,
	ownerGeneration int64,
	schedule SecretRotationSchedule,
	commandLeaseToken string,
	leaseDuration time.Duration,
) (SecretRotationScheduleTick, error) {
	var out SecretRotationScheduleTick
	if ownerToken == "" || ownerGeneration <= 0 || leaseDuration <= 0 || commandLeaseToken == "" ||
		schedule.TenantID != tick.TenantID || schedule.ID == "" || schedule.Provider == "" || schedule.Key == "" ||
		schedule.OldRef == "" || schedule.IntervalSeconds <= 0 || !schedule.Enabled {
		return out, fmt.Errorf("%w: row snapshot and unique child lease token are required", ErrSecretRotationScheduleTickConflict)
	}
	err := s.WithPrivacyTenantProjectionRepeatableRead(
		ctx, tick.TenantID, "secret rotation scheduler row start", func(tx pgx.Tx) error {
			if err := validateSecretRotationScheduleRegistrationTx(ctx, tx, tick.TenantID,
				tick.IdentityVersion, tick.TenantRegistrationEventID,
				tick.TenantRegistrationEventSequence); err != nil {
				return err
			}
			cursor, active, err := lockSecretRotationScheduleCursor(ctx, tx, tick.TenantID)
			if err != nil {
				return err
			}
			var retained SecretRotationScheduleTick
			if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2
			 FOR UPDATE`, tick.TenantID, tick.IdempotencyKey), &retained); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleTickOwner(cursor, active, retained, ownerToken, ownerGeneration); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleTickContinuation(retained, tick); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleTickSnapshotTx(ctx, tx, retained); err != nil {
				return err
			}
			if retained.Phase != "ready" || retained.Ran >= 50 || retained.Scanned >= retained.SnapshotCount {
				return fmt.Errorf("%w: tick cannot begin another row in phase %s", ErrSecretRotationScheduleTickConflict, retained.Phase)
			}
			expected, err := getSecretRotationScheduleTickRowTx(
				ctx, tx, retained.TenantID, retained.IdempotencyKey, retained.Scanned+1)
			if err != nil || !sameSecretRotationScheduleSnapshot(expected, schedule) {
				return fmt.Errorf("%w: row differs from immutable tick ordinal: %v", ErrSecretRotationScheduleTickConflict, err)
			}
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_ticks
			    SET phase = 'row_started', current_schedule_id = $4::uuid,
			        current_due_at = $5, current_provider = $6,
			        current_secret_key = $7, current_old_ref = $8,
			        current_interval_seconds = $9,
			        current_config_event_sequence = $10,
			        current_command_lease_token = $11,
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND idempotency_key = $2
			    AND request_binding = $3 AND phase = 'ready'
			    AND owner_token = $12 AND owner_generation = $13
			    AND EXISTS (
			        SELECT 1 FROM secret_rotation_schedule_scan_cursors AS cursor
			         WHERE cursor.tenant_id = $1
			           AND cursor.active_tick_key = $2
			           AND cursor.active_tick_binding = $3
			           AND cursor.lease_token = $12
			           AND cursor.lease_generation = $13
			           AND cursor.lease_until > clock_timestamp()
			    )`,
				retained.TenantID, retained.IdempotencyKey, retained.RequestBinding,
				schedule.ID, schedule.NextRunAt, schedule.Provider, schedule.Key,
				schedule.OldRef, schedule.IntervalSeconds, schedule.ConfigEventSequence, commandLeaseToken,
				ownerToken, ownerGeneration)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: start-row CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			tag, err = tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_scan_cursors
			    SET lease_until = clock_timestamp() + make_interval(secs => $4::double precision),
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND active_tick_key = $5
			    AND active_tick_binding = $6
			    AND lease_token = $2 AND lease_generation = $3
			    AND lease_until > clock_timestamp()`,
				retained.TenantID, ownerToken, ownerGeneration, leaseDuration.Seconds(),
				retained.IdempotencyKey, retained.RequestBinding)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: start-row lease CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			return scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2`, retained.TenantID, retained.IdempotencyKey), &out)
		})
	return out, err
}

// MarkSecretRotationScheduleTickWrapped persists the one allowed wrap before
// the head query begins, so restart never visits the tail twice in one tick.
func (s *Store) MarkSecretRotationScheduleTickWrapped(
	ctx context.Context,
	tick SecretRotationScheduleTick,
	ownerToken string,
	ownerGeneration int64,
	leaseDuration time.Duration,
) (SecretRotationScheduleTick, error) {
	var out SecretRotationScheduleTick
	if ownerToken == "" || ownerGeneration <= 0 || leaseDuration <= 0 {
		return out, fmt.Errorf("%w: live tick ownership is required", ErrSecretRotationScheduleTickConflict)
	}
	err := s.WithPrivacyTenantProjectionRepeatableRead(
		ctx, tick.TenantID, "secret rotation scheduler legacy wrap", func(tx pgx.Tx) error {
			if err := validateSecretRotationScheduleRegistrationTx(ctx, tx, tick.TenantID,
				tick.IdentityVersion, tick.TenantRegistrationEventID,
				tick.TenantRegistrationEventSequence); err != nil {
				return err
			}
			cursor, active, err := lockSecretRotationScheduleCursor(ctx, tx, tick.TenantID)
			if err != nil {
				return err
			}
			var retained SecretRotationScheduleTick
			if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2
			 FOR UPDATE`, tick.TenantID, tick.IdempotencyKey), &retained); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleTickOwner(cursor, active, retained, ownerToken, ownerGeneration); err != nil {
				return err
			}
			if retained.Phase != "ready" || retained.Wrapped || retained.StartScheduleID == ZeroUUID {
				return fmt.Errorf("%w: tick cannot enter wrapped segment", ErrSecretRotationScheduleTickConflict)
			}
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_ticks
			    SET wrapped = true, after_schedule_id = $6::uuid,
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND idempotency_key = $2 AND request_binding = $3
			    AND phase = 'ready' AND NOT wrapped
			    AND owner_token = $4 AND owner_generation = $5
			    AND EXISTS (
			        SELECT 1 FROM secret_rotation_schedule_scan_cursors AS cursor
			         WHERE cursor.tenant_id = $1
			           AND cursor.active_tick_key = $2
			           AND cursor.active_tick_binding = $3
			           AND cursor.lease_token = $4
			           AND cursor.lease_generation = $5
			           AND cursor.lease_until > clock_timestamp()
			    )`,
				retained.TenantID, retained.IdempotencyKey, retained.RequestBinding,
				ownerToken, ownerGeneration, ZeroUUID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: wrap CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			tag, err = tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_scan_cursors
			    SET lease_until = clock_timestamp() + make_interval(secs => $4::double precision),
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND active_tick_key = $5
			    AND active_tick_binding = $6
			    AND lease_token = $2 AND lease_generation = $3
			    AND lease_until > clock_timestamp()`,
				retained.TenantID, ownerToken, ownerGeneration, leaseDuration.Seconds(),
				retained.IdempotencyKey, retained.RequestBinding)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: wrap lease CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			return scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2`, retained.TenantID, retained.IdempotencyKey), &out)
		})
	return out, err
}

// CompleteSecretRotationScheduleTickRow atomically consumes one logical scan
// budget, appends its already-canonical receipt, advances the global cursor,
// and releases an owned deferred child lease. Lock order is cursor -> tick ->
// command, so every crash sees either all progress or none of it.
func (s *Store) CompleteSecretRotationScheduleTickRow(
	ctx context.Context,
	tick SecretRotationScheduleTick,
	ownerToken string,
	ownerGeneration int64,
	receipt []byte,
	ran, scanned int,
	commandRelease *SecretRotationScheduleCommandLeaseRelease,
	leaseDuration time.Duration,
) (SecretRotationScheduleTick, error) {
	if err := validateSecretRotationScheduleTickReceipt(receipt, ran, scanned, 0); err != nil {
		return SecretRotationScheduleTick{}, err
	}
	return s.completeSecretRotationScheduleTickRow(
		ctx, tick, ownerToken, ownerGeneration, receipt, ran, scanned,
		nil, commandRelease, leaseDuration)
}

// CompleteSecretRotationScheduleTickRowOutcome appends only the current row's
// new closed-schema outcome. The store owns the growing aggregate receipt, so a
// 500-row tick does not repeatedly submit and deeply revalidate all prior
// outcomes. Full receipts are still validated when a tick is claimed/recovered,
// finalized, replayed, or passed through the legacy completion entry point.
func (s *Store) CompleteSecretRotationScheduleTickRowOutcome(
	ctx context.Context,
	tick SecretRotationScheduleTick,
	ownerToken string,
	ownerGeneration int64,
	outcome SecretRotationScheduleTickRowOutcome,
	commandRelease *SecretRotationScheduleCommandLeaseRelease,
	leaseDuration time.Duration,
) (SecretRotationScheduleTick, error) {
	return s.completeSecretRotationScheduleTickRow(
		ctx, tick, ownerToken, ownerGeneration, nil, 0, 0,
		&outcome, commandRelease, leaseDuration)
}

func (s *Store) completeSecretRotationScheduleTickRow(
	ctx context.Context,
	tick SecretRotationScheduleTick,
	ownerToken string,
	ownerGeneration int64,
	receipt []byte,
	ran, scanned int,
	outcome *SecretRotationScheduleTickRowOutcome,
	commandRelease *SecretRotationScheduleCommandLeaseRelease,
	leaseDuration time.Duration,
) (SecretRotationScheduleTick, error) {
	var out SecretRotationScheduleTick
	if ownerToken == "" || ownerGeneration <= 0 || leaseDuration <= 0 {
		return out, fmt.Errorf("%w: live tick ownership is required", ErrSecretRotationScheduleTickConflict)
	}
	err := s.WithPrivacyTenantProjectionRepeatableRead(
		ctx, tick.TenantID, "secret rotation scheduler row completion", func(tx pgx.Tx) error {
			if err := validateSecretRotationScheduleRegistrationTx(ctx, tx, tick.TenantID,
				tick.IdentityVersion, tick.TenantRegistrationEventID,
				tick.TenantRegistrationEventSequence); err != nil {
				return err
			}
			cursor, active, err := lockSecretRotationScheduleCursor(ctx, tx, tick.TenantID)
			if err != nil {
				return err
			}
			var retained SecretRotationScheduleTick
			if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2
			 FOR UPDATE`, tick.TenantID, tick.IdempotencyKey), &retained); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleTickOwner(cursor, active, retained, ownerToken, ownerGeneration); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleTickSnapshotTx(ctx, tx, retained); err != nil {
				return err
			}
			if outcome == nil {
				if err := validateSecretRotationScheduleTickProgress(retained, receipt, ran, scanned); err != nil {
					return err
				}
			} else {
				if err := validateSecretRotationScheduleTickContinuation(retained, tick); err != nil {
					return err
				}
				var err error
				receipt, ran, scanned, err = appendSecretRotationScheduleTickRowOutcome(retained, *outcome)
				if err != nil {
					return err
				}
			}
			if commandRelease != nil {
				if commandRelease.ScheduleID != retained.CurrentSchedule.ID ||
					commandRelease.LeaseToken != retained.CurrentCommandLeaseToken {
					return fmt.Errorf("%w: deferred command release names another schedule", ErrSecretRotationScheduleTickConflict)
				}
			}
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_ticks
			    SET phase = 'ready', after_schedule_id = $4::uuid,
			        current_schedule_id = NULL, current_due_at = NULL,
			        current_provider = NULL, current_secret_key = NULL,
			        current_old_ref = NULL, current_interval_seconds = NULL,
			        current_config_event_sequence = NULL,
			        current_command_lease_token = NULL,
			        ran = $5, scanned = $6, receipt = $7::jsonb,
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND idempotency_key = $2 AND request_binding = $3
			    AND phase = 'row_started' AND owner_token = $8 AND owner_generation = $9
			    AND EXISTS (
			        SELECT 1 FROM secret_rotation_schedule_scan_cursors AS cursor
			         WHERE cursor.tenant_id = $1
			           AND cursor.active_tick_key = $2
			           AND cursor.active_tick_binding = $3
			           AND cursor.lease_token = $8
			           AND cursor.lease_generation = $9
			           AND cursor.lease_until > clock_timestamp()
			    )`,
				retained.TenantID, retained.IdempotencyKey, retained.RequestBinding,
				retained.CurrentSchedule.ID, ran, scanned, receipt, ownerToken, ownerGeneration)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: row-progress CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			// Progress is written before a deferred child lease is released. Both
			// changes still commit atomically, so a crash can expose neither half.
			if commandRelease != nil {
				if err := releaseSecretRotationScheduleCommandLeaseTx(ctx, tx, retained.TenantID, *commandRelease); err != nil {
					return err
				}
			}
			tag, err = tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_scan_cursors
			    SET after_schedule_id = $4::uuid, generation = generation + 1,
			        lease_until = clock_timestamp() + make_interval(secs => $5::double precision),
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND active_tick_key = $6
			    AND active_tick_binding = $7
			    AND lease_token = $2 AND lease_generation = $3
			    AND lease_until > clock_timestamp()`,
				retained.TenantID, ownerToken, ownerGeneration,
				retained.CurrentSchedule.ID, leaseDuration.Seconds(),
				retained.IdempotencyKey, retained.RequestBinding)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: cursor-progress CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			return scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2`, retained.TenantID, retained.IdempotencyKey), &out)
		})
	return out, err
}

// FinalizeSecretRotationScheduleTick stores the exact canonical HTTP body and
// releases aggregate authority in one CAS transaction. A late owner cannot
// overwrite bytes after lease expiry or different-key takeover.
func (s *Store) FinalizeSecretRotationScheduleTick(
	ctx context.Context,
	tick SecretRotationScheduleTick,
	ownerToken string,
	ownerGeneration int64,
	httpStatus int,
	body []byte,
	commandRelease *SecretRotationScheduleCommandLeaseRelease,
) (SecretRotationScheduleTick, error) {
	var out SecretRotationScheduleTick
	if ownerToken == "" || ownerGeneration <= 0 {
		return out, fmt.Errorf("%w: live tick ownership is required", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationScheduleTickReceipt(body, tick.Ran, tick.Scanned, httpStatus); err != nil {
		return out, err
	}
	err := s.WithPrivacyTenantProjectionRepeatableRead(
		ctx, tick.TenantID, "secret rotation scheduler tick completion", func(tx pgx.Tx) error {
			if err := validateSecretRotationScheduleRegistrationTx(ctx, tx, tick.TenantID,
				tick.IdentityVersion, tick.TenantRegistrationEventID,
				tick.TenantRegistrationEventSequence); err != nil {
				return err
			}
			cursor, active, err := lockSecretRotationScheduleCursor(ctx, tx, tick.TenantID)
			if err != nil {
				return err
			}
			var retained SecretRotationScheduleTick
			if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2
			 FOR UPDATE`, tick.TenantID, tick.IdempotencyKey), &retained); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleTickOwner(cursor, active, retained, ownerToken, ownerGeneration); err != nil {
				return err
			}
			if err := validateSecretRotationScheduleTickSnapshotTx(ctx, tx, retained); err != nil {
				return err
			}
			if retained.Ran != tick.Ran || retained.Scanned != tick.Scanned {
				return fmt.Errorf("%w: terminal budgets differ from retained progress", ErrSecretRotationScheduleTickConflict)
			}
			if err := validateSecretRotationScheduleTickTerminal(retained, body, httpStatus); err != nil {
				return err
			}
			if httpStatus == 200 && retained.Phase != "ready" {
				return fmt.Errorf("%w: successful tick cannot abandon a started row", ErrSecretRotationScheduleTickConflict)
			}
			if commandRelease != nil {
				if retained.CurrentSchedule == nil || commandRelease.ScheduleID != retained.CurrentSchedule.ID ||
					commandRelease.LeaseToken != retained.CurrentCommandLeaseToken {
					return fmt.Errorf("%w: terminal command release names another schedule", ErrSecretRotationScheduleTickConflict)
				}
			}
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_ticks
			    SET phase = 'terminal', receipt = $4::jsonb,
			        current_schedule_id = NULL, current_due_at = NULL,
			        current_provider = NULL, current_secret_key = NULL,
			        current_old_ref = NULL, current_interval_seconds = NULL,
			        current_config_event_sequence = NULL,
			        current_command_lease_token = NULL,
			        owner_token = '', terminal_http_status = $5,
			        terminal_body = $6, updated_at = clock_timestamp(),
			        completed_at = clock_timestamp()
			  WHERE tenant_id = $1 AND idempotency_key = $2 AND request_binding = $3
			    AND phase <> 'terminal' AND owner_token = $7 AND owner_generation = $8
			    AND EXISTS (
			        SELECT 1 FROM secret_rotation_schedule_scan_cursors AS cursor
			         WHERE cursor.tenant_id = $1
			           AND cursor.active_tick_key = $2
			           AND cursor.active_tick_binding = $3
			           AND cursor.lease_token = $7
			           AND cursor.lease_generation = $8
			           AND cursor.lease_until > clock_timestamp()
			    )`,
				retained.TenantID, retained.IdempotencyKey, retained.RequestBinding,
				body, httpStatus, body, ownerToken, ownerGeneration)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: terminal tick CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			if commandRelease != nil {
				if err := releaseSecretRotationScheduleCommandLeaseTx(ctx, tx, retained.TenantID, *commandRelease); err != nil {
					return err
				}
			}
			tag, err = tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_scan_cursors
			    SET active_tick_key = '', active_tick_binding = '',
			        lease_token = '', lease_until = NULL,
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND active_tick_key = $4
			    AND active_tick_binding = $5
			    AND lease_token = $2 AND lease_generation = $3
			    AND lease_until > clock_timestamp()`,
				retained.TenantID, ownerToken, ownerGeneration,
				retained.IdempotencyKey, retained.RequestBinding)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: terminal cursor CAS changed %d rows", ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			return scanSecretRotationScheduleTick(tx.QueryRow(ctx,
				secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2`, retained.TenantID, retained.IdempotencyKey), &out)
		})
	return out, err
}

// VerifySecretRotationScheduleTickTerminalTx proves that bytes about to enter
// the outer idempotency cache are exactly the terminal receiver bytes. The
// caller performs the protected outer UPDATE in this same transaction.
func (s *Store) VerifySecretRotationScheduleTickTerminalTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, idempotencyKey, requestBinding string,
	tenantRegistrationEventID string,
	tenantRegistrationEventSequence uint64,
	httpStatus int,
	body []byte,
) error {
	if tx == nil || tenantID == "" || idempotencyKey == "" || requestBinding == "" || len(body) == 0 {
		return fmt.Errorf("%w: terminal cache verification requires exact authority and bytes", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationScheduleRegistrationTx(ctx, tx, tenantID,
		SecretRotationScheduleIdentityVersion, tenantRegistrationEventID,
		tenantRegistrationEventSequence); err != nil {
		return err
	}
	if _, _, err := lockSecretRotationScheduleCursor(ctx, tx, tenantID); err != nil {
		return err
	}
	var retained SecretRotationScheduleTick
	if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
		secretRotationScheduleTickSelect+`
		 AND idempotency_key = $2
		 FOR UPDATE`, tenantID, idempotencyKey), &retained); err != nil {
		return err
	}
	if retained.IdentityVersion != SecretRotationScheduleIdentityVersion ||
		retained.TenantRegistrationEventID != tenantRegistrationEventID ||
		retained.TenantRegistrationEventSequence != tenantRegistrationEventSequence ||
		retained.RequestBinding != requestBinding || retained.Phase != "terminal" ||
		retained.TerminalHTTPStatus == nil || *retained.TerminalHTTPStatus != httpStatus ||
		!bytes.Equal(retained.TerminalBody, body) {
		return fmt.Errorf("%w: outer result differs from terminal scheduler receipt", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationScheduleTickRetainedTerminal(retained); err != nil {
		return err
	}
	return validateSecretRotationScheduleTickSnapshotTx(ctx, tx, retained)
}

func releaseSecretRotationScheduleCommandLeaseTx(ctx context.Context, tx pgx.Tx, tenantID string, release SecretRotationScheduleCommandLeaseRelease) error {
	if release.ScheduleID == "" || release.RunID == "" || release.LeaseToken == "" {
		return fmt.Errorf("%w: incomplete child command lease release", ErrSecretRotationScheduleCommandConflict)
	}
	tag, err := tx.Exec(ctx,
		`UPDATE secret_rotation_schedule_commands
		    SET lease_token = '', lease_until = NULL, updated_at = clock_timestamp()
		  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
		    AND status = 'claimed' AND lease_token = $4`,
		tenantID, release.ScheduleID, release.RunID, release.LeaseToken)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var status string
	if err := tx.QueryRow(ctx,
		`SELECT status
		   FROM secret_rotation_schedule_commands
		  WHERE tenant_id = $1 AND schedule_id = $2 AND run_id = $3::uuid
		  FOR UPDATE`, tenantID, release.ScheduleID, release.RunID).Scan(&status); err != nil {
		return err
	}
	if secretRotationScheduleTerminalStatus(status) {
		return nil
	}
	return fmt.Errorf("%w: child command lease is not owned by aggregate tick", ErrSecretRotationScheduleCommandConflict)
}

// GetSecretRotationScheduleTick loads retained aggregate authority under RLS.
func (s *Store) GetSecretRotationScheduleTick(ctx context.Context, tenantID, idempotencyKey string) (SecretRotationScheduleTick, error) {
	var out SecretRotationScheduleTick
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretRotationScheduleTick(tx.QueryRow(ctx,
			secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2`, tenantID, idempotencyKey), &out)
	})
	return out, err
}
