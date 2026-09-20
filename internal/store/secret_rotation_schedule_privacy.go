// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
)

const SecretRotationSchedulePrivacyRewriteVersion = 1

const secretRotationSchedulePrivacyClosedError = ""

const secretRotationSchedulePrivacyClearedFreeText = ""

const (
	SecretRotationSchedulePrivacyDispositionTick    = "secret_rotation_schedule_tick"
	SecretRotationSchedulePrivacyDispositionCommand = "secret_rotation_schedule_command"
	SecretRotationSchedulePrivacyDispositionErased  = "privacy_erased"

	secretRotationSchedulePrivacyEvidenceMax = 100000
)

// SecretRotationSchedulePrivacyDisposition is non-PII evidence returned to the
// privacy preparation owner. TickRef is a tenant-bound one-way reference to an
// outer key; command dispositions use the stable scheduled-run event UUID.
// Neither form exposes a raw Idempotency-Key or a scheduler field.
type SecretRotationSchedulePrivacyDisposition struct {
	Kind         string `json:"kind"`
	AuthorityRef string `json:"authority_ref"`
	Disposition  string `json:"disposition"`
}

// ValidateSecretRotationSchedulePrivacyDispositionsV3 accepts only the two
// scheduler receiver classes, their closed privacy-erased disposition, and the
// non-PII authority identity shape owned by each class. Evidence must already be
// in canonical kind/ref order so retries and recovered events are byte-stable.
func ValidateSecretRotationSchedulePrivacyDispositionsV3(
	dispositions []SecretRotationSchedulePrivacyDisposition,
) error {
	if len(dispositions) > secretRotationSchedulePrivacyEvidenceMax {
		return errors.New("store: scheduler privacy evidence exceeds its bounded maximum")
	}
	previous := ""
	for index, disposition := range dispositions {
		switch disposition.Kind {
		case SecretRotationSchedulePrivacyDispositionTick:
			if !validSecretRotationSchedulePrivacySubjectRef(disposition.AuthorityRef) {
				return errors.New("store: scheduler privacy tick authority is not a one-way reference")
			}
		case SecretRotationSchedulePrivacyDispositionCommand:
			parsed, err := uuid.Parse(disposition.AuthorityRef)
			if err != nil || parsed.String() != disposition.AuthorityRef {
				return errors.New("store: scheduler privacy command authority is not a canonical UUID")
			}
		default:
			return fmt.Errorf("store: scheduler privacy evidence kind %q is unsupported", disposition.Kind)
		}
		if disposition.Disposition != SecretRotationSchedulePrivacyDispositionErased {
			return fmt.Errorf("store: scheduler privacy disposition %q is unsupported", disposition.Disposition)
		}
		identity := disposition.Kind + "\x00" + disposition.AuthorityRef
		if index > 0 && identity <= previous {
			return errors.New("store: scheduler privacy evidence is unsorted or contains a duplicate")
		}
		previous = identity
	}
	return nil
}

// ValidateSecretRotationSchedulePrivacyEvidenceV3 binds the closed aggregate
// counts in privacy.subject.erased to the exact retained dispositions. The two
// physical-only counts are bounded by the selected tick set and cannot smuggle
// arbitrary labels or negative values into canonical history.
func ValidateSecretRotationSchedulePrivacyEvidenceV3(
	counts map[string]int,
	dispositions []SecretRotationSchedulePrivacyDisposition,
) error {
	if dispositions == nil {
		return errors.New("store: scheduler privacy dispositions are required")
	}
	if err := ValidateSecretRotationSchedulePrivacyDispositionsV3(dispositions); err != nil {
		return err
	}
	keys := [...]string{
		"secret_rotation_schedule_ticks",
		"secret_rotation_schedule_tick_rows",
		"secret_rotation_schedule_commands",
		"secret_rotation_schedule_outer_resolutions",
	}
	for _, key := range keys {
		if _, ok := counts[key]; !ok {
			return fmt.Errorf("store: scheduler privacy count %q is required", key)
		}
	}
	ticks := counts["secret_rotation_schedule_ticks"]
	tickRows := counts["secret_rotation_schedule_tick_rows"]
	commands := counts["secret_rotation_schedule_commands"]
	outerResolutions := counts["secret_rotation_schedule_outer_resolutions"]
	if ticks < 0 || tickRows < 0 || commands < 0 || outerResolutions < 0 ||
		ticks > secretRotationSchedulePrivacyEvidenceMax ||
		commands > secretRotationSchedulePrivacyEvidenceMax ||
		outerResolutions > ticks || tickRows > ticks*500 {
		return errors.New("store: scheduler privacy counts exceed their closed bounds")
	}
	var dispositionTicks, dispositionCommands int
	for _, disposition := range dispositions {
		switch disposition.Kind {
		case SecretRotationSchedulePrivacyDispositionTick:
			dispositionTicks++
		case SecretRotationSchedulePrivacyDispositionCommand:
			dispositionCommands++
		}
	}
	if dispositionTicks != ticks || dispositionCommands != commands {
		return errors.New("store: scheduler privacy counts differ from exact dispositions")
	}
	return nil
}

// SecretRotationSchedulePrivacyPreparation reports the exact rows closed by one
// preparation transaction. OuterResolutions counts exact same-transaction
// acknowledgements from the generic protected idempotency-result owner.
type SecretRotationSchedulePrivacyPreparation struct {
	Ticks            int
	TickRows         int
	Commands         int
	OuterResolutions int
	Dispositions     []SecretRotationSchedulePrivacyDisposition
}

// SecretRotationSchedulePrivacyOuterRequirement is the transient contract for
// the generic idempotency-result owner. AuthorityRef is a one-way lookup name;
// the raw key is passed only as a callback argument and must never enter durable
// privacy evidence. A key match requires an AN-5 tombstone/rekey. A body match
// requires a protected deterministic replacement for the exact terminal bytes.
type SecretRotationSchedulePrivacyOuterRequirement struct {
	AuthorityRef              string
	RequestBinding            string
	Status                    string
	ResultCodec               string
	ReplacementIdempotencyKey string
	RawKeyTokenMatch          bool
	TerminalBodyMatch         bool
	TerminalHTTPStatus        int
	OriginalTerminalBody      []byte
	RewrittenTerminalBody     []byte
}

// SecretRotationSchedulePrivacyOuterAcknowledgement is returned only after the
// resolver has installed its tombstone/protected result in the same tx. The
// scheduler verifies the exact row key, binding, codec, and protected bytes
// before it closes any tick, child row, or command.
type SecretRotationSchedulePrivacyOuterAcknowledgement struct {
	AuthorityRef           string
	RequestBinding         string
	OriginalResultCodec    string
	ResolvedIdempotencyKey string
	ResolvedResultCodec    string
	ProtectedResult        []byte
}

type SecretRotationSchedulePrivacyOuterResolver func(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, rawIdempotencyKey string,
	requirement SecretRotationSchedulePrivacyOuterRequirement,
) (SecretRotationSchedulePrivacyOuterAcknowledgement, error)

type secretRotationSchedulePrivacyTick struct {
	tick SecretRotationScheduleTick
}

type secretRotationSchedulePrivacyOuter struct {
	key            string
	status         string
	requestBinding string
	resultCodec    string
	result         []byte
}

type secretRotationSchedulePrivacyTickRow struct {
	tickKey    string
	ordinal    int
	scheduleID string
	dueAt      time.Time
	provider   string
	key        string
	oldRef     string
}

type secretRotationSchedulePrivacyCommand struct {
	runID                 string
	scheduleID            string
	dueAt                 time.Time
	provider              string
	key                   string
	oldRef                string
	newRef                string
	errorText             string
	preparedNewRef        string
	preparedError         string
	tickKey               string
	terminalEventID       string
	status                string
	privacyRewriteVersion int
	privacySubjectRef     string
	privacyOperationID    string
	privacyEventID        string
}

// PrepareSecretRotationSchedulePrivacyErasureTx closes and pseudonymizes only
// scheduler receivers whose declared human-entered fields semantically contain
// the exact subject. tx belongs to the caller's already-open privacy preparation
// transaction and exclusive history-operation grant. This function never opens
// another transaction. It delegates selected outer key/result changes to their
// generic owner and verifies that owner's exact same-transaction acknowledgement.
func (s *Store) PrepareSecretRotationSchedulePrivacyErasureTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, subject, subjectRef, operationID, eventID string,
	resolveOuter SecretRotationSchedulePrivacyOuterResolver,
) (SecretRotationSchedulePrivacyPreparation, error) {
	var result SecretRotationSchedulePrivacyPreparation
	subject = strings.TrimSpace(subject)
	if tx == nil || tenantID == "" || subject == "" ||
		subjectRef != privacy.SubjectRef(tenantID, subject) || operationID == "" ||
		!validSecretRotationSchedulePrivacyIdentity(operationID) ||
		!validSecretRotationSchedulePrivacyIdentity(eventID) {
		return result, errors.New("store: scheduler privacy preparation identity is incomplete")
	}

	ticks, err := loadSecretRotationSchedulePrivacyTicksTx(ctx, tx, tenantID)
	if err != nil {
		return result, err
	}
	tickRows, err := loadSecretRotationSchedulePrivacyTickRowsTx(ctx, tx, tenantID)
	if err != nil {
		return result, err
	}
	commands, err := loadSecretRotationSchedulePrivacyCommandsTx(ctx, tx, tenantID)
	if err != nil {
		return result, err
	}

	selectedTicks := make(map[string]bool)
	selectedCommands := make(map[string]bool)
	selectedEdges := make(map[string]bool)
	for _, candidate := range ticks {
		selected, err := secretRotationSchedulePrivacyTickMatches(candidate.tick, subject)
		if err != nil {
			return result, err
		}
		_, rawKeyMatch := rewriteSecretRotationSchedulePrivacySubjectToken(
			candidate.tick.IdempotencyKey, subject, "")
		if selected || rawKeyMatch {
			selectedTicks[candidate.tick.IdempotencyKey] = true
		}
	}
	for _, row := range tickRows {
		if secretRotationSchedulePrivacyTickRowMatches(row, subject) {
			selectedTicks[row.tickKey] = true
		}
	}
	for _, command := range commands {
		selected, err := secretRotationSchedulePrivacyCommandMatches(command, subject)
		if err != nil {
			return result, err
		}
		if selected {
			selectedCommands[command.runID] = true
			if command.status == "claimed" {
				selectedEdges[secretRotationSchedulePrivacyEdge(command.scheduleID, command.dueAt)] = true
			}
		}
	}

	// Close the whole execution lineage for a selected row. A command can have
	// originated in tick A and be carried by tick B, so both the stored tick key
	// and the deterministic schedule/due edge participate in this finite closure.
	for changed := true; changed; {
		changed = false
		for _, tick := range ticks {
			if selectedTicks[tick.tick.IdempotencyKey] && tick.tick.Phase == "row_started" &&
				tick.tick.CurrentSchedule != nil {
				edge := secretRotationSchedulePrivacyEdge(
					tick.tick.CurrentSchedule.ID, tick.tick.CurrentSchedule.NextRunAt)
				if !selectedEdges[edge] {
					selectedEdges[edge] = true
					changed = true
				}
			}
			if tick.tick.Phase == "row_started" && tick.tick.CurrentSchedule != nil &&
				selectedEdges[secretRotationSchedulePrivacyEdge(
					tick.tick.CurrentSchedule.ID, tick.tick.CurrentSchedule.NextRunAt)] &&
				!selectedTicks[tick.tick.IdempotencyKey] {
				selectedTicks[tick.tick.IdempotencyKey] = true
				changed = true
			}
		}
		for _, command := range commands {
			edge := secretRotationSchedulePrivacyEdge(command.scheduleID, command.dueAt)
			if selectedCommands[command.runID] || (command.status == "claimed" && selectedEdges[edge]) {
				if !selectedCommands[command.runID] {
					selectedCommands[command.runID] = true
					changed = true
				}
				if command.status == "claimed" && !selectedEdges[edge] {
					selectedEdges[edge] = true
					changed = true
				}
			}
		}
	}
	if len(selectedTicks) == 0 && len(selectedCommands) == 0 {
		result.Dispositions = []SecretRotationSchedulePrivacyDisposition{}
		return result, nil
	}

	// Privacy preparation owns the exclusive operation grant, so ordinary
	// scheduler transactions have drained before these locks. Keep the receiver
	// order explicit anyway: cursor -> outer rows -> ticks -> snapshot rows -> commands.
	// These protected receivers deliberately grant trstctl_app SELECT only. Move
	// to the narrow owner role before FOR UPDATE (which PostgreSQL treats as an
	// update privilege) and keep the existing restore immediately after the
	// verified writes.
	if err := resetSecretRotationSchedulePrivacyRole(ctx, tx); err != nil {
		return result, err
	}
	if _, _, err := lockSecretRotationScheduleCursor(ctx, tx, tenantID); err != nil {
		return result, fmt.Errorf("store: lock scheduler cursor for privacy preparation: %w", err)
	}
	tickKeys := sortedSecretRotationSchedulePrivacyKeys(selectedTicks)
	lockedOuters := make(map[string]secretRotationSchedulePrivacyOuter, len(tickKeys))
	for _, tickKey := range tickKeys {
		outer := secretRotationSchedulePrivacyOuter{key: tickKey}
		if err := tx.QueryRow(ctx,
			`SELECT status, request_binding, result_codec, result
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2
			  FOR UPDATE`, tenantID, tickKey).Scan(
			&outer.status, &outer.requestBinding, &outer.resultCodec, &outer.result); err != nil {
			return result, fmt.Errorf("store: lock selected scheduler outer authority: %w", err)
		}
		if outer.status != "bound" && outer.status != "completed" {
			return result, fmt.Errorf("%w: selected scheduler outer status %q is invalid",
				ErrSecretRotationScheduleTickConflict, outer.status)
		}
		lockedOuters[tickKey] = outer
	}
	lockedTicks := make(map[string]SecretRotationScheduleTick, len(tickKeys))
	for _, tickKey := range tickKeys {
		var retained SecretRotationScheduleTick
		if err := scanSecretRotationScheduleTick(tx.QueryRow(ctx,
			secretRotationScheduleTickSelect+`
			 AND idempotency_key = $2
			 FOR UPDATE`, tenantID, tickKey), &retained); err != nil {
			return result, fmt.Errorf("store: lock selected scheduler tick: %w", err)
		}
		if err := authorizeSecretRotationSchedulePrivacyRestampTx(
			ctx, tx, tenantID,
			retained.PrivacyRewriteVersion, retained.PrivacySubjectRef,
			retained.PrivacyOperationID, retained.PrivacyEventID,
			subjectRef, operationID, eventID,
		); err != nil {
			return result, err
		}
		if retained.RequestBinding != lockedOuters[tickKey].requestBinding {
			return result, fmt.Errorf("%w: scheduler tick and outer binding differ",
				ErrSecretRotationScheduleTickConflict)
		}
		lockedTicks[tickKey] = retained
	}
	lockedTickRows, err := lockSecretRotationSchedulePrivacyTickRowsTx(ctx, tx, tenantID, tickKeys)
	if err != nil {
		return result, err
	}
	commandIDs := sortedSecretRotationSchedulePrivacyKeys(selectedCommands)
	lockedCommands := make(map[string]secretRotationSchedulePrivacyCommand, len(commandIDs))
	for _, runID := range commandIDs {
		retained, err := scanSecretRotationSchedulePrivacyCommand(tx.QueryRow(ctx,
			secretRotationSchedulePrivacyCommandSelect+`
			 AND run_id = $2::uuid
			 FOR UPDATE`, tenantID, runID))
		if err != nil {
			return result, fmt.Errorf("store: lock selected scheduler command: %w", err)
		}
		if err := authorizeSecretRotationSchedulePrivacyRestampTx(
			ctx, tx, tenantID,
			retained.privacyRewriteVersion, retained.privacySubjectRef,
			retained.privacyOperationID, retained.privacyEventID,
			subjectRef, operationID, eventID,
		); err != nil {
			return result, err
		}
		lockedCommands[runID] = retained
	}

	resolvedTickKeys := make(map[string]string, len(tickKeys))
	ownerErr := func() error {
		placeholder := privacy.Placeholder(subjectRef)
		if _, err := tx.Exec(ctx,
			`UPDATE secret_rotation_schedule_scan_cursors
			    SET active_tick_key = '', active_tick_binding = '',
			        lease_token = '', lease_until = NULL,
			        updated_at = clock_timestamp()
			  WHERE tenant_id = $1 AND active_tick_key = ANY($2::text[])`,
			tenantID, tickKeys); err != nil {
			return err
		}
		for _, tickKey := range tickKeys {
			resolvedTickKeys[tickKey] = tickKey
			requirement, required, err := secretRotationSchedulePrivacyOuterRequirementForTick(
				tenantID, subject, placeholder, lockedOuters[tickKey], lockedTicks[tickKey])
			if err != nil {
				return err
			}
			if !required {
				continue
			}
			if resolveOuter == nil {
				return fmt.Errorf("%w: scheduler outer authority %s requires same-transaction privacy resolution",
					ErrSecretRotationScheduleTickConflict, requirement.AuthorityRef)
			}
			acknowledgement, err := resolveOuter(ctx, tx, tenantID, tickKey, requirement)
			if err != nil {
				return fmt.Errorf("store: resolve scheduler outer privacy authority %s: %w",
					requirement.AuthorityRef, err)
			}
			if err := verifySecretRotationSchedulePrivacyOuterAcknowledgementTx(
				ctx, tx, tenantID, tickKey, lockedOuters[tickKey], requirement, acknowledgement); err != nil {
				return err
			}
			resolvedTickKeys[tickKey] = acknowledgement.ResolvedIdempotencyKey
			result.OuterResolutions++
		}
		for _, tickKey := range tickKeys {
			retained := lockedTicks[tickKey]
			resolvedTickKey := resolvedTickKeys[tickKey]
			currentScheduleID := ""
			if retained.CurrentSchedule != nil {
				currentScheduleID = retained.CurrentSchedule.ID
			}
			closed := retained.Phase != "terminal" && retained.TerminalHTTPStatus == nil
			receipt, _, err := rewriteSecretRotationSchedulePrivacyReceipt(
				retained.Receipt, subject, placeholder, closed, currentScheduleID)
			if err != nil {
				return err
			}
			var terminalBody []byte
			if retained.TerminalHTTPStatus != nil {
				terminalBody, _, err = rewriteSecretRotationSchedulePrivacyReceipt(
					retained.TerminalBody, subject, placeholder, false, "")
				if err != nil {
					return err
				}
			}
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_ticks
			    SET phase = 'privacy_erased',
			        current_schedule_id = NULL, current_due_at = NULL,
			        current_provider = NULL, current_secret_key = NULL,
			        current_old_ref = NULL, current_interval_seconds = NULL,
			        current_config_event_sequence = NULL,
			        current_command_lease_token = NULL,
			        receipt = $3::jsonb, owner_token = '',
			        terminal_http_status = $4, terminal_body = $5,
			        privacy_rewrite_version = $6, privacy_subject_ref = $7,
			        privacy_operation_id = $8, privacy_event_id = $9,
			        updated_at = clock_timestamp(),
			        completed_at = coalesce(completed_at, clock_timestamp())
			  WHERE tenant_id = $1 AND idempotency_key = $2
			    AND privacy_rewrite_version = $10
			    AND privacy_subject_ref = $11
			    AND privacy_operation_id = $12 AND privacy_event_id = $13`,
				tenantID, resolvedTickKey, receipt, retained.TerminalHTTPStatus, terminalBody,
				SecretRotationSchedulePrivacyRewriteVersion, subjectRef, operationID, eventID,
				retained.PrivacyRewriteVersion, retained.PrivacySubjectRef,
				retained.PrivacyOperationID, retained.PrivacyEventID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: privacy tick CAS changed %d rows",
					ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
		}
		for _, row := range lockedTickRows {
			resolvedTickKey := resolvedTickKeys[row.tickKey]
			provider, _ := rewriteSecretRotationSchedulePrivacySubjectToken(row.provider, subject, placeholder)
			key, _ := rewriteSecretRotationSchedulePrivacySubjectToken(row.key, subject, placeholder)
			oldRef, _ := rewriteSecretRotationSchedulePrivacyOpaqueExact(row.oldRef, subject, placeholder)
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_tick_rows
				    SET provider = $4, secret_key = $5, old_ref = $6
				  WHERE tenant_id = $1 AND idempotency_key = $2 AND ordinal = $3
				    AND provider = $7 AND secret_key = $8 AND old_ref = $9`,
				tenantID, resolvedTickKey, row.ordinal, provider, key, oldRef,
				row.provider, row.key, row.oldRef)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: privacy tick-row CAS changed %d rows",
					ErrSecretRotationScheduleTickConflict, tag.RowsAffected())
			}
			result.TickRows++
		}
		for _, runID := range commandIDs {
			command := lockedCommands[runID]
			provider, _ := rewriteSecretRotationSchedulePrivacySubjectToken(command.provider, subject, placeholder)
			key, _ := rewriteSecretRotationSchedulePrivacySubjectToken(command.key, subject, placeholder)
			oldRef, _ := rewriteSecretRotationSchedulePrivacyOpaqueExact(command.oldRef, subject, placeholder)
			newRef, _ := rewriteSecretRotationSchedulePrivacyOpaqueExact(command.newRef, subject, placeholder)
			errorText, _ := rewriteSecretRotationSchedulePrivacyFreeText(command.errorText, subject)
			preparedNewRef, _ := rewriteSecretRotationSchedulePrivacyOpaqueExact(command.preparedNewRef, subject, placeholder)
			preparedError, _ := rewriteSecretRotationSchedulePrivacyFreeText(command.preparedError, subject)
			resolvedCommandTickKey := command.tickKey
			if resolved, ok := resolvedTickKeys[command.tickKey]; ok {
				resolvedCommandTickKey = resolved
			} else if _, changed := rewriteSecretRotationSchedulePrivacySubjectToken(
				command.tickKey, subject, ""); changed {
				resolvedCommandTickKey = secretRotationSchedulePrivacyOuterReplacementKey(
					secretRotationSchedulePrivacyOuterAuthorityRef(tenantID, command.tickKey))
			}
			tag, err := tx.Exec(ctx,
				`UPDATE secret_rotation_schedule_commands
				    SET provider = $3, secret_key = $4, old_ref = $5,
				        new_ref = $6, error = $7,
				        prepared_status = '', prepared_new_ref = $8, prepared_error = $9,
				        tick_idempotency_key = $10,
				        prepared_event_digest = '', prepared_at = NULL,
				        terminal_event_type = '', terminal_event_sequence = NULL,
				        terminal_event_digest = '', terminal_event_from_event = NULL,
				        status = 'privacy_erased', lease_token = '', lease_until = NULL,
				        privacy_rewrite_version = $11, privacy_subject_ref = $12,
				        privacy_operation_id = $13, privacy_event_id = $14,
				        updated_at = clock_timestamp(),
				        terminal_at = coalesce(terminal_at, clock_timestamp())
				  WHERE tenant_id = $1 AND run_id = $2::uuid
				    AND provider = $15 AND secret_key = $16 AND old_ref = $17
				    AND new_ref = $18 AND error = $19
				    AND prepared_new_ref = $20 AND prepared_error = $21
				    AND tick_idempotency_key = $22 AND status = $23
				    AND privacy_rewrite_version = $24
				    AND privacy_subject_ref = $25
				    AND privacy_operation_id = $26 AND privacy_event_id = $27`,
				tenantID, runID, provider, key, oldRef, newRef, errorText,
				preparedNewRef, preparedError, resolvedCommandTickKey,
				SecretRotationSchedulePrivacyRewriteVersion, subjectRef, operationID, eventID,
				command.provider, command.key, command.oldRef, command.newRef, command.errorText,
				command.preparedNewRef, command.preparedError, command.tickKey, command.status,
				command.privacyRewriteVersion, command.privacySubjectRef,
				command.privacyOperationID, command.privacyEventID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: privacy command CAS changed %d rows",
					ErrSecretRotationScheduleCommandConflict, tag.RowsAffected())
			}
		}
		return nil
	}()
	restoreErr := restoreSecretRotationSchedulePrivacyRole(ctx, tx)
	if ownerErr != nil || restoreErr != nil {
		return result, errors.Join(ownerErr, restoreErr)
	}

	result.Ticks = len(tickKeys)
	result.Commands = len(commandIDs)
	result.Dispositions = make([]SecretRotationSchedulePrivacyDisposition, 0, len(tickKeys)+len(commandIDs))
	for _, tickKey := range tickKeys {
		result.Dispositions = append(result.Dispositions, SecretRotationSchedulePrivacyDisposition{
			Kind:         SecretRotationSchedulePrivacyDispositionTick,
			AuthorityRef: secretRotationSchedulePrivacyOuterAuthorityRef(tenantID, tickKey),
			Disposition:  SecretRotationSchedulePrivacyDispositionErased,
		})
	}
	for _, command := range commands {
		if selectedCommands[command.runID] {
			result.Dispositions = append(result.Dispositions, SecretRotationSchedulePrivacyDisposition{
				Kind: SecretRotationSchedulePrivacyDispositionCommand, AuthorityRef: command.terminalEventID,
				Disposition: SecretRotationSchedulePrivacyDispositionErased,
			})
		}
	}
	sort.Slice(result.Dispositions, func(i, j int) bool {
		if result.Dispositions[i].Kind == result.Dispositions[j].Kind {
			return result.Dispositions[i].AuthorityRef < result.Dispositions[j].AuthorityRef
		}
		return result.Dispositions[i].Kind < result.Dispositions[j].Kind
	})
	if err := ValidateSecretRotationSchedulePrivacyDispositionsV3(result.Dispositions); err != nil {
		return SecretRotationSchedulePrivacyPreparation{}, err
	}
	return result, nil
}

func loadSecretRotationSchedulePrivacyTicksTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) ([]secretRotationSchedulePrivacyTick, error) {
	rows, err := tx.Query(ctx, secretRotationScheduleTickSelect+`
		 ORDER BY idempotency_key`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []secretRotationSchedulePrivacyTick
	for rows.Next() {
		var candidate secretRotationSchedulePrivacyTick
		if err := scanSecretRotationScheduleTick(rows, &candidate.tick); err != nil {
			return nil, err
		}
		out = append(out, candidate)
	}
	return out, rows.Err()
}

func loadSecretRotationSchedulePrivacyTickRowsTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) ([]secretRotationSchedulePrivacyTickRow, error) {
	rows, err := tx.Query(ctx,
		`SELECT idempotency_key, ordinal, schedule_id::text, due_at, provider, secret_key, old_ref
		   FROM secret_rotation_schedule_tick_rows
		  WHERE tenant_id = $1
		  ORDER BY idempotency_key, ordinal`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []secretRotationSchedulePrivacyTickRow
	for rows.Next() {
		var row secretRotationSchedulePrivacyTickRow
		if err := rows.Scan(&row.tickKey, &row.ordinal, &row.scheduleID, &row.dueAt,
			&row.provider, &row.key, &row.oldRef); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func lockSecretRotationSchedulePrivacyTickRowsTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	tickKeys []string,
) ([]secretRotationSchedulePrivacyTickRow, error) {
	if len(tickKeys) == 0 {
		return []secretRotationSchedulePrivacyTickRow{}, nil
	}
	rows, err := tx.Query(ctx,
		`SELECT idempotency_key, ordinal, schedule_id::text, due_at, provider, secret_key, old_ref
		   FROM secret_rotation_schedule_tick_rows
		  WHERE tenant_id = $1 AND idempotency_key = ANY($2::text[])
		  ORDER BY idempotency_key, ordinal
		  FOR UPDATE`, tenantID, tickKeys)
	if err != nil {
		return nil, fmt.Errorf("store: lock selected scheduler tick rows: %w", err)
	}
	defer rows.Close()
	var out []secretRotationSchedulePrivacyTickRow
	for rows.Next() {
		var row secretRotationSchedulePrivacyTickRow
		if err := rows.Scan(&row.tickKey, &row.ordinal, &row.scheduleID, &row.dueAt,
			&row.provider, &row.key, &row.oldRef); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// #nosec G101 -- SQL authority columns are names, not embedded credentials (CWE-798).
const secretRotationSchedulePrivacyCommandSelect = `SELECT run_id::text, schedule_id::text, due_at,
       provider, secret_key, old_ref, new_ref, error,
       prepared_new_ref, prepared_error, tick_idempotency_key,
       terminal_event_id, status,
       privacy_rewrite_version, privacy_subject_ref,
       privacy_operation_id, privacy_event_id
  FROM secret_rotation_schedule_commands
 WHERE tenant_id = $1`

func scanSecretRotationSchedulePrivacyCommand(row rowScanner) (secretRotationSchedulePrivacyCommand, error) {
	var command secretRotationSchedulePrivacyCommand
	err := row.Scan(
		&command.runID, &command.scheduleID, &command.dueAt,
		&command.provider, &command.key, &command.oldRef,
		&command.newRef, &command.errorText,
		&command.preparedNewRef, &command.preparedError, &command.tickKey,
		&command.terminalEventID, &command.status,
		&command.privacyRewriteVersion, &command.privacySubjectRef,
		&command.privacyOperationID, &command.privacyEventID,
	)
	return command, err
}

func loadSecretRotationSchedulePrivacyCommandsTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) ([]secretRotationSchedulePrivacyCommand, error) {
	rows, err := tx.Query(ctx, secretRotationSchedulePrivacyCommandSelect+`
		 ORDER BY run_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []secretRotationSchedulePrivacyCommand
	for rows.Next() {
		command, err := scanSecretRotationSchedulePrivacyCommand(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, command)
	}
	return out, rows.Err()
}

func secretRotationSchedulePrivacyTickMatches(
	tick SecretRotationScheduleTick,
	subject string,
) (bool, error) {
	if err := validateSecretRotationSchedulePrivacyStamp(
		tick.PrivacyRewriteVersion, tick.PrivacySubjectRef,
		tick.PrivacyOperationID, tick.PrivacyEventID,
	); err != nil {
		return false, err
	}
	if tick.CurrentSchedule != nil {
		_, providerChanged := rewriteSecretRotationSchedulePrivacySubjectToken(
			tick.CurrentSchedule.Provider, subject, "")
		_, keyChanged := rewriteSecretRotationSchedulePrivacySubjectToken(
			tick.CurrentSchedule.Key, subject, "")
		_, oldRefChanged := rewriteSecretRotationSchedulePrivacyOpaqueExact(
			tick.CurrentSchedule.OldRef, subject, "")
		if providerChanged || keyChanged || oldRefChanged {
			return true, nil
		}
	}
	for _, raw := range [][]byte{tick.Receipt, tick.TerminalBody} {
		if len(raw) == 0 {
			continue
		}
		_, changed, err := rewriteSecretRotationSchedulePrivacyReceipt(
			raw, subject, privacy.Placeholder(privacy.SubjectRef(tick.TenantID, subject)), false, "")
		if err != nil {
			return false, err
		}
		if changed {
			return true, nil
		}
	}
	return false, nil
}

func secretRotationSchedulePrivacyCommandMatches(
	command secretRotationSchedulePrivacyCommand,
	subject string,
) (bool, error) {
	if err := validateSecretRotationSchedulePrivacyStamp(
		command.privacyRewriteVersion, command.privacySubjectRef,
		command.privacyOperationID, command.privacyEventID,
	); err != nil {
		return false, err
	}
	_, providerChanged := rewriteSecretRotationSchedulePrivacySubjectToken(command.provider, subject, "")
	_, keyChanged := rewriteSecretRotationSchedulePrivacySubjectToken(command.key, subject, "")
	_, oldRefChanged := rewriteSecretRotationSchedulePrivacyOpaqueExact(command.oldRef, subject, "")
	_, newRefChanged := rewriteSecretRotationSchedulePrivacyOpaqueExact(command.newRef, subject, "")
	_, errorChanged := rewriteSecretRotationSchedulePrivacyFreeText(command.errorText, subject)
	_, preparedNewRefChanged := rewriteSecretRotationSchedulePrivacyOpaqueExact(command.preparedNewRef, subject, "")
	_, preparedErrorChanged := rewriteSecretRotationSchedulePrivacyFreeText(command.preparedError, subject)
	_, tickKeyChanged := rewriteSecretRotationSchedulePrivacySubjectToken(command.tickKey, subject, "")
	return providerChanged || keyChanged || oldRefChanged || newRefChanged || errorChanged ||
		preparedNewRefChanged || preparedErrorChanged || tickKeyChanged, nil
}

func secretRotationSchedulePrivacyTickRowMatches(
	row secretRotationSchedulePrivacyTickRow,
	subject string,
) bool {
	_, providerChanged := rewriteSecretRotationSchedulePrivacySubjectToken(row.provider, subject, "")
	_, keyChanged := rewriteSecretRotationSchedulePrivacySubjectToken(row.key, subject, "")
	_, oldRefChanged := rewriteSecretRotationSchedulePrivacyOpaqueExact(row.oldRef, subject, "")
	return providerChanged || keyChanged || oldRefChanged
}

func rewriteSecretRotationSchedulePrivacyReceipt(
	raw []byte,
	subject, placeholder string,
	closeReceiver bool,
	currentScheduleID string,
) ([]byte, bool, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil, false, fmt.Errorf("%w: scheduler receipt is invalid during privacy preparation",
			ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationSchedulePrivacyJSONUniqueKeys(raw); err != nil {
		return nil, false, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil || document == nil {
		return nil, false, fmt.Errorf("%w: scheduler receipt is not an object during privacy preparation",
			ErrSecretRotationScheduleTickConflict)
	}
	allowed := map[string]bool{
		"ran": true, "scanned": true, "runs": true, "deferred": true,
		"run_limit_reached": true, "scan_limit_reached": true,
		"complete": true, "partial": true,
		"failed_schedule_id": true, "system_error": true,
	}
	if err := rejectUnknownSecretRotationSchedulePrivacyJSON(
		document, allowed, "scheduler receipt"); err != nil {
		return nil, false, err
	}
	ran, err := requireSecretRotationSchedulePrivacyJSONInt(document, "ran")
	if err != nil || ran < 0 || ran > 50 {
		return nil, false, fmt.Errorf("%w: scheduler receipt ran is invalid", ErrSecretRotationScheduleTickConflict)
	}
	scanned, err := requireSecretRotationSchedulePrivacyJSONInt(document, "scanned")
	if err != nil || scanned < ran || scanned > 500 {
		return nil, false, fmt.Errorf("%w: scheduler receipt scanned is invalid", ErrSecretRotationScheduleTickConflict)
	}
	for _, key := range []string{"run_limit_reached", "scan_limit_reached", "complete", "partial"} {
		if err := requireSecretRotationSchedulePrivacyJSONBool(document, key); err != nil {
			return nil, false, err
		}
	}
	var runs []json.RawMessage
	if err := json.Unmarshal(document["runs"], &runs); err != nil || runs == nil {
		return nil, false, fmt.Errorf("%w: scheduler receipt runs are invalid", ErrSecretRotationScheduleTickConflict)
	}
	var deferred []json.RawMessage
	if err := json.Unmarshal(document["deferred"], &deferred); err != nil || deferred == nil {
		return nil, false, fmt.Errorf("%w: scheduler receipt deferrals are invalid", ErrSecretRotationScheduleTickConflict)
	}
	changed := false
	for index, encoded := range runs {
		rewritten, itemChanged, err := rewriteSecretRotationSchedulePrivacyRun(encoded, subject, placeholder)
		if err != nil {
			return nil, false, err
		}
		if itemChanged {
			runs[index] = rewritten
			changed = true
		}
	}
	for index, encoded := range deferred {
		rewritten, itemChanged, err := rewriteSecretRotationSchedulePrivacyDeferred(encoded, subject, placeholder)
		if err != nil {
			return nil, false, err
		}
		if itemChanged {
			deferred[index] = rewritten
			changed = true
		}
	}
	if changed {
		document["runs"], err = json.Marshal(runs)
		if err != nil {
			return nil, false, err
		}
		document["deferred"], err = json.Marshal(deferred)
		if err != nil {
			return nil, false, err
		}
	}
	if value, ok := document["system_error"]; ok {
		fieldChanged, err := rewriteSecretRotationSchedulePrivacyFreeTextField(
			document, "system_error", value, subject)
		if err != nil {
			return nil, false, err
		}
		changed = changed || fieldChanged
	}
	if value, ok := document["failed_schedule_id"]; ok {
		if err := validateSecretRotationSchedulePrivacyUUID(value, "failed_schedule_id"); err != nil {
			return nil, false, err
		}
	}
	if closeReceiver {
		document["run_limit_reached"] = json.RawMessage("false")
		document["scan_limit_reached"] = json.RawMessage("false")
		document["complete"] = json.RawMessage("false")
		partial, err := json.Marshal(ran > 0 || len(deferred) > 0)
		if err != nil {
			return nil, false, err
		}
		document["partial"] = partial
		systemError, err := json.Marshal(secretRotationSchedulePrivacyClosedError)
		if err != nil {
			return nil, false, err
		}
		document["system_error"] = systemError
		if currentScheduleID != "" {
			parsed, parseErr := uuid.Parse(currentScheduleID)
			if parseErr != nil || parsed.String() != currentScheduleID {
				return nil, false, fmt.Errorf("%w: scheduler privacy current schedule id is invalid",
					ErrSecretRotationScheduleTickConflict)
			}
			failedID, err := json.Marshal(currentScheduleID)
			if err != nil {
				return nil, false, err
			}
			document["failed_schedule_id"] = failedID
		}
		changed = true
	}
	if !changed {
		return append([]byte(nil), raw...), false, nil
	}
	rewritten, err := json.Marshal(document)
	if err != nil {
		return nil, false, err
	}
	return rewritten, true, nil
}

func rewriteSecretRotationSchedulePrivacyRun(
	raw []byte,
	subject, placeholder string,
) ([]byte, bool, error) {
	var document map[string]json.RawMessage
	if !json.Valid(raw) || validateSecretRotationSchedulePrivacyJSONUniqueKeys(raw) != nil ||
		json.Unmarshal(raw, &document) != nil || document == nil {
		return nil, false, fmt.Errorf("%w: scheduler run receipt is invalid", ErrSecretRotationScheduleTickConflict)
	}
	allowed := map[string]bool{
		"schedule_id": true, "run_id": true, "due_at": true,
		"status": true, "rotation": true,
		"error": true, "ran_at": true, "reconciled": true,
	}
	if err := rejectUnknownSecretRotationSchedulePrivacyJSON(document, allowed, "scheduler run receipt"); err != nil {
		return nil, false, err
	}
	for _, key := range []string{"schedule_id", "run_id"} {
		if err := validateSecretRotationSchedulePrivacyUUID(document[key], key); err != nil {
			return nil, false, err
		}
	}
	// v2 terminal HTTP receipts predate due_at. They remain privacy-rewritable
	// evidence after migration 0159. New v3 progress still requires the field:
	// validateSecretRotationScheduleTickProgress compares the decoded value with
	// the immutable snapshot's exact due edge before accepting an append.
	if value, ok := document["due_at"]; ok {
		if err := validateSecretRotationSchedulePrivacyTime(value, "due_at"); err != nil {
			return nil, false, err
		}
	}
	status, err := requireSecretRotationSchedulePrivacyJSONString(document, "status")
	if err != nil || !secretRotationScheduleTerminalStatus(status) {
		return nil, false, fmt.Errorf("%w: scheduler run receipt status is invalid", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationSchedulePrivacyTime(document["ran_at"], "ran_at"); err != nil {
		return nil, false, err
	}
	if err := requireSecretRotationSchedulePrivacyJSONBool(document, "reconciled"); err != nil {
		return nil, false, err
	}
	rotation, rotationChanged, err := rewriteSecretRotationSchedulePrivacyRotation(
		document["rotation"], subject, placeholder)
	if err != nil {
		return nil, false, err
	}
	changed := rotationChanged
	if rotationChanged {
		document["rotation"] = rotation
	}
	if value, ok := document["error"]; ok {
		fieldChanged, err := rewriteSecretRotationSchedulePrivacyFreeTextField(
			document, "error", value, subject)
		if err != nil {
			return nil, false, err
		}
		changed = changed || fieldChanged
	}
	if !changed {
		return append([]byte(nil), raw...), false, nil
	}
	rewritten, err := json.Marshal(document)
	return rewritten, true, err
}

func rewriteSecretRotationSchedulePrivacyRotation(
	raw []byte,
	subject, placeholder string,
) ([]byte, bool, error) {
	var document map[string]json.RawMessage
	if !json.Valid(raw) || validateSecretRotationSchedulePrivacyJSONUniqueKeys(raw) != nil ||
		json.Unmarshal(raw, &document) != nil || document == nil {
		return nil, false, fmt.Errorf("%w: scheduler rotation receipt is invalid", ErrSecretRotationScheduleTickConflict)
	}
	allowed := map[string]bool{
		"key": true, "old_ref": true, "new_ref": true,
		"completed": true, "queued": true, "rolled_back": true,
		"rollback_attempted": true, "rollback_failed": true,
		"rollback_error": true, "failed_phase": true, "error": true,
	}
	if err := rejectUnknownSecretRotationSchedulePrivacyJSON(document, allowed, "scheduler rotation receipt"); err != nil {
		return nil, false, err
	}
	changed := false
	for _, key := range []string{"key", "old_ref", "new_ref"} {
		value, ok := document[key]
		if !ok {
			return nil, false, fmt.Errorf("%w: scheduler rotation receipt lacks %s",
				ErrSecretRotationScheduleTickConflict, key)
		}
		var fieldChanged bool
		var err error
		if key == "key" {
			fieldChanged, err = rewriteSecretRotationSchedulePrivacySubjectTokenField(
				document, key, value, subject, placeholder)
		} else {
			fieldChanged, err = rewriteSecretRotationSchedulePrivacyOpaqueExactField(
				document, key, value, subject, placeholder)
		}
		if err != nil {
			return nil, false, err
		}
		changed = changed || fieldChanged
	}
	for _, key := range []string{"completed", "queued", "rolled_back", "rollback_attempted", "rollback_failed"} {
		if err := requireSecretRotationSchedulePrivacyJSONBool(document, key); err != nil {
			return nil, false, err
		}
	}
	for _, key := range []string{"rollback_error", "error"} {
		if value, ok := document[key]; ok {
			fieldChanged, err := rewriteSecretRotationSchedulePrivacyFreeTextField(
				document, key, value, subject)
			if err != nil {
				return nil, false, err
			}
			changed = changed || fieldChanged
		}
	}
	if value, ok := document["failed_phase"]; ok {
		phase, err := decodeSecretRotationSchedulePrivacyJSONString(value, "failed_phase")
		if err != nil {
			return nil, false, err
		}
		switch phase {
		case "", "stage", "cutover", "verify", "retire", "delivery", "provider":
		default:
			return nil, false, fmt.Errorf("%w: scheduler rotation failed phase is invalid",
				ErrSecretRotationScheduleTickConflict)
		}
	}
	if !changed {
		return append([]byte(nil), raw...), false, nil
	}
	rewritten, err := json.Marshal(document)
	return rewritten, true, err
}

func rewriteSecretRotationSchedulePrivacyDeferred(
	raw []byte,
	subject, placeholder string,
) ([]byte, bool, error) {
	var document map[string]json.RawMessage
	if !json.Valid(raw) || validateSecretRotationSchedulePrivacyJSONUniqueKeys(raw) != nil ||
		json.Unmarshal(raw, &document) != nil || document == nil {
		return nil, false, fmt.Errorf("%w: scheduler deferral receipt is invalid", ErrSecretRotationScheduleTickConflict)
	}
	allowed := map[string]bool{"schedule_id": true, "reason": true, "due_at": true, "error": true}
	if err := rejectUnknownSecretRotationSchedulePrivacyJSON(document, allowed, "scheduler deferral receipt"); err != nil {
		return nil, false, err
	}
	if err := validateSecretRotationSchedulePrivacyUUID(document["schedule_id"], "schedule_id"); err != nil {
		return nil, false, err
	}
	reason, err := requireSecretRotationSchedulePrivacyJSONString(document, "reason")
	if err != nil {
		return nil, false, err
	}
	switch reason {
	case "approval_pending", "command_in_flight", "command_claimed", "config_revision_unanchored":
	default:
		return nil, false, fmt.Errorf("%w: scheduler deferral reason is invalid", ErrSecretRotationScheduleTickConflict)
	}
	if err := validateSecretRotationSchedulePrivacyTime(document["due_at"], "due_at"); err != nil {
		return nil, false, err
	}
	changed := false
	if value, ok := document["error"]; ok {
		changed, err = rewriteSecretRotationSchedulePrivacyFreeTextField(
			document, "error", value, subject)
		if err != nil {
			return nil, false, err
		}
	}
	if !changed {
		return append([]byte(nil), raw...), false, nil
	}
	rewritten, err := json.Marshal(document)
	return rewritten, true, err
}

func rejectUnknownSecretRotationSchedulePrivacyJSON(
	document map[string]json.RawMessage,
	allowed map[string]bool,
	label string,
) error {
	for key := range document {
		if allowed[key] {
			continue
		}
		return fmt.Errorf("%w: %s has unsupported field %q",
			ErrSecretRotationScheduleTickConflict, label, key)
	}
	return nil
}

func validateSecretRotationSchedulePrivacyJSONUniqueKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateSecretRotationSchedulePrivacyJSONValueTokens(decoder); err != nil {
		return fmt.Errorf("%w: scheduler receipt duplicate-key preflight: %v",
			ErrSecretRotationScheduleTickConflict, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: scheduler receipt has trailing JSON tokens",
			ErrSecretRotationScheduleTickConflict)
	}
	return nil
}

func validateSecretRotationSchedulePrivacyJSONValueTokens(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateSecretRotationSchedulePrivacyJSONValueTokens(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object did not end cleanly")
		}
	case '[':
		for decoder.More() {
			if err := validateSecretRotationSchedulePrivacyJSONValueTokens(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array did not end cleanly")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func rewriteSecretRotationSchedulePrivacySubjectTokenField(
	document map[string]json.RawMessage,
	key string,
	raw json.RawMessage,
	subject, placeholder string,
) (bool, error) {
	value, err := decodeSecretRotationSchedulePrivacyJSONString(raw, key)
	if err != nil {
		return false, err
	}
	rewritten, changed := rewriteSecretRotationSchedulePrivacySubjectToken(value, subject, placeholder)
	if !changed {
		return false, nil
	}
	document[key], err = json.Marshal(rewritten)
	return true, err
}

func rewriteSecretRotationSchedulePrivacyOpaqueExactField(
	document map[string]json.RawMessage,
	key string,
	raw json.RawMessage,
	subject, placeholder string,
) (bool, error) {
	value, err := decodeSecretRotationSchedulePrivacyJSONString(raw, key)
	if err != nil {
		return false, err
	}
	rewritten, changed := rewriteSecretRotationSchedulePrivacyOpaqueExact(value, subject, placeholder)
	if !changed {
		return false, nil
	}
	document[key], err = json.Marshal(rewritten)
	return true, err
}

func rewriteSecretRotationSchedulePrivacyFreeTextField(
	document map[string]json.RawMessage,
	key string,
	raw json.RawMessage,
	subject string,
) (bool, error) {
	value, err := decodeSecretRotationSchedulePrivacyJSONString(raw, key)
	if err != nil {
		return false, err
	}
	rewritten, changed := rewriteSecretRotationSchedulePrivacyFreeText(value, subject)
	if !changed {
		return false, nil
	}
	document[key], err = json.Marshal(rewritten)
	return true, err
}

// subject_token is the policy for provider and secret-key names. An exact
// subject occurrence is rewritten only when both neighboring runes are
// delimiters. This preserves unrelated short-subject collisions such as the
// subject "a" inside "vault" while still handling connector:a and /a/.
func rewriteSecretRotationSchedulePrivacySubjectToken(
	value, subject, placeholder string,
) (string, bool) {
	if value == "" || subject == "" {
		return value, false
	}
	var rewritten strings.Builder
	lastWritten := 0
	searchFrom := 0
	changed := false
	for searchFrom <= len(value)-len(subject) {
		relative := strings.Index(value[searchFrom:], subject)
		if relative < 0 {
			break
		}
		index := searchFrom + relative
		end := index + len(subject)
		if secretRotationSchedulePrivacySubjectOverlapsPlaceholder(value, index, end) {
			searchFrom = end
			continue
		}
		leftBoundary := index == 0
		if !leftBoundary {
			left, _ := utf8.DecodeLastRuneInString(value[:index])
			leftBoundary = !secretRotationSchedulePrivacyTokenRune(left)
		}
		rightBoundary := end == len(value)
		if !rightBoundary {
			right, _ := utf8.DecodeRuneInString(value[end:])
			rightBoundary = !secretRotationSchedulePrivacyTokenRune(right)
		}
		if leftBoundary && rightBoundary {
			rewritten.WriteString(value[lastWritten:index])
			rewritten.WriteString(placeholder)
			lastWritten = end
			changed = true
		}
		searchFrom = end
	}
	if !changed {
		return value, false
	}
	rewritten.WriteString(value[lastWritten:])
	return rewritten.String(), true
}

func secretRotationSchedulePrivacySubjectOverlapsPlaceholder(
	value string,
	subjectStart, subjectEnd int,
) bool {
	const prefix = "erased:"
	const digestLength = 12
	searchFrom := 0
	for searchFrom < len(value) {
		relative := strings.Index(value[searchFrom:], prefix)
		if relative < 0 {
			return false
		}
		start := searchFrom + relative
		digestStart := start + len(prefix)
		end := digestStart + digestLength
		valid := end <= len(value) && validSecretRotationSchedulePrivacyPlaceholderDigest(value[digestStart:end])
		if valid && start > 0 {
			left, _ := utf8.DecodeLastRuneInString(value[:start])
			valid = !secretRotationSchedulePrivacyTokenRune(left)
		}
		if valid && end < len(value) {
			right, _ := utf8.DecodeRuneInString(value[end:])
			valid = !secretRotationSchedulePrivacyTokenRune(right)
		}
		if valid && subjectStart < end && subjectEnd > start {
			return true
		}
		searchFrom = start + len(prefix)
	}
	return false
}

func validSecretRotationSchedulePrivacyPlaceholderDigest(value string) bool {
	if len(value) != 12 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func secretRotationSchedulePrivacyTokenRune(value rune) bool {
	return unicode.IsLetter(value) || unicode.IsDigit(value) ||
		value == '_' || value == '-' || value == '.' || value == '@'
}

// opaque_exact is the policy for provider-owned version references. They are
// not prose and must never be spliced: only a whole-value subject is rewritten.
func rewriteSecretRotationSchedulePrivacyOpaqueExact(
	value, subject, placeholder string,
) (string, bool) {
	if subject != "" && value == subject {
		return placeholder, true
	}
	return value, false
}

// free_text_clear is the policy for diagnostic text. Retaining surrounding
// prose risks leaking or changing the meaning, so the entire field is replaced
// by one fixed, non-subject marker when it contains the subject.
func rewriteSecretRotationSchedulePrivacyFreeText(value, subject string) (string, bool) {
	if subject != "" && strings.Contains(value, subject) {
		return secretRotationSchedulePrivacyClearedFreeText, true
	}
	return value, false
}

func requireSecretRotationSchedulePrivacyJSONString(
	document map[string]json.RawMessage,
	key string,
) (string, error) {
	raw, ok := document[key]
	if !ok {
		return "", fmt.Errorf("%w: scheduler receipt lacks %s",
			ErrSecretRotationScheduleTickConflict, key)
	}
	return decodeSecretRotationSchedulePrivacyJSONString(raw, key)
}

func decodeSecretRotationSchedulePrivacyJSONString(raw json.RawMessage, key string) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return "", fmt.Errorf("%w: scheduler receipt %s is not a string",
			ErrSecretRotationScheduleTickConflict, key)
	}
	return value, nil
}

func requireSecretRotationSchedulePrivacyJSONInt(
	document map[string]json.RawMessage,
	key string,
) (int, error) {
	raw, ok := document[key]
	if !ok {
		return 0, fmt.Errorf("%w: scheduler receipt lacks %s",
			ErrSecretRotationScheduleTickConflict, key)
	}
	var value int
	if json.Unmarshal(raw, &value) != nil {
		return 0, fmt.Errorf("%w: scheduler receipt %s is not an integer",
			ErrSecretRotationScheduleTickConflict, key)
	}
	return value, nil
}

func requireSecretRotationSchedulePrivacyJSONBool(
	document map[string]json.RawMessage,
	key string,
) error {
	raw, ok := document[key]
	if !ok {
		return fmt.Errorf("%w: scheduler receipt lacks %s",
			ErrSecretRotationScheduleTickConflict, key)
	}
	var value bool
	if json.Unmarshal(raw, &value) != nil {
		return fmt.Errorf("%w: scheduler receipt %s is not a boolean",
			ErrSecretRotationScheduleTickConflict, key)
	}
	return nil
}

func validateSecretRotationSchedulePrivacyUUID(raw json.RawMessage, key string) error {
	value, err := decodeSecretRotationSchedulePrivacyJSONString(raw, key)
	if err != nil {
		return err
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return fmt.Errorf("%w: scheduler receipt %s is not a canonical UUID",
			ErrSecretRotationScheduleTickConflict, key)
	}
	return nil
}

func validateSecretRotationSchedulePrivacyTime(raw json.RawMessage, key string) error {
	value, err := decodeSecretRotationSchedulePrivacyJSONString(raw, key)
	if err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return fmt.Errorf("%w: scheduler receipt %s is not a timestamp",
			ErrSecretRotationScheduleTickConflict, key)
	}
	return nil
}

func validateSecretRotationSchedulePrivacyStamp(
	version int,
	retainedSubjectRef, retainedOperationID, retainedEventID string,
) error {
	if version == 0 && retainedSubjectRef == "" && retainedOperationID == "" && retainedEventID == "" {
		return nil
	}
	if version == SecretRotationSchedulePrivacyRewriteVersion &&
		validSecretRotationSchedulePrivacySubjectRef(retainedSubjectRef) &&
		validSecretRotationSchedulePrivacyIdentity(retainedOperationID) &&
		validSecretRotationSchedulePrivacyIdentity(retainedEventID) {
		return nil
	}
	return fmt.Errorf("%w: scheduler privacy stamp has a partial or invalid shape",
		ErrSecretRotationScheduleCommandConflict)
}

func authorizeSecretRotationSchedulePrivacyRestampTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	version int,
	retainedSubjectRef, retainedOperationID, retainedEventID,
	subjectRef, operationID, eventID string,
) error {
	if err := validateSecretRotationSchedulePrivacyStamp(
		version, retainedSubjectRef, retainedOperationID, retainedEventID); err != nil {
		return err
	}
	if version == 0 || (retainedSubjectRef == subjectRef &&
		retainedOperationID == operationID && retainedEventID == eventID) {
		return nil
	}
	var priorComplete bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1
		      FROM privacy_subject_erasure_operations
		     WHERE tenant_id = $1 AND operation_id = $2
		       AND event_id = $3 AND subject_ref = $4
		)`, tenantID, retainedOperationID, retainedEventID, retainedSubjectRef).Scan(&priorComplete); err != nil {
		return err
	}
	if !priorComplete {
		return fmt.Errorf("%w: prior scheduler privacy stamp has no completed erasure operation",
			ErrSecretRotationScheduleCommandConflict)
	}
	return nil
}

func validSecretRotationSchedulePrivacySubjectRef(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validSecretRotationSchedulePrivacyIdentity(value string) bool {
	return strings.HasPrefix(value, "sha256:") &&
		validSecretRotationSchedulePrivacySubjectRef(strings.TrimPrefix(value, "sha256:"))
}

func secretRotationSchedulePrivacyOuterAuthorityRef(tenantID, rawKey string) string {
	return privacy.SubjectRef(tenantID, "secret-rotation-schedule-tick\x1f"+rawKey)
}

func secretRotationSchedulePrivacyOuterReplacementKey(authorityRef string) string {
	return "privacy-scheduler:" + authorityRef
}

func secretRotationSchedulePrivacyOuterRequirementForTick(
	tenantID, subject, placeholder string,
	outer secretRotationSchedulePrivacyOuter,
	tick SecretRotationScheduleTick,
) (SecretRotationSchedulePrivacyOuterRequirement, bool, error) {
	requirement := SecretRotationSchedulePrivacyOuterRequirement{
		AuthorityRef:              secretRotationSchedulePrivacyOuterAuthorityRef(tenantID, outer.key),
		RequestBinding:            outer.requestBinding,
		Status:                    outer.status,
		ResultCodec:               outer.resultCodec,
		ReplacementIdempotencyKey: outer.key,
	}
	_, requirement.RawKeyTokenMatch = rewriteSecretRotationSchedulePrivacySubjectToken(
		outer.key, subject, "")
	if requirement.RawKeyTokenMatch {
		requirement.ReplacementIdempotencyKey =
			secretRotationSchedulePrivacyOuterReplacementKey(requirement.AuthorityRef)
	}
	if outer.status == "completed" {
		if tick.Phase != "terminal" || tick.TerminalHTTPStatus == nil ||
			len(tick.TerminalBody) == 0 || outer.resultCodec == "" || len(outer.result) == 0 {
			return requirement, false, fmt.Errorf(
				"%w: completed outer authority lacks exact terminal tick/result evidence",
				ErrSecretRotationScheduleTickConflict)
		}
		requirement.TerminalHTTPStatus = *tick.TerminalHTTPStatus
		requirement.OriginalTerminalBody = append([]byte(nil), tick.TerminalBody...)
		rewritten, changed, err := rewriteSecretRotationSchedulePrivacyReceipt(
			tick.TerminalBody, subject, placeholder, false, "")
		if err != nil {
			return requirement, false, err
		}
		if changed {
			requirement.TerminalBodyMatch = true
			requirement.TerminalHTTPStatus = *tick.TerminalHTTPStatus
			requirement.RewrittenTerminalBody = rewritten
		}
	} else if tick.Phase == "terminal" || tick.TerminalHTTPStatus != nil || len(tick.TerminalBody) != 0 {
		return requirement, false, fmt.Errorf(
			"%w: bound outer authority disagrees with terminal tick",
			ErrSecretRotationScheduleTickConflict)
	}
	return requirement, requirement.RawKeyTokenMatch || requirement.TerminalBodyMatch, nil
}

func verifySecretRotationSchedulePrivacyOuterAcknowledgementTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, rawKey string,
	outer secretRotationSchedulePrivacyOuter,
	requirement SecretRotationSchedulePrivacyOuterRequirement,
	ack SecretRotationSchedulePrivacyOuterAcknowledgement,
) error {
	if ack.AuthorityRef != requirement.AuthorityRef ||
		ack.RequestBinding != requirement.RequestBinding ||
		ack.OriginalResultCodec != requirement.ResultCodec ||
		ack.ResolvedIdempotencyKey != requirement.ReplacementIdempotencyKey ||
		ack.ResolvedIdempotencyKey == "" {
		return fmt.Errorf("%w: scheduler outer privacy acknowledgement differs from requirement",
			ErrSecretRotationScheduleTickConflict)
	}
	if requirement.TerminalBodyMatch {
		if ack.ResolvedResultCodec == "" || len(ack.ProtectedResult) == 0 {
			return fmt.Errorf("%w: scheduler outer privacy result was not protected",
				ErrSecretRotationScheduleTickConflict)
		}
	} else if outer.status == "completed" {
		// A key-only rewrite must still re-protect completed bytes because the
		// production envelope authenticates the idempotency key as AAD.
		if ack.ResolvedResultCodec == "" || len(ack.ProtectedResult) == 0 {
			return fmt.Errorf("%w: scheduler outer rekey did not re-protect its result",
				ErrSecretRotationScheduleTickConflict)
		}
	} else if ack.ResolvedResultCodec != outer.resultCodec || len(ack.ProtectedResult) != 0 {
		return fmt.Errorf("%w: bound scheduler privacy rekey invented result authority",
			ErrSecretRotationScheduleTickConflict)
	}
	var status, binding, codec string
	var protected []byte
	if err := tx.QueryRow(ctx,
		`SELECT status, request_binding, result_codec, result
		   FROM idempotency_keys
		  WHERE tenant_id = $1 AND key = $2
		  FOR UPDATE`, tenantID, ack.ResolvedIdempotencyKey).Scan(
		&status, &binding, &codec, &protected); err != nil {
		return fmt.Errorf("store: verify resolved scheduler outer authority: %w", err)
	}
	if status != outer.status || binding != outer.requestBinding || codec != ack.ResolvedResultCodec {
		return fmt.Errorf("%w: resolved scheduler outer row changed immutable authority",
			ErrSecretRotationScheduleTickConflict)
	}
	if outer.status == "completed" {
		if !bytes.Equal(protected, ack.ProtectedResult) {
			return fmt.Errorf("%w: resolved scheduler outer row differs from protected acknowledgement",
				ErrSecretRotationScheduleTickConflict)
		}
	} else if len(protected) != 0 || len(outer.result) != 0 {
		return fmt.Errorf("%w: bound scheduler outer rekey retained result bytes",
			ErrSecretRotationScheduleTickConflict)
	}
	if requirement.RawKeyTokenMatch {
		var oldExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM idempotency_keys WHERE tenant_id = $1 AND key = $2
			)`, tenantID, rawKey).Scan(&oldExists); err != nil {
			return err
		}
		if oldExists {
			return fmt.Errorf("%w: raw scheduler outer key survived acknowledged rekey",
				ErrSecretRotationScheduleTickConflict)
		}
	}
	return nil
}

func secretRotationSchedulePrivacyEdge(scheduleID string, dueAt time.Time) string {
	return scheduleID + "\x00" + dueAt.UTC().Format(time.RFC3339Nano)
}

func sortedSecretRotationSchedulePrivacyKeys(selected map[string]bool) []string {
	keys := make([]string, 0, len(selected))
	for key, include := range selected {
		if include {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func resetSecretRotationSchedulePrivacyRole(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "RESET ROLE"); err != nil {
		return fmt.Errorf("store: scheduler privacy preparation assume owner: %w", err)
	}
	return nil
}

func restoreSecretRotationSchedulePrivacyRole(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+appRole); err != nil {
		return fmt.Errorf("store: scheduler privacy preparation restore application role: %w", err)
	}
	return nil
}
