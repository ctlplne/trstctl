// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

const SecretRotationScheduleReferenceReviewRequired = "reference_review_required"

// SecretRotationScheduleTerminalReferenceSource identifies the version and
// original bytes of a terminal result with a protected reference-safe view.
func SecretRotationScheduleTerminalReferenceSource(original []byte) string {
	return "v1:" + crypto.SHA256Hex(original)
}

func SecretRotationScheduleHasNamespacedReference(provider string) bool {
	for _, prefix := range []string{"connector:", "dynamic-lease:"} {
		if suffix, ok := strings.CutPrefix(provider, prefix); ok && suffix != "" {
			return true
		}
	}
	return false
}

// SecretRotationScheduleReferenceCanSnapshot mirrors the eligibility check
// in the snapshot transaction. A native legacy provider can retain its
// ordinary reference when the reference has no hosted binding delimiter.
func SecretRotationScheduleReferenceCanSnapshot(schedule SecretRotationSchedule, legacyNativeProviders []string) bool {
	return schedule.ReferenceProviderType != "" || schedule.OldRef == "none" ||
		SecretRotationScheduleHasNamespacedReference(schedule.Provider) ||
		(slices.Contains(legacyNativeProviders, schedule.Provider) && !strings.Contains(schedule.OldRef, "/"))
}

// SecretRotationScheduleReferenceView removes unproved historical references
// from metadata. It never changes the actual schedule or a retained receipt.
func SecretRotationScheduleReferenceView(schedule SecretRotationSchedule) SecretRotationSchedule {
	if schedule.ReferenceViewVersion == 1 || SecretRotationScheduleHasNamespacedReference(schedule.Provider) ||
		schedule.ReferenceProviderType == SecretRotationScheduleNativeReference {
		return schedule
	}
	if schedule.ReferenceProviderType == "" {
		if schedule.OldRef != "none" {
			schedule.OldRef = ""
		}
		schedule.LastNewRef = ""
	} else if schedule.LastNewRef != schedule.OldRef {
		// A last-run result can predate the current approved revision.
		schedule.LastNewRef = ""
	}
	return schedule
}

// RenderSecretRotationScheduleTickReferenceViewTx uses only the immutable
// snapshot for this retained tick. Child command collection and live provider
// configuration cannot change the resulting body.
func RenderSecretRotationScheduleTickReferenceViewTx(
	ctx context.Context, tx pgx.Tx, tenantID, tickKey string, raw []byte,
) ([]byte, bool, error) {
	// The privacy owner also renders exact historical receipts before erasing
	// their free text. The runtime validates its closed error vocabulary at
	// its original receipt boundary before calling this view.
	receipt, err := decodeSecretRotationScheduleTickReceiptShape(raw)
	if err != nil {
		return nil, false, err
	}
	if len(receipt.Runs) == 0 {
		return raw, false, nil
	}
	type snapshotReference struct {
		dueAt        time.Time
		provider     string
		providerType string
	}
	snapshots := make(map[string]snapshotReference)
	rows, err := tx.Query(ctx, `SELECT r.schedule_id::text, r.due_at, r.provider, r.reference_provider_type
		FROM secret_rotation_schedule_tick_rows r
		JOIN secret_rotation_schedule_ticks t ON t.tenant_id = r.tenant_id AND t.idempotency_key = r.idempotency_key
		    AND t.identity_version = r.identity_version AND t.tenant_registration_event_id = r.tenant_registration_event_id
		    AND t.tenant_registration_event_sequence = r.tenant_registration_event_sequence
		WHERE r.tenant_id = $1 AND r.idempotency_key = $2`, tenantID, tickKey)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		var id string
		var source snapshotReference
		if err := rows.Scan(&id, &source.dueAt, &source.provider, &source.providerType); err != nil {
			rows.Close()
			return nil, false, err
		}
		snapshots[id] = source
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	changed := false
	for i, rawRun := range receipt.Runs {
		var run map[string]json.RawMessage
		var identity struct {
			ScheduleID string    `json:"schedule_id"`
			DueAt      time.Time `json:"due_at"`
		}
		if err := json.Unmarshal(rawRun, &identity); err != nil {
			return nil, false, err
		}
		source, found := snapshots[identity.ScheduleID]
		sameEdge := found && identity.DueAt.Equal(source.dueAt)
		if sameEdge && source.providerType != "" {
			continue
		}
		if json.Unmarshal(rawRun, &run) != nil || run == nil {
			return nil, false, fmt.Errorf("%w: retained reference view has invalid run metadata", ErrSecretRotationScheduleTickConflict)
		}
		var rotation map[string]json.RawMessage
		if json.Unmarshal(run["rotation"], &rotation) != nil || rotation == nil {
			return nil, false, fmt.Errorf("%w: retained reference view has no rotation result", ErrSecretRotationScheduleTickConflict)
		}
		runChanged := false
		for _, field := range []string{"old_ref", "new_ref"} {
			var value string
			if encoded, exists := rotation[field]; exists && json.Unmarshal(encoded, &value) != nil {
				return nil, false, fmt.Errorf("%w: retained rotation reference is not a string", ErrSecretRotationScheduleTickConflict)
			}
			if value == "" || field == "old_ref" && value == "none" {
				continue
			}
			// A cadence can chain a newer lease or version than the snapshot's
			// original predecessor. Neither closed shape can hold a hosted binding.
			if sameEdge && retainedNamespacedRotationReference(source.provider, value) {
				continue
			}
			rotation[field] = json.RawMessage(`""`)
			runChanged = true
		}
		if !runChanged {
			continue
		}
		changed = true
		run["rotation"], err = json.Marshal(rotation)
		if err != nil {
			return nil, false, err
		}
		receipt.Runs[i], err = json.Marshal(run)
		if err != nil {
			return nil, false, err
		}
	}
	if !changed {
		return raw, false, nil
	}
	result, err := json.Marshal(receipt)
	return result, true, err
}

func retainedNamespacedRotationReference(provider, value string) bool {
	if target, ok := strings.CutPrefix(provider, "connector:"); ok && target != "" {
		version, ok := strings.CutPrefix(value, "version:")
		n, err := strconv.Atoi(version)
		return ok && err == nil && n > 0
	}
	if target, ok := strings.CutPrefix(provider, "dynamic-lease:"); ok && target != "" {
		id, ok := strings.CutPrefix(value, "lease-")
		parsed, err := uuid.Parse(id)
		return ok && err == nil && parsed.String() == id
	}
	return false
}

func upgradeSecretRotationScheduleTickReferenceViewTx(ctx context.Context, tx pgx.Tx, tick *SecretRotationScheduleTick) error {
	if tick.ReferenceViewVersion != 0 {
		return validateSecretRotationScheduleTickReferenceViewTx(ctx, tx, *tick)
	}
	if len(tick.Receipt) == 0 || tick.Phase == "terminal" {
		return nil
	}
	if err := validateSecretRotationScheduleTickReceipt(tick.Receipt, tick.Ran, tick.Scanned, 0); err != nil {
		return err
	}
	body, changed, err := RenderSecretRotationScheduleTickReferenceViewTx(ctx, tx, tick.TenantID, tick.IdempotencyKey, tick.Receipt)
	if err != nil || !changed {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_ticks
		SET reference_view_version = 1, safe_receipt = $4::jsonb,
		    legacy_receipt_digest = $5, safe_prefix_digest = $6
		WHERE tenant_id = $1 AND idempotency_key = $2 AND request_binding = $3
		  AND reference_view_version = 0 AND receipt = $7::jsonb
		  AND owner_token = $8 AND owner_generation = $9`,
		tick.TenantID, tick.IdempotencyKey, tick.RequestBinding, body,
		crypto.SHA256Hex(tick.Receipt), crypto.SHA256Hex(body), tick.Receipt, tick.OwnerToken, tick.OwnerGeneration)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: rotation reference progress changed before its safe view", ErrSecretRotationScheduleTickConflict)
	}
	return scanSecretRotationScheduleTick(tx.QueryRow(ctx, secretRotationScheduleTickSelect+`
		AND idempotency_key = $2`, tick.TenantID, tick.IdempotencyKey), tick)
}

func validateSecretRotationScheduleTickReferenceViewTx(ctx context.Context, tx pgx.Tx, tick SecretRotationScheduleTick) error {
	if tick.ReferenceViewVersion != 1 || tick.LegacyReceiptDigest != crypto.SHA256Hex(tick.OriginalReceipt) {
		return fmt.Errorf("%w: retained rotation reference source digest differs", ErrSecretRotationScheduleTickConflict)
	}
	body, _, err := RenderSecretRotationScheduleTickReferenceViewTx(ctx, tx, tick.TenantID, tick.IdempotencyKey, tick.OriginalReceipt)
	if err != nil {
		return err
	}
	if tick.SafePrefixDigest != crypto.SHA256Hex(body) {
		return fmt.Errorf("%w: retained rotation reference view prefix digest differs", ErrSecretRotationScheduleTickConflict)
	}
	prefix, err := decodeSecretRotationScheduleTickReceipt(body)
	if err != nil {
		return err
	}
	active, err := decodeSecretRotationScheduleTickReceipt(tick.Receipt)
	if err != nil {
		return err
	}
	if prefix.Scanned > active.Scanned || prefix.Ran > active.Ran ||
		!secretRotationScheduleTickJSONPrefixEqual(prefix.Runs, active.Runs) ||
		!secretRotationScheduleTickJSONPrefixEqual(prefix.Deferred, active.Deferred) {
		return fmt.Errorf("%w: scheduler reference view changed its retained receipt prefix", ErrSecretRotationScheduleTickConflict)
	}
	return nil
}
