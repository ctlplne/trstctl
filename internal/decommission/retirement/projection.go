// SPDX-License-Identifier: BUSL-1.1

package retirement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// Projection owns the PostgreSQL retirement read model and the command's outbox
// producer. Applying RequestedV1 records both rows in one transaction (AN-6).
type Projection struct {
	store  *corestore.Store
	outbox *orchestrator.Outbox

	mu        sync.Mutex
	watermark uint64
}

func NewProjection(store *corestore.Store, outbox *orchestrator.Outbox) *Projection {
	if outbox == nil && store != nil {
		outbox = orchestrator.NewOutbox(store)
	}
	return &Projection{store: store, outbox: outbox}
}

func (p *Projection) Name() string { return "vdec.retirement" }

func (p *Projection) ReplayWatermark() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.watermark
}

func (p *Projection) Reset(ctx context.Context) error {
	if p == nil || p.store == nil {
		return ErrProjectionMissing
	}
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.ResetTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Projection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return ErrProjectionMissing
	}
	//trstctl:system-query — cross-tenant by design: a full event replay resets every tenant's derived VDEC retirement view (no tenant filter) before exact tenant-bound events, each scoped by its own tenant_id, repopulate it.
	if _, err := tx.Exec(ctx, `DELETE FROM decommission_retirements`); err != nil {
		return fmt.Errorf("vdec retirement: reset projection: %w", err)
	}
	p.mu.Lock()
	p.watermark = 0
	p.mu.Unlock()
	return nil
}

func (p *Projection) Apply(ctx context.Context, ev eventspec.Event) error {
	if p == nil || p.store == nil {
		return ErrProjectionMissing
	}
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.ApplyTx(ctx, tx, ev); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Projection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || p.outbox == nil || tx == nil {
		return ErrProjectionMissing
	}
	var err error
	switch ev.Type {
	case TypeRetirementRequested:
		err = p.applyRequestedTx(ctx, tx, ev)
	case TypeRetirementRetryRequested:
		err = p.applyRetryRequestedTx(ctx, tx, ev)
	case TypeRetirementRefused:
		err = p.applyRefusedTx(ctx, tx, ev)
	case TypeDestructionRecorded:
		err = p.applyRecordedTx(ctx, tx, ev)
	case projections.EventTenantOffboarded:
		// The core lifecycle transaction already selected this tenant under RLS.
		_, err = tx.Exec(ctx,
			`DELETE FROM decommission_retirements
			  WHERE tenant_id = $1`, ev.TenantID)
	}
	if err != nil {
		return err
	}
	p.advance(ev.Sequence)
	return nil
}

func (p *Projection) applyRetryRequestedTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	retry, err := DecodeRetryRequested(ev)
	if err != nil {
		return err
	}
	if retry.TenantID != ev.TenantID || ev.Actor == nil || ev.Actor.Subject != retry.Actor ||
		RetryEventID(retry.TenantID, retry.KeyID,
			retry.CommandEventID, retry.Attempts, retry.RequestKey, retry.Actor) != ev.ID {
		return fmt.Errorf("%w: retry event binding differs", ErrInvalidCommand)
	}
	var activeCommand, retirementStatus string
	if err := tx.QueryRow(ctx, `SELECT command_event_id,status FROM decommission_retirements
	    WHERE tenant_id=$1 AND key_id=$2 FOR UPDATE`, retry.TenantID, retry.KeyID).
		Scan(&activeCommand, &retirementStatus); err != nil {
		return fmt.Errorf("vdec retirement: load retry target: %w", err)
	}
	if activeCommand != retry.CommandEventID {
		return ErrCommandConflict
	}
	var destination, outboxKey, outboxStatus string
	var payload []byte
	var attempts, retryLimit int
	if err := tx.QueryRow(ctx, `SELECT destination,idempotency_key,payload,status,attempts,retry_attempt_limit
	    FROM outbox WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, retry.TenantID, retry.OutboxID).
		Scan(&destination, &outboxKey, &payload, &outboxStatus, &attempts, &retryLimit); err != nil {
		return fmt.Errorf("vdec retirement: load retry outbox row: %w", err)
	}
	if destination != DestinationRetirement || outboxKey != retry.CommandEventID ||
		crypto.SHA256Hex(payload) != retry.PayloadSHA256 {
		return ErrCommandConflict
	}
	if retirementStatus == StatusDestroyed || retirementStatus == StatusRefused ||
		outboxStatus == "delivered" || attempts > retry.Attempts {
		// A replay after the signer answered or consumed the granted attempt must
		// never reactivate the original row.
		return nil
	}
	if retirementStatus != StatusPending {
		return ErrRetryUnavailable
	}
	if attempts == retry.Attempts && outboxStatus == "pending" && retryLimit == attempts+1 {
		return nil // append succeeded and the same grant already projected
	}
	if attempts != retry.Attempts || outboxStatus != "failed" || retryLimit > attempts {
		return ErrRetryUnavailable
	}
	tag, err := tx.Exec(ctx, `UPDATE outbox SET status='pending',next_attempt_at=$4,
	    worker_id=NULL,lease_until=NULL,retry_attempt_limit=$3+1
	    WHERE tenant_id=$1 AND id=$2 AND attempts=$3 AND status='failed'`,
		retry.TenantID, retry.OutboxID, retry.Attempts, retry.RequestedAt)
	if err != nil {
		return fmt.Errorf("vdec retirement: project bounded retry: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrRetryUnavailable
	}
	return nil
}

func (p *Projection) ProjectsTenantLifecycle() {}

func (p *Projection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}

func (p *Projection) applyRequestedTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	requested, err := DecodeRequested(ev)
	if err != nil {
		return err
	}
	if requested.TenantID != ev.TenantID {
		return fmt.Errorf("%w: requested tenant mismatch", ErrInvalidCommand)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO decommission_retirements
		       (tenant_id, key_id, command_event_id, status, final_epoch, ledger_position,
		        refusal_record, destruction_record, record_event_id, updated_at)
		VALUES ($1, $2, $3, 'pending', $4, $5, NULL, NULL, '', now())
		ON CONFLICT (tenant_id, key_id) DO UPDATE
		   SET command_event_id = EXCLUDED.command_event_id,
		       status = 'pending',
		       final_epoch = EXCLUDED.final_epoch,
		       ledger_position = EXCLUDED.ledger_position,
		       refusal_record = NULL,
		       updated_at = now()
		 WHERE decommission_retirements.status IN ('pending', 'refused')
		   AND EXCLUDED.ledger_position > decommission_retirements.ledger_position`,
		requested.TenantID, requested.KeyID, ev.ID, requested.FinalEpoch, requested.LedgerPosition)
	if err != nil {
		return fmt.Errorf("vdec retirement: project requested command: %w", err)
	}
	var activeEventID, status string
	if err := tx.QueryRow(ctx, `
		SELECT command_event_id, status
		  FROM decommission_retirements
		 WHERE tenant_id = $1 AND key_id = $2`, requested.TenantID, requested.KeyID).
		Scan(&activeEventID, &status); err != nil {
		return fmt.Errorf("vdec retirement: read active command: %w", err)
	}
	if activeEventID != ev.ID || status != StatusPending {
		return nil
	}
	payload, err := json.Marshal(struct {
		CommandEventID string      `json:"command_event_id"`
		Requested      RequestedV1 `json:"requested"`
	}{CommandEventID: ev.ID, Requested: requested})
	if err != nil {
		return err
	}
	_, err = p.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
		TenantID: requested.TenantID, Destination: DestinationRetirement,
		IdempotencyKey: ev.ID, EffectLane: DestinationRetirement + ":" + requested.KeyID,
		RequiredAgentRole: "control_plane", Payload: payload,
	})
	if err != nil {
		return fmt.Errorf("vdec retirement: enqueue isolated-signer command: %w", err)
	}
	return nil
}

func (p *Projection) applyRefusedTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	refused, err := DecodeRefused(ev)
	if err != nil {
		return err
	}
	if refused.TenantID != ev.TenantID {
		return fmt.Errorf("%w: refusal tenant mismatch", ErrInvalidCommand)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE decommission_retirements
		   SET status = 'refused', refusal_record = $4, updated_at = now()
		 WHERE tenant_id = $1 AND key_id = $2 AND command_event_id = $3
		   AND status <> 'destroyed'`,
		refused.TenantID, refused.KeyID, refused.CommandEventID, refused.RefusalRecord)
	if err != nil {
		return fmt.Errorf("vdec retirement: project signed refusal: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return p.ensureSupersededTerminalTx(ctx, tx, refused.TenantID, refused.KeyID, refused.CommandEventID)
	}
	return nil
}

func (p *Projection) applyRecordedTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	recorded, err := DecodeRecorded(ev)
	if err != nil {
		return err
	}
	if recorded.TenantID != ev.TenantID {
		return fmt.Errorf("%w: record tenant mismatch", ErrInvalidCommand)
	}
	raw, err := recordBytes(recorded)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE decommission_retirements
		   SET status = 'destroyed', refusal_record = NULL,
		       destruction_record = $4, record_event_id = $5, updated_at = now()
		 WHERE tenant_id = $1 AND key_id = $2 AND command_event_id = $3`,
		recorded.TenantID, recorded.KeyID, recorded.CommandEventID, raw, ev.ID)
	if err != nil {
		return fmt.Errorf("vdec retirement: project destruction record: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: destruction record %s has no exact request", ErrProjectionMissing, ev.ID)
	}
	return nil
}

func (p *Projection) ensureSupersededTerminalTx(ctx context.Context, tx pgx.Tx, tenantID, keyID, commandEventID string) error {
	var activeID, status string
	err := tx.QueryRow(ctx, `
		SELECT command_event_id, status
		  FROM decommission_retirements
		 WHERE tenant_id = $1 AND key_id = $2`, tenantID, keyID).Scan(&activeID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrProjectionMissing
	}
	if err != nil {
		return err
	}
	if activeID != commandEventID || status == StatusDestroyed {
		return nil
	}
	return ErrProjectionMissing
}

func (p *Projection) Fetch(ctx context.Context, tenantID, keyID string) (State, bool, error) {
	if p == nil || p.store == nil {
		return State{}, false, ErrProjectionMissing
	}
	var out State
	found := false
	err := p.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT tenant_id::text, key_id, command_event_id, status, final_epoch,
			       ledger_position, COALESCE(refusal_record, ''::bytea),
			       COALESCE(destruction_record, ''::bytea)
			  FROM decommission_retirements
			 WHERE tenant_id = $1 AND key_id = $2`, tenantID, keyID).
			Scan(&out.TenantID, &out.KeyID, &out.CommandEventID, &out.Status,
				&out.FinalEpoch, &out.LedgerPosition, &out.RefusalRecord, &out.DestructionRecord)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			found = true
		}
		return err
	})
	return out, found, err
}

type DeliveryState struct {
	OutboxID     int64
	Status       string
	Attempts     int
	AttemptLimit int
}

func (p *Projection) FetchDelivery(ctx context.Context, tenantID, commandEventID string) (DeliveryState, bool, error) {
	if p == nil || p.store == nil || tenantID == "" || commandEventID == "" {
		return DeliveryState{}, false, ErrProjectionMissing
	}
	var out DeliveryState
	found := false
	err := p.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id,status,attempts,retry_attempt_limit
		  FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 AND destination=$3`,
			tenantID, commandEventID, DestinationRetirement).
			Scan(&out.OutboxID, &out.Status, &out.Attempts, &out.AttemptLimit)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			found = true
		}
		return err
	})
	return out, found, err
}

func (p *Projection) advance(sequence uint64) {
	p.mu.Lock()
	if sequence > p.watermark {
		p.watermark = sequence
	}
	p.mu.Unlock()
}

func recordBytes(recorded RecordedV1) ([]byte, error) {
	return json.Marshal(recorded.Record)
}
