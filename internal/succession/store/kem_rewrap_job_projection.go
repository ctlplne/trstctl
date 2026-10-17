// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/succession"
)

func (r *Repo) ApplyKEMRewrapRequestedEvent(ctx context.Context, ev eventspec.Event) error {
	return r.core.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return ApplyKEMRewrapRequestedEventTx(ctx, tx, ev)
	})
}

func (r *Repo) ApplyKEMRewrapCompletedStages(ctx context.Context, ev eventspec.Event) error {
	return r.core.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return ApplyKEMRewrapCompletedStagesTx(ctx, tx, ev)
	})
}

func ApplyKEMRewrapRequestedEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeKEMRewrapRequested || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas KEM job: invalid request source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	p, ok := decoded.(succession.KEMRewrapRequestedV1)
	if !ok {
		return nil
	}
	if p.TenantID != ev.TenantID || p.IdentityID == "" || strings.TrimSpace(p.IdentityID) != p.IdentityID ||
		p.RequestID == "" || p.PredecessorEpoch > math.MaxInt64 || len(p.RequestDigest) != 32 ||
		ev.ID != succession.KEMRewrapRequestEventID(p.TenantID, p.RequestID) ||
		succession.ValidateKEMRewrapStages(p.Stages) != nil {
		return errors.New("pcas KEM job: request source binding or stage list invalid")
	}
	for _, stage := range p.Stages {
		_, err := tx.Exec(ctx, `INSERT INTO pcas_rewrap_job
			(tenant_id, job_id, identity_id, predecessor_epoch, stage, total_stages,
			 completed_stages, status, source_sequence, request_digest)
			VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, 0, 'queued', $6, $7)
			ON CONFLICT DO NOTHING`, p.RequestID, p.IdentityID, int64(p.PredecessorEpoch),
			stage, len(p.Stages), int64(ev.Sequence), p.RequestDigest)
		if err != nil {
			return fmt.Errorf("pcas KEM job: project accepted stage: %w", err)
		}
		if err := checkKEMStage(ctx, tx, p.RequestID, p.IdentityID, p.PredecessorEpoch,
			stage, len(p.Stages), ev.Sequence, p.RequestDigest, true); err != nil {
			return err
		}
	}
	return checkKEMStageCount(ctx, tx, p.RequestID, len(p.Stages))
}

func ApplyKEMRewrapCompletedStagesTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeKEMRewrapRecorded || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas KEM job: invalid completed source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	p, ok := decoded.(succession.KEMRewrapRecordedV1)
	if !ok {
		return nil
	}
	if p.TenantID != ev.TenantID || p.IdentityID == "" || p.Epoch == 0 || p.Epoch > math.MaxInt64 ||
		p.RequestID == "" || len(p.RequestDigest) != 32 ||
		ev.ID != succession.KEMRewrapRecordEventID(p.TenantID, p.IdentityID, p.Epoch) ||
		succession.ValidateKEMRewrapStages(p.Stages) != nil {
		return errors.New("pcas KEM job: completed source binding or stage list invalid")
	}
	predecessorEpoch := p.Epoch - 1
	for _, stage := range p.Stages {
		_, err := tx.Exec(ctx, `UPDATE pcas_rewrap_job SET completed_stages = total_stages,
			status = 'complete', source_sequence = $6, updated_at = now()
			WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  AND job_id = $1 AND identity_id = $2 AND predecessor_epoch = $3
			  AND stage = $4 AND total_stages = $5 AND request_digest = $7
			  AND source_sequence > 0 AND source_sequence < $6`,
			p.RequestID, p.IdentityID, int64(predecessorEpoch), stage, len(p.Stages), int64(ev.Sequence), p.RequestDigest)
		if err != nil {
			return fmt.Errorf("pcas KEM job: project completed stage: %w", err)
		}
		if err := checkKEMStage(ctx, tx, p.RequestID, p.IdentityID, predecessorEpoch,
			stage, len(p.Stages), ev.Sequence, p.RequestDigest, false); err != nil {
			return err
		}
	}
	return checkKEMStageCount(ctx, tx, p.RequestID, len(p.Stages))
}

func checkKEMStage(ctx context.Context, tx pgx.Tx, requestID, identityID string,
	predecessorEpoch uint64, stage string, total int, sourceSequence uint64, requestDigest []byte, queuedOK bool) error {
	var gotIdentity, gotStage, gotStatus string
	var gotPredecessor, gotSource int64
	var gotTotal, gotCompleted int
	var gotDigest []byte
	err := tx.QueryRow(ctx, `SELECT identity_id, predecessor_epoch, stage, total_stages,
		completed_stages, status, source_sequence, request_digest FROM pcas_rewrap_job
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND job_id = $1 AND stage = $2`,
		requestID, stage).Scan(&gotIdentity, &gotPredecessor, &gotStage, &gotTotal,
		&gotCompleted, &gotStatus, &gotSource, &gotDigest)
	if err != nil || gotIdentity != identityID || gotStage != stage ||
		gotPredecessor < 0 || uint64(gotPredecessor) != predecessorEpoch || gotTotal != total || gotSource <= 0 ||
		!bytes.Equal(gotDigest, requestDigest) {
		return errors.New("pcas KEM job: conflicting projected stage identity or source")
	}
	if queuedOK && gotStatus == "queued" && gotCompleted == 0 && uint64(gotSource) == sourceSequence {
		return nil
	}
	if gotStatus == "complete" && gotCompleted == total &&
		((queuedOK && uint64(gotSource) > sourceSequence) || (!queuedOK && uint64(gotSource) == sourceSequence)) {
		return nil
	}
	return errors.New("pcas KEM job: conflicting stage status or first-writer sequence")
}

func checkKEMStageCount(ctx context.Context, tx pgx.Tx, requestID string, want int) error {
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pcas_rewrap_job
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND job_id = $1`, requestID).Scan(&count); err != nil {
		return err
	}
	if count != want {
		return errors.New("pcas KEM job: source stage set differs from projected job")
	}
	return nil
}

// EqualKEMRewrapRequest confirms that a first-writer event belongs to this
// exact immutable outbox request; it is shared by admission and worker replay.
func EqualKEMRewrapRequest(p succession.KEMRewrapRequestedV1, tenantID, identityID,
	requestID string, predecessorEpoch uint64, requestDigest []byte, stages []string) bool {
	if p.TenantID != tenantID || p.IdentityID != identityID || p.RequestID != requestID ||
		p.PredecessorEpoch != predecessorEpoch || !bytes.Equal(p.RequestDigest, requestDigest) ||
		len(p.Stages) != len(stages) {
		return false
	}
	for i := range stages {
		if p.Stages[i] != stages[i] {
			return false
		}
	}
	return true
}
