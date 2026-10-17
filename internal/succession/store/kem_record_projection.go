// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/succession"
	pcaskem "trstctl.com/trstctl/internal/succession/kem"
)

func (r *Repo) ApplyKEMRewrapRecordEvent(ctx context.Context, ev eventspec.Event) error {
	return r.core.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		if err := ApplyKEMRewrapRecordEventTx(ctx, tx, ev); err != nil {
			return err
		}
		return ApplyKEMRewrapCompletedStagesTx(ctx, tx, ev)
	})
}

// ApplyKEMRewrapRecordEventTx projects only an immutable, independently
// verified paired record. Identical replay is harmless; an occupied epoch with
// different bytes, request or source event is a conflict, never a silent no-op.
func ApplyKEMRewrapRecordEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeKEMRewrapRecorded || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas KEM record: invalid source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	p, ok := decoded.(succession.KEMRewrapRecordedV1)
	if !ok {
		return nil // an unknown future schema never authorizes a current row
	}
	if p.TenantID != ev.TenantID || p.IdentityID == "" || strings.TrimSpace(p.IdentityID) != p.IdentityID ||
		p.Epoch == 0 || p.Epoch > math.MaxInt64 || p.RequestID == "" || len(p.RequestDigest) != 32 ||
		ev.ID != succession.KEMRewrapRecordEventID(p.TenantID, p.IdentityID, p.Epoch) {
		return errors.New("pcas KEM record: source tenant, identity, epoch or event fence mismatch")
	}
	var rec pcaskem.PairedRecord
	if err := json.Unmarshal(p.RecordJSON, &rec); err != nil {
		return fmt.Errorf("pcas KEM record: decode paired record: %w", err)
	}
	f := rec.Base.Fields
	if f.TenantID != p.TenantID || f.IdentityID != p.IdentityID || f.Epoch != p.Epoch ||
		f.PredecessorEpoch > math.MaxInt64 || f.PredecessorEpoch+1 != f.Epoch {
		return errors.New("pcas KEM record: signed tuple differs from source event")
	}
	if err := pcaskem.VerifyPaired(rec); err != nil {
		return fmt.Errorf("pcas KEM record: invalid paired proof: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO succession_records
		(tenant_id, identity_id, epoch, predecessor_epoch, predecessor_alg,
		 successor_alg, successor_pub, record, idempotency_key, source_sequence)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT DO NOTHING`, p.IdentityID, int64(p.Epoch), int64(f.PredecessorEpoch),
		string(f.PredecessorAlg), string(f.SuccessorAlg), f.SuccessorPub,
		p.RecordJSON, p.RequestID, int64(ev.Sequence))
	if err != nil {
		return fmt.Errorf("pcas KEM record: project source: %w", err)
	}
	var stored []byte
	var storedRequest, predecessorAlg, successorAlg string
	var sourceSequence int64
	var successorPub []byte
	err = tx.QueryRow(ctx, `SELECT record, idempotency_key, source_sequence,
		predecessor_alg, successor_alg, successor_pub FROM succession_records
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1 AND epoch = $2`,
		p.IdentityID, int64(p.Epoch)).Scan(&stored, &storedRequest, &sourceSequence,
		&predecessorAlg, &successorAlg, &successorPub)
	if err != nil || storedRequest != p.RequestID || sourceSequence != int64(ev.Sequence) ||
		predecessorAlg != string(f.PredecessorAlg) || successorAlg != string(f.SuccessorAlg) ||
		!bytes.Equal(successorPub, f.SuccessorPub) || !bytes.Equal(stored, p.RecordJSON) {
		return errors.New("pcas KEM record: conflicting projected record, source or request")
	}
	_, err = tx.Exec(ctx, `INSERT INTO identity_algorithm_epoch (tenant_id, identity_id, epoch)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2)
		ON CONFLICT (tenant_id, identity_id) DO UPDATE SET epoch = EXCLUDED.epoch, updated_at = now()
		WHERE identity_algorithm_epoch.epoch < EXCLUDED.epoch`, p.IdentityID, int64(p.Epoch))
	return err
}
