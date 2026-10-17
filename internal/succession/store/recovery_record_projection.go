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
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/recovery"
	"trstctl.com/trstctl/internal/translog"
)

// RecoveryRecordProjection rebuilds the SQL chain and epoch serving copy from
// immutable, tenant-bound recovery and KEM rewrap events. Historical direct-write records
// have source_sequence=0 and are never silently promoted to source authority.
type RecoveryRecordProjection struct{ store *corestore.Store }

func NewRecoveryRecordProjection(store *corestore.Store) *RecoveryRecordProjection {
	return &RecoveryRecordProjection{store: store}
}

func (*RecoveryRecordProjection) Name() string             { return "pcas.recovery.record" }
func (*RecoveryRecordProjection) ProjectsTenantLifecycle() {}

func (p *RecoveryRecordProjection) withSystemTx(ctx context.Context, apply func(pgx.Tx) error) error {
	if p == nil || p.store == nil {
		return errors.New("pcas recovery record: projection store unavailable")
	}
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := apply(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *RecoveryRecordProjection) Reset(ctx context.Context) error {
	return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ResetTx(ctx, tx) })
}

func (p *RecoveryRecordProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas recovery record: projection store unavailable")
	}
	//trstctl:system-query — cross-tenant full replay removes only event-sourced recovery and KEM rows; legacy and ordinary succession rows remain.
	if _, err := tx.Exec(ctx, `DELETE FROM succession_records WHERE source_sequence > 0`); err != nil {
		return err
	}
	//trstctl:system-query — cross-tenant system replay recomputes only the derived high-water from retained tenant_id-bound chain rows before restoring recovery events.
	if _, err := tx.Exec(ctx, `UPDATE identity_algorithm_epoch AS h SET epoch = r.epoch, updated_at = now()
		FROM (SELECT tenant_id, identity_id, max(epoch) AS epoch FROM succession_records GROUP BY tenant_id, identity_id) AS r
		WHERE h.tenant_id = r.tenant_id AND h.identity_id = r.identity_id`); err != nil {
		return err
	}
	//trstctl:system-query — cross-tenant system replay removes only derived high-water rows without any retained records for the same tenant_id and identity.
	_, err := tx.Exec(ctx, `DELETE FROM identity_algorithm_epoch AS h
		WHERE NOT EXISTS (SELECT 1 FROM succession_records AS r
		                  WHERE r.tenant_id = h.tenant_id AND r.identity_id = h.identity_id)`)
	return err
}

func (p *RecoveryRecordProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if ev.Type != succession.TypeRecoveryRecorded && ev.Type != succession.TypeRecoveryProofIssued &&
		ev.Type != succession.TypeKEMRewrapRecorded &&
		ev.Type != projections.EventTenantOffboarded {
		return nil
	}
	if p == nil || p.store == nil {
		return errors.New("pcas recovery record: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		return p.withSystemTx(ctx, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error { return p.ApplyTx(ctx, tx, ev) })
}

func (p *RecoveryRecordProjection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || tx == nil {
		return errors.New("pcas recovery record: projection store unavailable")
	}
	if ev.Type == projections.EventTenantOffboarded {
		//trstctl:system-query — the system transaction can see cross-tenant rows, but this offboard DELETE is limited to the event's exact tenant_id and projected recovery records.
		_, err := tx.Exec(ctx, `DELETE FROM succession_records WHERE tenant_id = $1 AND source_sequence > 0`, ev.TenantID)
		return err
	}
	if ev.Type != succession.TypeRecoveryRecorded {
		if ev.Type == succession.TypeRecoveryProofIssued {
			return ApplyRecoveryProofEventTx(ctx, tx, ev)
		}
		if ev.Type == succession.TypeKEMRewrapRecorded {
			return ApplyKEMRewrapRecordEventTx(ctx, tx, ev)
		}
		return nil
	}
	return ApplyRecoveryRecordEventTx(ctx, tx, ev)
}

func (p *RecoveryRecordProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}

func (r *Repo) ApplyRecoveryRecordEvent(ctx context.Context, ev eventspec.Event) error {
	return r.core.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return ApplyRecoveryRecordEventTx(ctx, tx, ev)
	})
}

func (r *Repo) ApplyRecoveryProofEvent(ctx context.Context, ev eventspec.Event) error {
	return r.core.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return ApplyRecoveryProofEventTx(ctx, tx, ev)
	})
}

// RecoveryLogLeaves returns only indexed, event-sourced leaf commitments for
// one tenant identity. It never scans the event log or unrelated identities.
func (r *Repo) RecoveryLogLeaves(ctx context.Context, tenantID, identityID string, epoch uint64) ([][]byte, int, error) {
	var leaves [][]byte
	index := -1
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT epoch, recovery_leaf FROM succession_records
			WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1
			  AND source_sequence > 0 ORDER BY epoch`, identityID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rowEpoch uint64
			var leaf []byte
			if err := rows.Scan(&rowEpoch, &leaf); err != nil {
				return err
			}
			if len(leaf) == 0 {
				return errors.New("pcas recovery log: projected leaf is absent")
			}
			if rowEpoch == epoch {
				index = len(leaves)
			}
			leaves = append(leaves, leaf)
		}
		return rows.Err()
	})
	if err == nil && index < 0 {
		err = errors.New("pcas recovery log: target source leaf is absent")
	}
	return leaves, index, err
}

// ApplyRecoveryRecordEventTx validates the signed source and projects it with
// an exact first-writer fence. A duplicate event is a no-op only if the stored
// bytes, request, and source sequence all match; a collision is an error.
func ApplyRecoveryRecordEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeRecoveryRecorded || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas recovery record: invalid source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	p, ok := decoded.(succession.RecoveryRecordedV1)
	if !ok {
		return nil // a newer schema is never interpreted as current authority
	}
	if p.TenantID != ev.TenantID || p.IdentityID == "" || strings.TrimSpace(p.IdentityID) != p.IdentityID ||
		p.Epoch == 0 || p.Epoch > math.MaxInt64 || p.RequestID == "" || len(p.RequestDigest) != 32 ||
		ev.ID != succession.RecoveryRecordEventID(p.TenantID, p.IdentityID, p.Epoch) {
		return errors.New("pcas recovery record: source tenant, identity, epoch or fence mismatch")
	}
	var rec recovery.RecoveryRecord
	if err := json.Unmarshal(p.RecordJSON, &rec); err != nil {
		return fmt.Errorf("pcas recovery record: decode signed record: %w", err)
	}
	if rec.Fields.TenantID != p.TenantID || rec.Fields.IdentityID != p.IdentityID || rec.Fields.Epoch != p.Epoch ||
		rec.Fields.PredecessorEpoch > math.MaxInt64 ||
		rec.Fields.RecordType != succession.RecordType("recovery") || len(rec.InclusionProof) != 0 {
		return errors.New("pcas recovery record: signed tuple differs from source event")
	}
	if err := recovery.VerifyRecord(rec, p.TrustRootDER); err != nil {
		return fmt.Errorf("pcas recovery record: invalid signed record: %w", err)
	}
	leaf, err := succession.Commit(rec.Fields)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO succession_records
		(tenant_id, identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg,
		 successor_pub, record, idempotency_key, source_sequence, recovery_leaf)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT DO NOTHING`, p.IdentityID, int64(p.Epoch), int64(rec.Fields.PredecessorEpoch),
		string(rec.Fields.PredecessorAlg), string(rec.Fields.SuccessorAlg), rec.Fields.SuccessorPub,
		p.RecordJSON, p.RequestID, int64(ev.Sequence), leaf)
	if err != nil {
		return fmt.Errorf("pcas recovery record: project source: %w", err)
	}
	var stored []byte
	var storedRequest string
	var sourceSequence int64
	var storedLeaf []byte
	var proofSequence int64
	err = tx.QueryRow(ctx, `SELECT record, idempotency_key, source_sequence, recovery_leaf, proof_event_sequence FROM succession_records
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1 AND epoch = $2`,
		p.IdentityID, int64(p.Epoch)).Scan(&stored, &storedRequest, &sourceSequence, &storedLeaf, &proofSequence)
	if err != nil || storedRequest != p.RequestID || sourceSequence != int64(ev.Sequence) || !bytes.Equal(storedLeaf, leaf) {
		return errors.New("pcas recovery record: conflicting projected record or request")
	}
	if proofSequence > 0 {
		var withProof recovery.RecoveryRecord
		if err := json.Unmarshal(stored, &withProof); err != nil || len(withProof.InclusionProof) == 0 {
			return errors.New("pcas recovery record: projected proof is malformed")
		}
		withProof.InclusionProof = nil
		stored, err = json.Marshal(withProof)
		if err != nil {
			return err
		}
	}
	if !bytes.Equal(stored, p.RecordJSON) {
		return errors.New("pcas recovery record: source bytes differ from existing row")
	}
	_, err = tx.Exec(ctx, `INSERT INTO identity_algorithm_epoch (tenant_id, identity_id, epoch)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2)
		ON CONFLICT (tenant_id, identity_id) DO UPDATE SET epoch = EXCLUDED.epoch, updated_at = now()
		WHERE identity_algorithm_epoch.epoch < EXCLUDED.epoch`, p.IdentityID, int64(p.Epoch))
	return err
}

// ApplyRecoveryProofEventTx attaches the first durable proof to its exact
// source record. The signed head must verify under the tenant's already pinned
// genesis root; a second proof cannot replace the first one.
func ApplyRecoveryProofEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeRecoveryProofIssued || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas recovery proof: invalid source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	p, ok := decoded.(succession.RecoveryProofIssuedV1)
	if !ok {
		return nil
	}
	if p.TenantID != ev.TenantID || p.IdentityID == "" || p.Epoch == 0 || p.Epoch > math.MaxInt64 ||
		p.RequestID == "" || p.RecordEventID != succession.RecoveryRecordEventID(p.TenantID, p.IdentityID, p.Epoch) ||
		ev.ID != succession.RecoveryProofEventID(p.TenantID, p.IdentityID, p.Epoch) {
		return errors.New("pcas recovery proof: source binding mismatch")
	}
	var rootDER []byte
	if err := tx.QueryRow(ctx, `SELECT trust_root_public_der FROM pcas_genesis
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1`,
		p.IdentityID).Scan(&rootDER); err != nil || !bytes.Equal(rootDER, p.LogPublicKeyDER) {
		return errors.New("pcas recovery proof: log signer differs from tenant genesis")
	}
	var raw []byte
	var requestID string
	var sourceSequence, proofSequence int64
	var leaf []byte
	if err := tx.QueryRow(ctx, `SELECT record, idempotency_key, source_sequence, proof_event_sequence, recovery_leaf
		FROM succession_records WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
		AND identity_id = $1 AND epoch = $2 FOR UPDATE`, p.IdentityID, int64(p.Epoch)).
		Scan(&raw, &requestID, &sourceSequence, &proofSequence, &leaf); err != nil {
		return fmt.Errorf("pcas recovery proof: source record unavailable: %w", err)
	}
	if sourceSequence == 0 || requestID != p.RequestID || len(leaf) == 0 {
		return errors.New("pcas recovery proof: record source differs from proof")
	}
	if err := translog.VerifyEncodedInclusion(leaf, p.ProofBytes, rootDER); err != nil {
		return fmt.Errorf("pcas recovery proof: invalid signed inclusion: %w", err)
	}
	proof, err := translog.DecodeProof(p.ProofBytes)
	if err != nil {
		return err
	}
	// The signed head must commit to EVERY earlier event-sourced recovery leaf
	// for this identity, in epoch order. A valid signature over a one-leaf tree
	// is not enough if older recoveries exist.
	rows, err := tx.Query(ctx, `SELECT epoch, recovery_leaf FROM succession_records
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1
		AND source_sequence > 0 AND source_sequence < $2 ORDER BY epoch`,
		p.IdentityID, int64(ev.Sequence))
	if err != nil {
		return err
	}
	tree := translog.New(nil)
	targetIndex := -1
	for rows.Next() {
		var rowEpoch uint64
		var rowLeaf []byte
		if err := rows.Scan(&rowEpoch, &rowLeaf); err != nil {
			rows.Close()
			return err
		}
		if len(rowLeaf) == 0 {
			rows.Close()
			return errors.New("pcas recovery proof: prior projected leaf is absent")
		}
		index, _, err := tree.Append(rowLeaf)
		if err != nil {
			rows.Close()
			return err
		}
		if rowEpoch == p.Epoch {
			targetIndex = index
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	head, err := tree.Head()
	if err != nil {
		return err
	}
	if targetIndex != proof.Index || head.TreeSize != proof.STH.TreeSize ||
		!bytes.Equal(head.RootHash, proof.STH.RootHash) {
		return errors.New("pcas recovery proof: signed head omits or reorders a prior recovery")
	}
	var rec recovery.RecoveryRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	if proofSequence != 0 {
		if proofSequence != int64(ev.Sequence) || !bytes.Equal(rec.InclusionProof, p.ProofBytes) {
			return errors.New("pcas recovery proof: conflicting first-writer proof")
		}
		return nil
	}
	if len(rec.InclusionProof) != 0 {
		return errors.New("pcas recovery proof: unsigned serving proof already exists")
	}
	rec.InclusionProof = p.ProofBytes
	updated, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE succession_records SET record = $3, proof_event_sequence = $4
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1 AND epoch = $2`,
		p.IdentityID, int64(p.Epoch), updated, int64(ev.Sequence))
	return err
}
