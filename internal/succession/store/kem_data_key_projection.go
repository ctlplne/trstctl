// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/succession"
)

// KEMDataKey is one projected data-key envelope (A16).
type KEMDataKey struct {
	IdentityID         string
	Epoch              uint64
	TargetRef          string
	Stage              string
	KEMCiphertext      []byte
	WrappedDEK         []byte
	DEKSHA256          []byte
	CiphertextSHA256   []byte
	RewrappedFromEpoch uint64
	RewrapRequestID    string
	ReadbackVerified   bool
	SourceSequence     uint64
	CreatedAt          time.Time
}

// MaxKEMDataKeyTargetRef bounds an operator's target reference.
const MaxKEMDataKeyTargetRef = 256

// ValidateKEMDataKeyEnvelope checks the shape of a registered or re-wrapped
// envelope: bounded ciphertext, a sealed data key and a 32-byte digest.
func ValidateKEMDataKeyEnvelope(targetRef, stage string, kemCiphertext, wrappedDEK, dekSHA256 []byte) error {
	if targetRef == "" || len(targetRef) > MaxKEMDataKeyTargetRef || strings.TrimSpace(targetRef) != targetRef {
		return errors.New("pcas KEM data key: target_ref must be 1 to 256 trimmed bytes")
	}
	if err := succession.ValidateKEMRewrapStages([]string{stage}); err != nil {
		return err
	}
	if len(kemCiphertext) == 0 || len(kemCiphertext) > 4096 {
		return errors.New("pcas KEM data key: kem_ciphertext must be 1 to 4096 bytes")
	}
	if len(wrappedDEK) == 0 || len(wrappedDEK) > 1024 {
		return errors.New("pcas KEM data key: wrapped_dek must be 1 to 1024 bytes")
	}
	if len(dekSHA256) != 32 {
		return errors.New("pcas KEM data key: dek_sha256 must be 32 bytes")
	}
	return nil
}

func (r *Repo) ApplyKEMDataKeyEvent(ctx context.Context, ev eventspec.Event) error {
	return r.core.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return ApplyKEMDataKeyEventTx(ctx, tx, ev)
	})
}

// ApplyKEMDataKeyEventTx projects a registered or re-wrapped envelope. The
// (identity, epoch, target_ref) tuple is first-writer fenced by the event id:
// identical replay is harmless, different bytes at an occupied tuple conflict.
func ApplyKEMDataKeyEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas KEM data key: invalid source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	row := KEMDataKey{SourceSequence: ev.Sequence}
	switch p := decoded.(type) {
	case succession.KEMDataKeyRegisteredV1:
		if p.TenantID != ev.TenantID || p.Epoch == 0 || p.Epoch > math.MaxInt64 ||
			ev.ID != succession.KEMDataKeyEventID(p.TenantID, p.IdentityID, p.Epoch, p.TargetRef, false) {
			return errors.New("pcas KEM data key: registration source binding mismatch")
		}
		row.IdentityID, row.Epoch, row.TargetRef, row.Stage = p.IdentityID, p.Epoch, p.TargetRef, p.Stage
		row.KEMCiphertext, row.WrappedDEK, row.DEKSHA256 = p.KEMCiphertext, p.WrappedDEK, p.DEKSHA256
	case succession.KEMDataKeyRewrappedV1:
		if p.TenantID != ev.TenantID || p.Epoch == 0 || p.Epoch > math.MaxInt64 || p.PredecessorEpoch+1 != p.Epoch ||
			p.RequestID == "" || len(p.RequestDigest) != 32 || len(p.PredecessorCiphertextSHA256) != 32 ||
			!bytes.Equal(p.DEKSHA256, p.ReadbackDEKSHA256) ||
			ev.ID != succession.KEMDataKeyEventID(p.TenantID, p.IdentityID, p.Epoch, p.TargetRef, true) {
			return errors.New("pcas KEM data key: re-wrap receipt binding mismatch")
		}
		row.IdentityID, row.Epoch, row.TargetRef, row.Stage = p.IdentityID, p.Epoch, p.TargetRef, p.Stage
		row.KEMCiphertext, row.WrappedDEK, row.DEKSHA256 = p.KEMCiphertext, p.WrappedDEK, p.DEKSHA256
		row.RewrappedFromEpoch, row.RewrapRequestID, row.ReadbackVerified = p.PredecessorEpoch, p.RequestID, true
	default:
		return nil // unknown future schema never authorizes a current row
	}
	if p, ok := decoded.(succession.KEMDataKeyRewrappedV1); ok {
		// The receipt names the predecessor envelope it replaced; that row must
		// exist with the same data key digest, else the receipt is not ours.
		var predDigest, predCiphertext []byte
		if err := tx.QueryRow(ctx, `SELECT dek_sha256, ciphertext_sha256 FROM pcas_kem_data_key
			WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1 AND epoch = $2 AND target_ref = $3`,
			p.IdentityID, pgInt64(p.PredecessorEpoch), p.TargetRef).Scan(&predDigest, &predCiphertext); err != nil {
			return fmt.Errorf("pcas KEM data key: predecessor envelope for receipt: %w", err)
		}
		if !bytes.Equal(predDigest, p.DEKSHA256) || !bytes.Equal(predCiphertext, p.PredecessorCiphertextSHA256) {
			return errors.New("pcas KEM data key: receipt does not match the predecessor envelope")
		}
	}
	if err := ValidateKEMDataKeyEnvelope(row.TargetRef, row.Stage, row.KEMCiphertext, row.WrappedDEK, row.DEKSHA256); err != nil {
		return err
	}
	row.CiphertextSHA256 = crypto.SHA256Sum(row.KEMCiphertext)
	if _, err := tx.Exec(ctx, `INSERT INTO pcas_kem_data_key
		(tenant_id, identity_id, epoch, target_ref, stage, kem_ciphertext, wrapped_dek, dek_sha256, ciphertext_sha256,
		 rewrapped_from_epoch, rewrap_request_id, readback_verified, source_sequence)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT DO NOTHING`,
		row.IdentityID, pgInt64(row.Epoch), row.TargetRef, row.Stage, row.KEMCiphertext, row.WrappedDEK, row.DEKSHA256,
		row.CiphertextSHA256, pgInt64(row.RewrappedFromEpoch), row.RewrapRequestID, row.ReadbackVerified, pgInt64(ev.Sequence)); err != nil {
		return fmt.Errorf("pcas KEM data key: project envelope: %w", err)
	}
	var gotCiphertext, gotDigest []byte
	var gotStage, gotRequest string
	if err := tx.QueryRow(ctx, `SELECT stage, ciphertext_sha256, dek_sha256, rewrap_request_id FROM pcas_kem_data_key
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1 AND epoch = $2 AND target_ref = $3`,
		row.IdentityID, pgInt64(row.Epoch), row.TargetRef).Scan(&gotStage, &gotCiphertext, &gotDigest, &gotRequest); err != nil {
		return err
	}
	if gotStage != row.Stage || !bytes.Equal(gotCiphertext, row.CiphertextSHA256) || !bytes.Equal(gotDigest, row.DEKSHA256) || gotRequest != row.RewrapRequestID {
		return errors.New("pcas KEM data key: envelope tuple is occupied by a different envelope")
	}
	return nil
}

func (r *Repo) ApplyKEMRewrapStageCompletedEvent(ctx context.Context, ev eventspec.Event) error {
	return r.core.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return ApplyKEMRewrapStageCompletedEventTx(ctx, tx, ev)
	})
}

// ApplyKEMRewrapStageCompletedEventTx records a stage's data receipt on its job
// row: the retirement gate's RewrapComplete reads exactly this.
func ApplyKEMRewrapStageCompletedEventTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if ev.Type != succession.TypeKEMRewrapStageCompleted || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return errors.New("pcas KEM job: invalid stage completion source event")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	p, ok := decoded.(succession.KEMRewrapStageCompletedV1)
	if !ok {
		return nil
	}
	if p.TenantID != ev.TenantID || p.IdentityID == "" || p.RequestID == "" || len(p.RequestDigest) != 32 ||
		p.PredecessorEpoch+1 != p.Epoch || p.TargetCount < 0 || len(p.ReceiptsSHA256) != 32 ||
		succession.ValidateKEMRewrapStages([]string{p.Stage}) != nil ||
		ev.ID != succession.KEMRewrapStageCompletedEventID(p.TenantID, p.RequestID, p.Stage) {
		return errors.New("pcas KEM job: stage completion binding mismatch")
	}
	var inventory int64
	var attested bool
	if err := tx.QueryRow(ctx, `SELECT inventory_sequence, empty_inventory_attested FROM pcas_rewrap_job
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND job_id = $1 AND stage = $2`,
		p.RequestID, p.Stage).Scan(&inventory, &attested); err != nil {
		return fmt.Errorf("pcas KEM job: stage completion has no accepted stage: %w", err)
	}
	var registered, rewrapped int
	if err := tx.QueryRow(ctx, `SELECT
		  (SELECT count(*) FROM pcas_kem_data_key WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
		     AND identity_id = $1 AND epoch = $2 AND stage = $3 AND source_sequence <= $5),
		  (SELECT count(*) FROM pcas_kem_data_key WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
		     AND identity_id = $1 AND epoch = $2 + 1 AND stage = $3 AND rewrap_request_id = $4 AND readback_verified)`,
		p.IdentityID, pgInt64(p.PredecessorEpoch), p.Stage, p.RequestID, inventory).Scan(&registered, &rewrapped); err != nil {
		return err
	}
	if registered != p.TargetCount || rewrapped != p.TargetCount {
		return fmt.Errorf("pcas KEM job: stage %q claims %d targets, %d registered in the snapshot and %d read back", p.Stage, p.TargetCount, registered, rewrapped)
	}
	if p.TargetCount == 0 && !attested {
		return errors.New("pcas KEM job: a stage with no envelopes completes only with empty_inventory_attested")
	}
	tag, err := tx.Exec(ctx, `UPDATE pcas_rewrap_job
		SET status = 'complete', data_receipt_sequence = $5, data_keys = $6, data_keys_rewrapped = $6, updated_at = now()
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND job_id = $1 AND identity_id = $2
		  AND predecessor_epoch = $3 AND stage = $4 AND request_digest = $7 AND source_sequence > 0
		  AND (status = 'key_ready' OR (status = 'complete' AND data_receipt_sequence = $5))`,
		p.RequestID, p.IdentityID, pgInt64(p.PredecessorEpoch), p.Stage, pgInt64(ev.Sequence), p.TargetCount, p.RequestDigest)
	if err != nil {
		return fmt.Errorf("pcas KEM job: project stage data receipt: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("pcas KEM job: stage completion found no key-ready stage for this request")
	}
	_, err = tx.Exec(ctx, `UPDATE pcas_rewrap_job SET completed_stages = (
			SELECT count(*) FROM pcas_rewrap_job c
			 WHERE c.tenant_id = current_setting('trstctl.tenant_id')::uuid AND c.job_id = $1 AND c.status = 'complete')
		WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND job_id = $1`, p.RequestID)
	return err
}

const kemDataKeyColumns = `identity_id, epoch, target_ref, stage, kem_ciphertext, wrapped_dek, dek_sha256, ciphertext_sha256,
       rewrapped_from_epoch, rewrap_request_id, readback_verified, source_sequence, created_at`

func scanKEMDataKey(row pgx.Row) (KEMDataKey, error) {
	var k KEMDataKey
	var epoch, from, seq int64
	err := row.Scan(&k.IdentityID, &epoch, &k.TargetRef, &k.Stage, &k.KEMCiphertext, &k.WrappedDEK, &k.DEKSHA256, &k.CiphertextSHA256,
		&from, &k.RewrapRequestID, &k.ReadbackVerified, &seq, &k.CreatedAt)
	if err != nil {
		return KEMDataKey{}, err
	}
	k.Epoch, k.RewrappedFromEpoch, k.SourceSequence = pgUint64(epoch), pgUint64(from), pgUint64(seq)
	return k, nil
}

// ListKEMDataKeys returns an identity epoch's envelopes, optionally one stage,
// ordered by target reference.
func (r *Repo) ListKEMDataKeys(ctx context.Context, tenantID, identityID string, epoch uint64, stage string) ([]KEMDataKey, error) {
	var out []KEMDataKey
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+kemDataKeyColumns+` FROM pcas_kem_data_key
			WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1 AND epoch = $2
			  AND ($3 = '' OR stage = $3)
			ORDER BY target_ref`, identityID, pgInt64(epoch), stage)
		if err != nil {
			return fmt.Errorf("succession store: list KEM data keys: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			k, err := scanKEMDataKey(rows)
			if err != nil {
				return fmt.Errorf("succession store: scan KEM data key: %w", err)
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

// KEMDataKeyInventorySequence is the predecessor epoch's inventory snapshot: the
// highest registration source sequence at this moment. A re-wrap request moves
// exactly the envelopes registered up to it; later registrations wait for the
// next request and keep the retirement gate closed meanwhile.
func (r *Repo) KEMDataKeyInventorySequence(ctx context.Context, tenantID, identityID string, epoch uint64) (uint64, error) {
	var seq int64
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(max(source_sequence), 0) FROM pcas_kem_data_key
			WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1 AND epoch = $2`,
			identityID, pgInt64(epoch)).Scan(&seq)
	})
	if err != nil {
		return 0, err
	}
	return pgUint64(seq), nil
}

// ListKEMDataKeysUpTo lists the envelopes a request's inventory snapshot covers.
func (r *Repo) ListKEMDataKeysUpTo(ctx context.Context, tenantID, identityID string, epoch uint64, stage string, inventorySequence uint64) ([]KEMDataKey, error) {
	all, err := r.ListKEMDataKeys(ctx, tenantID, identityID, epoch, stage)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, k := range all {
		if k.SourceSequence <= inventorySequence {
			out = append(out, k)
		}
	}
	return out, nil
}

// KEMPublicKey returns the KEM algorithm and public encapsulation key the
// paired record established for an identity epoch.
func (r *Repo) KEMPublicKey(ctx context.Context, tenantID, identityID string, epoch uint64) (string, []byte, bool, error) {
	var recordJSON []byte
	found := false
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT record FROM succession_records
			WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1 AND epoch = $2`,
			identityID, pgInt64(epoch)).Scan(&recordJSON)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil || !found {
		return "", nil, false, err
	}
	alg, pub, ok := kemPublicFromRecord(recordJSON)
	return alg, pub, ok, nil
}

// pgInt64 and pgUint64 make bigint conversions total. Callers bound epochs and
// sequences to the PostgreSQL range before projecting; the clamps only keep a
// value that slipped past that check from wrapping.
func pgInt64(u uint64) int64 {
	if u > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(u)
}

func pgUint64(i int64) uint64 {
	if i < 0 {
		return 0
	}
	return uint64(i)
}
