// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

// CertificateMetadataEventAppliedTx checks exact execution, not a maximum
// sequence. Callers hold the metadata fence when making a write decision.
// The digest binds the entire immutable envelope, including schema and actor.
func (s *Store) CertificateMetadataEventAppliedTx(ctx context.Context, tx pgx.Tx, e eventspec.Event) (bool, error) {
	if e.Sequence == 0 {
		return false, nil
	}
	if e.Sequence > math.MaxInt64 || e.ID == "" {
		return false, errors.New("store: invalid certificate metadata event identity")
	}
	digest, err := certificateMetadataEventDigest(e)
	if err != nil {
		return false, err
	}
	rows, err := tx.Query(ctx, `SELECT event_id,event_digest FROM certificate_metadata_receipts
		WHERE tenant_id=$1 AND (event_sequence=$2 OR event_id=$3)`, e.TenantID, int64(e.Sequence), e.ID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	done := false
	for rows.Next() {
		var id, retainedDigest string
		if err := rows.Scan(&id, &retainedDigest); err != nil {
			return false, err
		}
		if id != e.ID || retainedDigest != digest {
			return false, fmt.Errorf("%w: certificate metadata event differs from its completed envelope", ErrIdempotencyConflict)
		}
		done = true
	}
	return done, rows.Err()
}

// CertificateMetadataReceiptBatchLimit bounds a recovery receipt read. The
// caller still verifies every envelope; neither a high watermark nor a current
// certificate row can stand in for an exact completion receipt.
const CertificateMetadataReceiptBatchLimit = 128

// CertificateMetadataEventsAppliedTx checks a bounded page in one SQL read.
// Callers hold the tenant metadata and privacy fences for the entire recovery.
// Results preserve input order, including duplicate immutable events retained
// at later physical sequences after the log's finite deduplication window.
func (s *Store) CertificateMetadataEventsAppliedTx(ctx context.Context, tx pgx.Tx, tenantID string, page []eventspec.Event) ([]bool, error) {
	if len(page) > CertificateMetadataReceiptBatchLimit {
		return nil, errors.New("store: certificate metadata receipt batch exceeds limit")
	}
	done := make([]bool, len(page))
	if len(page) == 0 {
		return done, nil
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, err
	}
	sequences := make([]int64, 0, len(page))
	ids := make([]string, 0, len(page))
	digests := make([]string, len(page))
	digester := newCertificateMetadataDigester()
	for i, e := range page {
		eventTenant, err := uuid.Parse(e.TenantID)
		if err != nil || eventTenant != tenant {
			return nil, errors.New("store: certificate metadata receipt batch contains another tenant")
		}
		if e.Sequence == 0 {
			continue
		}
		if e.Sequence > math.MaxInt64 || e.ID == "" {
			return nil, errors.New("store: invalid certificate metadata event identity")
		}
		digests[i], err = digester.digest(e)
		if err != nil {
			return nil, err
		}
		sequences = append(sequences, int64(e.Sequence))
		ids = append(ids, e.ID)
	}
	if len(sequences) == 0 {
		return done, nil
	}
	rows, err := tx.Query(ctx, `SELECT event_sequence,event_id,event_digest FROM certificate_metadata_receipts
		WHERE tenant_id=$1 AND (event_sequence=ANY($2::bigint[]) OR event_id=ANY($3::text[]))`, tenantID, sequences, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type receipt struct{ id, digest string }
	bySequence := make(map[uint64]receipt, len(page))
	byID := make(map[string]receipt, len(page))
	for rows.Next() {
		var sequence int64
		var r receipt
		if err := rows.Scan(&sequence, &r.id, &r.digest); err != nil {
			return nil, err
		}
		if sequence <= 0 {
			return nil, errors.New("store: invalid certificate metadata receipt sequence")
		}
		bySequence[uint64(sequence)] = r
		byID[r.id] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, e := range page {
		if e.Sequence == 0 {
			continue
		}
		sequenceReceipt, hasSequence := bySequence[e.Sequence]
		idReceipt, hasID := byID[e.ID]
		if (hasSequence && (sequenceReceipt.id != e.ID || sequenceReceipt.digest != digests[i])) ||
			(hasID && idReceipt.digest != digests[i]) {
			return nil, fmt.Errorf("%w: certificate metadata event differs from its completed envelope", ErrIdempotencyConflict)
		}
		done[i] = hasSequence || hasID
	}
	return done, nil
}

func certificateMetadataEventDigest(e eventspec.Event) (string, error) {
	e, err := canonicalCertificateMetadataEvent(e)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
}

// Recovery verifies many existing receipts in one bounded page. Reuse the
// encoded-envelope buffer instead of allocating a full second payload for
// every historical event. The bytes hashed are still exactly json.Marshal's
// existing receipt format; Encoder adds one final newline, which is excluded.
type certificateMetadataDigester struct {
	buffer  bytes.Buffer
	encoder *json.Encoder
}

func newCertificateMetadataDigester() *certificateMetadataDigester {
	d := &certificateMetadataDigester{}
	d.encoder = json.NewEncoder(&d.buffer)
	return d
}

func (d *certificateMetadataDigester) digest(e eventspec.Event) (string, error) {
	e, err := canonicalCertificateMetadataEvent(e)
	if err != nil {
		return "", err
	}
	d.buffer.Reset()
	if err := d.encoder.Encode(e); err != nil {
		return "", err
	}
	raw := d.buffer.Bytes()
	return crypto.SHA256Hex(raw[:len(raw)-1]), nil
}

func canonicalCertificateMetadataEvent(e eventspec.Event) (eventspec.Event, error) {
	tenant, err := uuid.Parse(e.TenantID)
	if err != nil {
		return eventspec.Event{}, err
	}
	e.TenantID = tenant.String()
	e.Time = e.Time.UTC()
	// JetStream's finite dedupe window permits the same immutable envelope at
	// another physical sequence. EventByID defines that as the same command.
	// The receipt keeps the first completed sequence, not a second execution.
	e.Sequence = 0
	if e.SchemaVersion == 0 {
		e.SchemaVersion = eventspec.DefaultSchemaVersion
	}
	return e, nil
}

// WithCertificateMetadataEventTx covers the whole dependent event, including
// decision reads and zero-row branches. A receipt commits atomically with every
// effect; a rolled-back event leaves no receipt. An unknown older event must
// rebuild in source order, never be reinterpreted against newer SQL state.
func (s *Store) WithCertificateMetadataEventTx(ctx context.Context, tx pgx.Tx, e eventspec.Event, apply func() error) error {
	if e.Sequence > math.MaxInt64 {
		return errors.New("store: certificate metadata sequence exceeds PostgreSQL bigint")
	}
	if err := s.LockCertificateMetadataOrderTx(ctx, tx, e.TenantID); err != nil {
		return err
	}
	if e.Sequence == 0 {
		return apply()
	}
	done, err := s.CertificateMetadataEventAppliedTx(ctx, tx, e)
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	var latest int64
	var unknown bool
	err = tx.QueryRow(ctx, `SELECT latest_sequence,unknown_write FROM certificate_metadata_watermarks WHERE tenant_id=$1`, e.TenantID).Scan(&latest, &unknown)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && (unknown || latest < 0 || uint64(latest) > e.Sequence) {
		return fmt.Errorf("%w: missing certificate metadata event %d follows statement %d (unknown=%t)", ErrCertificateRecordingRebuildRequired, e.Sequence, latest, unknown)
	}
	if err := apply(); err != nil {
		return err
	}
	digest, err := certificateMetadataEventDigest(e)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO certificate_metadata_receipts(tenant_id,event_sequence,event_id,event_digest) VALUES($1,$2,$3,$4)`, e.TenantID, int64(e.Sequence), e.ID, digest); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO certificate_metadata_watermarks(tenant_id,latest_sequence,unknown_write) VALUES($1,$2,false)
		ON CONFLICT(tenant_id) DO UPDATE SET latest_sequence=greatest(certificate_metadata_watermarks.latest_sequence,excluded.latest_sequence)`, e.TenantID, int64(e.Sequence))
	return err
}
